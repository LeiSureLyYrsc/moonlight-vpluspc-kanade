#pragma once

#ifndef KANADEAPI_H
#define KANADEAPI_H

#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QSet>
#include <QSslConfiguration>
#include <QString>
#include <QUrl>

#include <functional>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

// Low-level JSON client for the Kanade control plane (P1 client lane).
//
// Transport hardening (plan section 3.4 -- never weakened here):
//   * Strict HTTPS only. normalizeOrigin() is the single funnel that turns a
//     user-supplied service URL into a canonical origin (scheme "https",
//     lowercase host, no credentials, no path/query/fragment); anything else
//     is rejected before any network activity. Non-https schemes are never
//     "upgraded" implicitly.
//   * Redirects are never followed (manual redirect policy); a 3xx surfaces
//     as ErrorKind::Redirect.
//   * No cookies: the QNetworkAccessManager has no cookie jar and every
//     request pins both cookie attributes to Manual, so nothing is sent,
//     stored or echoed back.
//   * TLS is verified against the active QSslConfiguration (system trust by
//     default). sslErrors always fails closed: the connection is aborted and
//     the result is ErrorKind::Tls. ignoreSslErrors() is never called, and
//     there is no code path that trusts on first use or pins a leaf.
//   * Response bodies are bounded (kDefaultMaxBodyBytes); oversized replies
//     are aborted with ErrorKind::BodyTooLarge.
//   * Every request has a total deadline (kDefaultTimeoutMs) and is aborted
//     on expiry with ErrorKind::Timeout.
//   * All objects live on the thread that created this instance; replies are
//     cancelled and released by their owning thread only (abortAll()).
//   * abortAll() is safe from inside a completion: each context is detached
//     from its reply BEFORE its completion runs, so a completion that
//     re-enters the client (new request, new abortAll) never sees a
//     half-finished context and an old origin's reply is never delivered late.
//
// Token handling:
//   * Tokens are memory-only and live exclusively in this class
//     (adoptTokenPair()). The controller never copies token strings.
//   * Authenticated calls that answer 401 token_expired/token_invalid are
//     retried exactly once, but only after a *successful* refresh. Refresh is
//     single-flight: concurrent 401s queue on one in-flight rotation. If the
//     rotation result is ambiguous (timeout/network/HTTP error) the old
//     refresh token is never re-sent -- tokens are cleared and
//     authenticationLost() is emitted (fail closed, plan section 2).
//
// This class only speaks the safe REST surface from the P1 contract:
// /auth/*, /installations/*, /devices, /pair-requests/*, /grants/*. It does
// not do session/ICE/event traffic and does not attempt transport
// reachability probes.
class KanadeApi : public QObject
{
    Q_OBJECT

public:
    enum class ErrorKind {
        None,          // 2xx; body parsed into Result::body (may be empty)
        InvalidOrigin, // request issued before a valid origin was set
        Network,       // transport failure (DNS refused, connection reset, ...)
        Timeout,       // total deadline exceeded
        Tls,           // certificate or handshake verification failure
        Redirect,      // server answered 3xx (never followed)
        BodyTooLarge,  // response exceeded the configured body bound
        HttpError,     // non-2xx; Result::httpStatus and Result::serverCode set
        ParseError,    // response body was not a JSON object
        Cancelled,     // aborted locally (abortAll)
    };

    struct Result {
        ErrorKind kind = ErrorKind::None;
        int httpStatus = 0;
        // Raw detail.code from {"detail": {"code": ...}} (empty when absent).
        // Never surfaced to the UI verbatim; the controller maps it through
        // its fixed allowlist. Contains no credentials or response bodies.
        QString serverCode;
        QJsonObject body;
    };

    using Completion = std::function<void(const Result&)>;

    static constexpr int kDefaultTimeoutMs = 20000;
    static constexpr qint64 kDefaultMaxBodyBytes = 2 * 1024 * 1024;

    explicit KanadeApi(QObject* parent = nullptr);
    ~KanadeApi() override;

    // Strict HTTPS origin validation. Accepts only an explicit https:// URL
    // with a host, no credentials, no path beyond "/", and no query/fragment.
    // On success originOut is the canonical origin used for all requests
    // (default port stripped, host lowercased). Returns false for everything
    // else; on false no network object is touched.
    static bool normalizeOrigin(const QString& serviceUrl, QUrl& originOut);

    // Changing the origin is refused while usable credentials are held: a
    // cross-origin swap with live tokens is always a bug in the caller, and
    // silently re-pointing old credentials at a new host is exactly what the
    // plan forbids.  Callers must logout()/abortAll() + clearTokens() first.
    // Returns false (and leaves the origin unchanged) when refused.
    // Does not perform generation bookkeeping: the caller owns that.
    bool setOrigin(const QUrl& origin);
    QUrl origin() const;

    // Defaults to QSslConfiguration::defaultConfiguration() (system trust).
    // Tests and controlled deployments may install a configuration that adds
    // a test CA; verification itself is never disabled.
    void setSslConfiguration(const QSslConfiguration& configuration);

    void setTimeouts(int totalTimeoutMs, qint64 maxBodyBytes);

    // Memory-only token state. adoptTokenPair() parses the TokenPair schema
    // ({access_token, access_expires_at, refresh_token, ...}); malformed
    // payloads are ignored (and, if tokens existed, treated as auth loss).
    void adoptTokenPair(const QJsonObject& tokenPair);
    void clearTokens();
    bool hasTokens() const;

    // True when payload carries both a non-empty access and refresh token, i.e.
    // adoptTokenPair() would not fail closed.  Lets callers validate a reply
    // BEFORE adopting it.
    static bool tokenPairIsUsable(const QJsonObject& tokenPair);

    // Authenticated request with automatic single-flight refresh on 401
    // token_expired/token_invalid. A request is retried at most once and only
    // with a freshly rotated access token. logoutBestEffort() must not be
    // passed through these helpers (it owns its tokens and timing).
    void get(const QString& path, Completion completion);
    void post(const QString& path, const QJsonObject& body, bool authenticated, Completion completion);
    void del(const QString& path, Completion completion);

    // Idempotent best-effort logout of the current family.  The credentials
    // are captured and CLEARED SYNCHRONOUSLY before any network activity, so
    // local sign-out never depends on the network and a late reply cannot
    // touch newer state.  The request carries the captured bearer in the
    // header and the refresh token (and the access token as a fallback) in the
    // body, exactly as POST /v1/auth/logout accepts.  The completion (if any)
    // receives the raw result and must not change user-visible state.
    // Safe to call with no tokens (no-op).  Never follows redirects.
    void logoutBestEffort(Completion completion = Completion());

    // Aborts every outstanding reply and in-flight refresh, delivering
    // ErrorKind::Cancelled to their completions.  Every context is removed
    // from the set and detached from its reply BEFORE any completion runs, so
    // a completion may recursively complete or abort other contexts without
    // touching freed state, and a stale origin's reply is never delivered
    // late. Requests started inside an aborted completion are rejected; a
    // caller can start fresh work once abortAll() returns. After it returns,
    // no pre-existing completion can fire later.
    void abortAll();

signals:
    // Emitted after an unrecoverable refresh failure or a malformed token
    // payload: the client no longer holds usable credentials and must mark
    // itself unauthenticated. The old refresh token is never re-sent.
    void authenticationLost();

private:
    struct RequestContext; // defined in the .cpp

    void sendRequest(const QByteArray& method,
                     const QString& path,
                     const QJsonObject& body,
                     bool authenticated,
                     bool retried,
                     Completion completion,
                     const QString& bearerOverride = QString());
    void finishRequest(RequestContext* context);
    void complete(RequestContext* context, const Result& result);
    void deliver(const Completion& completion, const Result& result);

    void handleUnauthorized(RequestContext* context, const Result& result);
    void startRefresh();
    void finishRefresh(const Result& result);
    void flushRefreshWaiters(bool success, const Result& failure);

    QNetworkAccessManager* m_nam = nullptr;
    QUrl m_origin;
    QSslConfiguration m_sslConfiguration;
    int m_timeoutMs = kDefaultTimeoutMs;
    qint64 m_maxBodyBytes = kDefaultMaxBodyBytes;

    QString m_accessToken;
    QString m_refreshToken;

    // Bumped on every adopt/clear.  logoutBestEffort() captures it so a reply
    // arriving after re-authentication cannot clear newer credentials.
    quint64 m_tokenEpoch = 0;

    bool m_refreshInFlight = false;
    bool m_aborting = false;      // guards completions that re-enter abortAll()
    QSet<RequestContext*> m_contexts;
    QList<RequestContext*> m_refreshWaiters;
};

#endif // KANADEAPI_H
