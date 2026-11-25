#include "kanadeapi.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QRegularExpression>
#include <QTimer>

// ---------------------------------------------------------------------------
// RequestContext
// ---------------------------------------------------------------------------

struct KanadeApi::RequestContext {
    QPointer<QNetworkReply> reply;
    QTimer* timer = nullptr;
    Completion completion;
    QByteArray method;
    QString path;
    QJsonObject body;
    QString bearer; // non-empty only for logout (token state already cleared)
    bool authenticated = false;
    bool retried = false;
    // Termination flags; the first one set wins when the result is built.
    bool finished = false;
    bool tlsFailure = false;
    bool timedOut = false;
    bool bodyTooLarge = false;
    bool cancelled = false;
};

// ---------------------------------------------------------------------------
// Construction / configuration
// ---------------------------------------------------------------------------

KanadeApi::KanadeApi(QObject* parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
    , m_sslConfiguration(QSslConfiguration::defaultConfiguration())
{
    m_nam->setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
}

KanadeApi::~KanadeApi()
{
    // Destructor must not run application code: completions can re-enter this
    // object.  Detach and drop everything without delivering.
    for (RequestContext* context : m_contexts) {
        if (QNetworkReply* reply = context->reply) {
            reply->disconnect(this);
            reply->abort();
        }
        if (context->timer != nullptr) {
            context->timer->stop();
            context->timer->disconnect(this);
        }
        delete context;
    }
    m_contexts.clear();
    for (RequestContext* waiter : m_refreshWaiters)
        delete waiter;
    m_refreshWaiters.clear();
}

bool KanadeApi::normalizeOrigin(const QString& serviceUrl, QUrl& originOut)
{
    // Strict mode: malformed input parses to an invalid URL.
    const QUrl url(serviceUrl.trimmed(), QUrl::StrictMode);
    if (!url.isValid() || url.isRelative())
        return false;
    if (url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0)
        return false;
    if (url.host().isEmpty())
        return false;
    // An explicit :0 is not a valid HTTPS port.  QUrl reports it as port 0,
    // which the "non-default port" branch below would silently drop; reject it
    // instead of turning a malformed target into the default port.
    if (url.port() == 0)
        return false;
    if (url.authority(QUrl::FullyEncoded).contains(QLatin1Char('@')))
        return false; // credentials in URLs are rejected, never preserved
    if (url.hasFragment() || url.hasQuery() || url.host().contains(QLatin1Char(':')))
        return false;
    if (!url.path().isEmpty() && url.path() != QLatin1String("/"))
        return false;

    QUrl origin;
    origin.setScheme(QStringLiteral("https"));
    origin.setHost(url.host().toLower());
    if (url.port() > 0 && url.port() != 443)
        origin.setPort(url.port());
    if (!origin.isValid() || origin.host().isEmpty())
        return false;
    originOut = origin;
    return true;
}

bool KanadeApi::setOrigin(const QUrl& origin)
{
    QUrl canonical;
    if (!normalizeOrigin(origin.toString(QUrl::FullyEncoded), canonical) || canonical != origin)
        return false;
    if (hasTokens() && origin != m_origin)
        return false; // cross-origin swap with live credentials: refuse
    m_origin = origin;
    return true;
}

QUrl KanadeApi::origin() const
{
    return m_origin;
}

void KanadeApi::setSslConfiguration(const QSslConfiguration& configuration)
{
    m_sslConfiguration = configuration;
}

void KanadeApi::setTimeouts(int totalTimeoutMs, qint64 maxBodyBytes)
{
    m_timeoutMs = totalTimeoutMs > 0 ? totalTimeoutMs : kDefaultTimeoutMs;
    m_maxBodyBytes = maxBodyBytes > 0 ? maxBodyBytes : kDefaultMaxBodyBytes;
}

// ---------------------------------------------------------------------------
// Token state (memory only)
// ---------------------------------------------------------------------------

bool KanadeApi::tokenPairIsUsable(const QJsonObject& tokenPair)
{
    static const QRegularExpression access(QStringLiteral("\\Akat_[A-Za-z0-9_-]{43}\\z"));
    static const QRegularExpression refresh(QStringLiteral("\\Akrt_[A-Za-z0-9_-]{64}\\z"));
    return tokenPair.value(QStringLiteral("token_type")).toString() == QLatin1String("Bearer")
        && access.match(tokenPair.value(QStringLiteral("access_token")).toString()).hasMatch()
        && refresh.match(tokenPair.value(QStringLiteral("refresh_token")).toString()).hasMatch();
}

void KanadeApi::adoptTokenPair(const QJsonObject& tokenPair)
{
    if (!tokenPairIsUsable(tokenPair)) {
        if (hasTokens()) {
            clearTokens();
            emit authenticationLost();
        }
        return;
    }
    m_accessToken = tokenPair.value(QStringLiteral("access_token")).toString();
    m_refreshToken = tokenPair.value(QStringLiteral("refresh_token")).toString();
    ++m_tokenEpoch;
}

void KanadeApi::clearTokens()
{
    m_accessToken.clear();
    m_refreshToken.clear();
    ++m_tokenEpoch;
}

bool KanadeApi::hasTokens() const
{
    return !m_accessToken.isEmpty() || !m_refreshToken.isEmpty();
}

// ---------------------------------------------------------------------------
// Public request surface
// ---------------------------------------------------------------------------

void KanadeApi::get(const QString& path, Completion completion)
{
    sendRequest(QByteArrayLiteral("GET"), path, QJsonObject(), /*authenticated=*/true,
                /*retried=*/false, std::move(completion));
}

void KanadeApi::post(const QString& path, const QJsonObject& body, bool authenticated,
                     Completion completion)
{
    sendRequest(QByteArrayLiteral("POST"), path, body, authenticated, /*retried=*/false,
                std::move(completion));
}

void KanadeApi::del(const QString& path, Completion completion)
{
    sendRequest(QByteArrayLiteral("DELETE"), path, QJsonObject(), /*authenticated=*/true,
                /*retried=*/false, std::move(completion));
}

void KanadeApi::logoutBestEffort(Completion completion)
{
    if (m_accessToken.isEmpty() && m_refreshToken.isEmpty()) {
        if (completion)
            completion(Result{});
        return;
    }

    // Capture and CLEAR synchronously: local sign-out must not depend on the
    // network, and once the tokens are gone no later reply can change state.
    const QString access = m_accessToken;
    const QString refresh = m_refreshToken;
    clearTokens(); // bumps m_tokenEpoch

    QJsonObject body;
    if (!refresh.isEmpty())
        body.insert(QStringLiteral("refresh_token"), refresh);
    if (!access.isEmpty())
        body.insert(QStringLiteral("access_token"), access);

    // authenticated=false with an explicit bearer: token state is empty now, so
    // this must not ride (or trigger) the refresh machinery.
    sendRequest(QByteArrayLiteral("POST"), QStringLiteral("/v1/auth/logout"), body,
                /*authenticated=*/false, /*retried=*/true,
                [completion](const Result& result) {
                    // Best effort: the local logout already happened; the
                    // remote outcome never changes user-visible state.
                    if (completion)
                        completion(result);
                },
                access);
}

void KanadeApi::abortAll()
{
    if (m_aborting)
        return; // a completion re-entered abortAll(); outer sweep owns it
    m_aborting = true;

    // Phase 1: remove and fully detach every context/pending waiter so later
    // completions cannot observe (or free) them, and no Qt signal can reach a
    // context while we are delivering.
    const QList<RequestContext*> contexts = m_contexts.values();
    m_contexts.clear();
    QList<Completion> doomed;
    doomed.reserve(contexts.size());
    for (RequestContext* context : contexts) {
        if (context == nullptr)
            continue;
        context->finished = true;
        context->cancelled = true;
        if (QNetworkReply* reply = context->reply) {
            reply->disconnect(this);
            reply->abort();
            reply->deleteLater();
            context->reply = nullptr;
        }
        if (context->timer != nullptr) {
            context->timer->stop();
            context->timer->disconnect(this);
            context->timer->deleteLater();
            context->timer = nullptr;
        }
        if (context->completion)
            doomed.append(std::move(context->completion));
        delete context;
    }

    const QList<RequestContext*> waiters = m_refreshWaiters;
    m_refreshWaiters.clear();
    for (RequestContext* waiter : waiters) {
        if (waiter == nullptr)
            continue;
        if (waiter->completion)
            doomed.append(std::move(waiter->completion));
        delete waiter;
    }
    m_refreshInFlight = false;

    // Phase 2: deliver cancellations from the snapshot.  A delivery may start
    // new requests (e.g. sign-out right after abort) which must survive this
    // sweep, so m_aborting stays set: any nested abortAll returns immediately
    // and the outer sweep remains the only authority.
    const Result cancelled{ErrorKind::Cancelled};
    for (const Completion& completion : doomed) {
        if (completion)
            completion(cancelled);
    }
    m_aborting = false;
}



// ---------------------------------------------------------------------------
// Core request machinery
// ---------------------------------------------------------------------------

void KanadeApi::sendRequest(const QByteArray& method, const QString& path,
                            const QJsonObject& body, bool authenticated, bool retried,
                            Completion completion, const QString& bearerOverride)
{
    Result early;
    if (m_aborting) {
        early.kind = ErrorKind::Cancelled;
        deliver(completion, early);
        return;
    }
    if (!m_origin.isValid() || m_origin.scheme() != QLatin1String("https")) {
        early.kind = ErrorKind::InvalidOrigin;
        deliver(completion, early);
        return;
    }
    if (authenticated && m_accessToken.isEmpty() && bearerOverride.isEmpty()) {
        if (!m_refreshToken.isEmpty() && path != QLatin1String("/v1/auth/refresh")) {
            // Expiry boundary: ride the single-flight refresh, then retry once.
            auto* waiter = new RequestContext;
            waiter->method = method;
            waiter->path = path;
            waiter->body = body;
            waiter->authenticated = authenticated;
            waiter->retried = true;
            waiter->completion = std::move(completion);
            waiter->bearer = bearerOverride;
            m_refreshWaiters.append(waiter);
            startRefresh();
            return;
        }
        early.kind = ErrorKind::HttpError;
        early.httpStatus = 401;
        early.serverCode = QStringLiteral("token_missing");
        deliver(completion, early);
        return;
    }

    QUrl url(m_origin);
    url.setPath(path, QUrl::StrictMode);

    QNetworkRequest request(url);
    request.setSslConfiguration(m_sslConfiguration);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/json"));
    // Never follow redirects, never touch cookies.
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
#else
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::UserVerifiedRedirectPolicy);
#endif
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute,
                         QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute,
                         QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::AuthenticationReuseAttribute,
                         QNetworkRequest::Manual);
    if (authenticated || !bearerOverride.isEmpty()) {
        // logoutBestEffort() clears token state before sending, so it passes
        // authenticated=false with an explicit bearer; the header must still be
        // attached (the body also carries the token as a server-side fallback).
        const QString bearer = bearerOverride.isEmpty() ? m_accessToken : bearerOverride;
        request.setRawHeader("Authorization", "Bearer " + bearer.toUtf8());
    }

    auto* context = new RequestContext;
    context->method = method;
    context->path = path;
    context->body = body;
    context->authenticated = authenticated;
    context->retried = retried;
    context->completion = std::move(completion);
    context->bearer = bearerOverride;
    m_contexts.insert(context);

    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
    if (method == QByteArrayLiteral("GET"))
        context->reply = m_nam->get(request);
    else
        context->reply = m_nam->sendCustomRequest(request, method, payload);

    QNetworkReply* reply = context->reply;
    // Fail closed on any TLS problem: abort without ever calling
    // ignoreSslErrors(); chain and hostname verification stay enabled.
    connect(reply, &QNetworkReply::sslErrors, this, [context](const QList<QSslError>&) {
        context->tlsFailure = true;
        if (context->reply)
            context->reply->abort();
    });
    connect(reply, &QNetworkReply::downloadProgress, this,
            [this, context](qint64 bytesReceived, qint64) {
                if (bytesReceived > m_maxBodyBytes) {
                    context->bodyTooLarge = true;
                    if (context->reply)
                        context->reply->abort();
                }
            });

    context->timer = new QTimer(this);
    context->timer->setSingleShot(true);
    connect(context->timer, &QTimer::timeout, this, [context]() {
        context->timedOut = true;
        if (context->reply)
            context->reply->abort();
    });
    context->timer->start(m_timeoutMs);

    connect(reply, &QNetworkReply::finished, this,
            [this, context]() { finishRequest(context); });
}

void KanadeApi::finishRequest(RequestContext* context)
{
    if (context->finished)
        return;

    Result result;
    if (context->cancelled) {
        result.kind = ErrorKind::Cancelled;
    } else if (context->tlsFailure) {
        result.kind = ErrorKind::Tls;
    } else if (context->timedOut) {
        result.kind = ErrorKind::Timeout;
    } else if (context->bodyTooLarge) {
        result.kind = ErrorKind::BodyTooLarge;
    } else {
        QNetworkReply* reply = context->reply;
        const QVariant statusAttribute =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int status = statusAttribute.isValid() ? statusAttribute.toInt() : 0;
        const QByteArray rawBody = reply->readAll();

        if (status >= 300 && status < 400) {
            result.kind = ErrorKind::Redirect; // never followed
            result.httpStatus = status;
        } else if (reply->error() == QNetworkReply::NoError) {
            result.httpStatus = status;
            if (rawBody.isEmpty()) {
                result.kind = ErrorKind::None;
            } else {
                QJsonParseError parseError;
                const QJsonDocument document = QJsonDocument::fromJson(rawBody, &parseError);
                if (parseError.error == QJsonParseError::NoError && document.isObject()) {
                    result.kind = ErrorKind::None;
                    result.body = document.object();
                } else {
                    result.kind = ErrorKind::ParseError;
                }
            }
        } else if (status > 0) {
            // HTTP error: recover detail.code for the controller's allowlist
            // mapping. Response bodies never reach logs or the UI.
            result.kind = ErrorKind::HttpError;
            result.httpStatus = status;
            QJsonParseError parseError;
            const QJsonDocument document = QJsonDocument::fromJson(rawBody, &parseError);
            if (parseError.error == QJsonParseError::NoError && document.isObject()) {
                const QJsonValue detail = document.object().value(QStringLiteral("detail"));
                if (detail.isObject()) {
                    result.serverCode =
                        detail.toObject().value(QStringLiteral("code")).toString();
                }
            }
        } else {
            result.kind = ErrorKind::Network;
        }
    }

    // Single-flight refresh: exactly one retry, only after a successful
    // rotation, never for the refresh call itself, and only for 401s that
    // mean "this access token is stale" (never for credential failures).
    const bool refreshable = context->authenticated && !context->retried
        && context->path != QLatin1String("/v1/auth/refresh")
        && !m_refreshToken.isEmpty()
        && result.kind == ErrorKind::HttpError && result.httpStatus == 401
        && (result.serverCode == QLatin1String("token_expired")
            || result.serverCode == QLatin1String("token_invalid"));
    if (refreshable) {
        handleUnauthorized(context);
        return;
    }

    complete(context, result);
}

void KanadeApi::handleUnauthorized(RequestContext* context)
{
    auto* waiter = new RequestContext;
    waiter->method = context->method;
    waiter->path = context->path;
    waiter->body = context->body;
    waiter->authenticated = context->authenticated;
    waiter->bearer = context->bearer;
    waiter->retried = true; // retried once the refresh succeeds
    waiter->completion = std::move(context->completion);
    m_refreshWaiters.append(waiter);
    // The completion was moved out; this only releases the context/reply.
    complete(context, Result{ErrorKind::Cancelled});
    startRefresh();
}

void KanadeApi::startRefresh()
{
    if (m_refreshInFlight)
        return;
    if (m_refreshToken.isEmpty()) {
        flushRefreshWaiters(false,
                            Result{ErrorKind::HttpError, 401,
                                   QStringLiteral("token_missing"), QJsonObject()});
        return;
    }
    m_refreshInFlight = true;
    sendRequest(QByteArrayLiteral("POST"), QStringLiteral("/v1/auth/refresh"),
                QJsonObject{{QStringLiteral("refresh_token"), m_refreshToken}},
                /*authenticated=*/false, /*retried=*/true,
                [this](const Result& result) { finishRefresh(result); });
}

void KanadeApi::finishRefresh(const Result& result)
{
    m_refreshInFlight = false;
    if (result.kind == ErrorKind::None && tokenPairIsUsable(result.body)) {
        adoptTokenPair(result.body);
        flushRefreshWaiters(true, Result{});
        return;
    }
    // Definitive or ambiguous failure: fail closed. The old refresh token is
    // never re-sent and no waiter is retried with stale credentials.
    clearTokens();
    flushRefreshWaiters(false, result.kind == ErrorKind::None
                                   ? Result{ErrorKind::HttpError, 401,
                                            QStringLiteral("token_invalid"), QJsonObject()}
                                   : result);
    emit authenticationLost();
}

void KanadeApi::flushRefreshWaiters(bool success, const Result& failure)
{
    // Detach the whole list first: a delivery may re-enter (new request,
    // abortAll) and must never see a half-processed waiter.
    const QList<RequestContext*> waiters = m_refreshWaiters;
    m_refreshWaiters.clear();
    for (RequestContext* waiter : waiters) {
        const QByteArray method = waiter->method;
        const QString path = waiter->path;
        const QJsonObject body = waiter->body;
        const bool authenticated = waiter->authenticated;
        const QString bearer = waiter->bearer;
        Completion completion = std::move(waiter->completion);
        delete waiter;

        if (success) {
            sendRequest(method, path, body, authenticated, /*retried=*/true,
                        std::move(completion), bearer);
        }
        else if (completion) {
            completion(failure);
        }
    }
}

void KanadeApi::complete(RequestContext* context, const Result& result)
{
    if (context->finished)
        return;
    context->finished = true;
    m_contexts.remove(context);

    // Detach the reply before the context dies: no late signal (abort() can
    // emit finished() synchronously) may touch freed state.
    QNetworkReply* reply = context->reply;
    if (reply != nullptr) {
        reply->disconnect(this);
        reply->deleteLater();
    }
    if (context->timer != nullptr) {
        context->timer->stop();
        context->timer->deleteLater();
        context->timer = nullptr;
    }

    Completion completion = std::move(context->completion);
    delete context;
    if (completion)
        completion(result);
}

void KanadeApi::deliver(const Completion& completion, const Result& result)
{
    if (completion)
        completion(result);
}
