#pragma once

#ifndef KANADESESSION_H
#define KANADESESSION_H

#include <QByteArray>
#include <QJsonObject>
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QUrl>

#include <functional>

// Kanade online-mode client session lifecycle (control plane only).
//
// This module owns the device-authorized connection-session state machine of
// the Moonlight online mode: offer creation, host-accept observation, the
// client-side lease gate, renewal, revocation handling and deterministic
// close/cancel/logout.  It is the client-side counterpart of Kanade
// src/kanade/api/sessions.py (+ persistence/sessions.py).
//
// Wire contract (must match the server exactly):
//   * Base URL is the configured HTTPS origin; all paths below are absolute
//     and mounted under "/v1" (see Kanade src/kanade/main.py).  Every outgoing
//     request carries that normalized origin, so a transport can never pair a
//     request with a different peer.
//   * POST   /v1/sessions            {"grant_id": <uuid>} -> 201
//                                    {"session": <snapshot>, "expires_at": ...,
//                                     "server_time": <epoch seconds>}
//   * GET    /v1/sessions/current    -> 200 {"session": <snapshot>|null,
//                                            "role": ..., "server_time": ...}
//     READ-ONLY DIAGNOSTIC endpoint (plan section 5.3): returns at most the
//     calling installation's own open session; it is registered before the
//     parameterized route.  It is used only to classify a lost POST /sessions
//     outcome ("not applied" vs "unverifiable").  It NEVER adopts a session,
//     never opens the lease gate and never emits authorized(): an offer that
//     cannot be verified from the create response itself is abandoned and left
//     to the server offer TTL.  It also never triggers a DELETE.
//   * GET    /v1/sessions/{id}       -> 200 {"session": <snapshot>,
//                                            "role": "client",
//                                            "server_time": <epoch seconds>}
//   * POST   /v1/sessions/{id}/renew -> 200 {"session": <snapshot>,
//                                            "lease_until": ...,
//                                            "server_time": <epoch seconds>}
//   * DELETE /v1/sessions/{id}       -> 200 {"session": <snapshot>}
//     Idempotent server-side; only ever sent for an id this attempt already
//     owns from its own create reply.  Never sent because an entry is merely
//     "old", and never sent when the create outcome is unknown.
//   * Every session-bearing response MUST carry an integer "server_time".
//     A missing/invalid server_time is a protocol error and fails closed:
//     the local monotonic deadline is derived from server_time and the
//     request start, so an unverifiable clock base can never mint a lease.
//   * Error bodies use the shared envelope
//     {"detail": {"code": <string>, "message": <string>}}; only the code is
//     surfaced (failureDetail), never tokens or payloads.
//   * <snapshot> is session_snapshot() from persistence/sessions.py:
//     id/grant_id/host_id/host_installation_id/client_installation_id are
//     canonical lowercase UUIDs, host_key_version/client_key_version are
//     positive integers, state in {offered,active,closed,expired}, plus
//     lease_until/offered_until/created_at/closed_reason/is_open.
//
// Binding and security invariants (implementation-prompt "安全不可退让",
// plan 3.3 and 5.5):
//   * Exact expected scope.  setExpectedTarget() captures the selected host
//     id, host installation id and BOTH key versions.  Every response must
//     match that scope plus the attempt's grant id and this client
//     installation id exactly, and poll/renew replies must also name this
//     attempt's session id.  Anything else fails closed; no snapshot is
//     adopted, no mutation is steered from it.
//   * Configuration is frozen for the duration of an attempt: every setter
//     refuses (returns false) while a session is Creating/Diagnosing/
//     Offering/Active/Closing.  There is no mid-attempt rebinding of origin,
//     token, installation or target.
//   * Create exactly once per start().  POST /sessions, and any other
//     mutation with an uncertain outcome, is NEVER replayed.  An ambiguous
//     create is classified read-only and then abandoned; a retry needs a new
//     explicit start().
//   * The local lease gate is an independent monotonic deadline derived from
//     (request start, server_time, lease_until), clamped to the server lease
//     TTL (90 s).  It is checked against BOTH the monotonic clock and the
//     wall clock, so system-time jumps and sleep/resume can only shorten,
//     never extend, a lease.  Only this client's own confirmed responses
//     extend it, and only when their lease_until is STRICTLY greater than the
//     last confirmed value; equal or lower confirmations (replays, delayed or
//     out-of-order replies) leave the deadline untouched.  Nothing the peer,
//     a socket, a ticket TTL or UI state does can move it.
//   * A confirmed revocation/closure (grant_revoked, session_closed,
//     lease_expired, host-closed snapshot) stops the client locally at once.
//   * The access token is memory-only, attached by the transport as a Bearer
//     credential, and never logged by this module.
//   * HTTPS only: start() refuses any non-https or non-canonical origin.  The
//     transport must not follow redirects and must not relax TLS verification.
//
// Explicit non-goals (do not "fix" these here):
//   * No ticket minting policy, no transport, no data plane.  Activation is
//     limited to sending a caller-SIGNED proof (the caller supplies the
//     canonical base64 Ed25519 signature; signing happens in kanadesidecar.cpp
//     so this unit stays crypto-free and linkable by its offline test).
//     The controller lane owns orchestration; this class never reports
//     streaming readiness and never claims a tunnel exists.
//   * authorized() means "Kanade lease active" only.  activationConfirmed()
//     means the SERVER reported both participants' proofs; neither is a
//     data-plane "connected" state.
//
// Threading: KanadeSession and its KanadeHttpTransport must live on the same
// (controller) thread; all transport callbacks are delivered as direct
// signal emissions on that thread.
namespace Kanade {

// One outgoing control-plane request.  The transport serializes `body` as
// compact JSON for POST, sends the request only to `origin`, attaches
// "Authorization: Bearer <bearerToken>", applies `timeoutMs`, and must report
// timeouts as Error::Timeout (an ambiguous outcome), never silently retry.
struct KanadeHttpRequest {
    QString origin;         // normalized https origin this request belongs to
    QByteArray method;      // "GET" | "POST" | "DELETE"
    QString path;           // absolute, starts with "/v1/"
    QJsonObject body;       // POST payload; empty for GET/DELETE
    QByteArray bearerToken; // memory-only; never log
    int timeoutMs = 10000;
};

struct KanadeHttpReply {
    enum class Error {
        None,    // HTTP response received (see httpStatus)
        Network, // connection failed / dropped before a response
        Timeout, // request deadline exceeded; outcome unknown
        Aborted, // aborted via abort(); normally not delivered at all
        Tls      // TLS handshake/verification failure (fail closed)
    };
    Error error = Error::None;
    int httpStatus = 0; // 0 when error != None
    QByteArray body;    // raw response body (JSON object expected)
};
} // namespace Kanade

Q_DECLARE_METATYPE(Kanade::KanadeHttpReply)

namespace Kanade {

// Injectable async HTTPS sender.  Implemented by the controller lane with
// QNetworkAccessManager (or equivalent) and by tests with a fake.  send()
// returns an opaque tag; every started request eventually produces exactly
// one finished() emission unless abort() was called for it.  Callbacks are
// delivered on the transport's thread, which must equal the session's.
class KanadeHttpTransport : public QObject {
    Q_OBJECT
public:
    explicit KanadeHttpTransport(QObject* parent = nullptr) : QObject(parent) {}
    ~KanadeHttpTransport() override = default;

    virtual quint64 send(const KanadeHttpRequest& request) = 0;
    virtual void abort(quint64 tag) = 0;

Q_SIGNALS:
    void finished(quint64 tag, const Kanade::KanadeHttpReply& reply);
};

class KanadeSession : public QObject {
    Q_OBJECT
public:
    // Lifecycle states.  Closed and Failed are terminal; start() is accepted
    // again only from Idle/Closed/Failed.
    enum class State {
        Idle,        // no attempt running
        Creating,    // POST /v1/sessions in flight (exactly once)
        Diagnosing,  // create outcome unknown; GET /v1/sessions/current in flight
        Offering,    // offer adopted from our create reply; waiting for host accept
        Active,      // host accepted; local lease gate armed; renewing
        Closing,     // local stop requested; best-effort remote cleanup running
        Closed,      // terminal: clean end (user, server, or offer expiry)
        Failed       // terminal: error / fail-closed stop
    };
    Q_ENUM(State)

    enum class StopReason {
        None,
        UserCancelled,    // cancel()
        Logout,           // logout()
        ServerClosed,     // authoritative snapshot says closed by host/server
        GrantRevoked,     // server confirmed grant revocation
        LeaseExpired,     // local lease gate reached (API unreachable or renew lost)
        OfferExpired,     // offer window elapsed without host acceptance
        SessionExpired,   // server reports the session expired
        ProtocolError,    // malformed/foreign/unverifiable server data (fail closed)
        NetworkFailure,   // transport failure on a read-only path
        AuthFailed,       // 401/403 without a more specific code
        CreateConflict,   // an unrelated/foreign open session blocks this attempt
        CreateNotApplied, // diagnostic read proved the create never took effect
        CreateUnverified, // diagnostic read could not attribute a session: fail closed
        ActivationFailed, // ticket or activation refused; nothing was retried
        ActivationUnconfirmed // activation could not be proven on both sides
    };
    Q_ENUM(StopReason)

    // Cadence knobs.  Defaults follow the plan (renew ~30 s, offer poll a few
    // seconds, 1 s lease watchdog); tests shrink them.  These never affect
    // the server-confirmed deadlines themselves.
    struct Timing {
        int renewIntervalMs = 30000;
        int offerPollIntervalMs = 2000;
        int watchdogIntervalMs = 1000;
        int requestTimeoutMs = 10000;
    };

    // The exact selected peer scope, captured from the explicit user
    // selection before start().  Every response is checked against it.
    struct ExpectedTarget {
        QString hostId;               // canonical UUID4
        QString hostInstallationId;   // canonical UUID4
        int hostKeyVersion = 0;       // >= 1
        int clientKeyVersion = 0;     // >= 1
    };

    explicit KanadeSession(KanadeHttpTransport* transport, QObject* parent = nullptr);

    // --- Configuration (frozen while an attempt is live) ---------------------
    // Each setter returns false without changing anything when an attempt is
    // in flight (Creating/Diagnosing/Offering/Active/Closing).  They are safe
    // to call again only from Idle/Closed/Failed before the next start().

    // Accepts only a canonical HTTPS origin ("https://host[:port]", see
    // managedendpoint.h) and stores its normalized form.
    bool setServerOrigin(const QUrl& origin);
    bool setInstallationId(const QString& installationId); // canonical UUID4
    bool setAccessToken(const QString& token);             // memory-only
    // True when the transport itself attaches the credential (and this object
    // therefore holds no token at all).  Used by the managed online path, where
    // the bearer lives only in the single KanadeApi instance.  Refused while an
    // attempt is live.
    bool setTransportProvidesCredentials(bool provided);
    bool setTiming(const Timing& timing);
    bool setExpectedTarget(const ExpectedTarget& target);

    // Test hook: replace the clocks.  monotonicMs must be non-decreasing;
    // wallClockSecs is epoch seconds. Windows uses uptime including suspend;
    // QDateTime::currentSecsSinceEpoch() is an additional conservative check.
    void setClockForTesting(std::function<qint64()> monotonicMs,
                            std::function<qint64()> wallClockSecs);
#ifdef KANADE_SESSION_TEST
    void pollActivationForTesting() { onWatchdog(); }
#endif

    State state() const { return m_state; }
    StopReason stopReason() const { return m_stopReason; }
    QString sessionId() const { return m_sessionId; }
    QString grantId() const { return m_grantId; }
    QString origin() const { return m_origin; }
    QString installationId() const { return m_installationId; }
    ExpectedTarget expectedTarget() const { return m_target; }

    // True only when the SERVER's scoped read (or the activate reply) reported
    // activation.both_activated for THIS session.  A ticket, a local proof or
    // the peer's renewal can never set it, and a scoped read never extends the
    // lease gate.
    bool activationConfirmed() const { return m_activationConfirmed; }
    // True while the server reports this attempt's own activation recorded.
    bool localActivationRecorded() const { return m_localActivationRecorded; }

    // The local lease gate: true only while BOTH the monotonic deadline and
    // the wall-clock deadline (last confirmed by our own renew) are in the
    // future.  This is the last gate; when it is false nothing may flow.
    bool hasValidLease() const;
    qint64 leaseRemainingMs() const; // 0 when the gate is closed
    // Absolute deadline on the SAME monotonic clock as GetTickCount64() (-1 when
    // no lease is held).  This is what a sidecar/native guard is given: absolute
    // instants only, never a relative duration.
    qint64 leaseDeadlineMonotonicMs() const { return m_leaseMonoDeadlineMs; }

    // Starts one attempt for a grant.  Accepted only from Idle/Closed/Failed
    // with a complete configuration; otherwise transitions to
    // Failed/ProtocolError (or is ignored while an attempt is running).
    // Never replays a create.
    void start(const QString& grantId);

    // Deterministic user cancel: immediate local stop of the lease gate,
    // in-flight requests are aborted, late replies are dropped, and one
    // best-effort DELETE runs before Closed when this attempt already owns a
    // session id from its own create reply.  When the create outcome is
    // unknown nothing is deleted: an unattributable server-side offer expires
    // on its own within the offer TTL.
    void cancel();

    // cancel() with StopReason::Logout; also drops the in-memory token.
    void logout();

    // Activation (contract `session-activation-v1`).
    //
    // The ticket is minted by this class, used immediately and never stored:
    // the caller receives only the canonical message to sign and returns the
    // proof.  `signer(ticket, message)` is expected to return the canonical
    // standard-base64 (padded) 64-byte Ed25519 proof, or empty to fail closed.
    // The ticket is passed to the signer solely so it can be hashed; the
    // session itself only ever keeps its SHA-256.
    //
    // One attempt per run.  The ticket POST and the activate POST are NEVER
    // replayed: an ambiguous outcome is classified by the read-only scoped
    // recovery read, exactly like an ambiguous create.
    using ActivationSigner = std::function<QByteArray(const QString& ticket,
                                                     const QByteArray& message)>;

    // Accepted only from Active with a valid lease; refused (returns false,
    // nothing sent) for a non-canonical binding or a live attempt.
    bool beginActivation(const QByteArray& channelBinding32, ActivationSigner signer);

    // Canonical `session-activation-v1` message, byte-identical to the server's
    // kanade.security.session_activation.activation_message().  Pure: no crypto,
    // no I/O.
    static QByteArray activationMessage(const QString& sessionId,
                                        const QString& role,
                                        const QString& clientInstallationId,
                                        const QString& hostInstallationId,
                                        int clientKeyVersion,
                                        int hostKeyVersion,
                                        const QString& ticketSha256Hex,
                                        const QString& channelBindingHex);

Q_SIGNALS:
    void stateChanged(Kanade::KanadeSession::State state);
    // Emitted once when the host acceptance is confirmed and the local lease
    // gate opens.  Means "Kanade lease active" ONLY -- there is no data
    // plane, so this is never a streaming-ready indication.
    void authorized();
    // Emitted exactly once per attempt when a terminal state is reached.
    void stopped(Kanade::KanadeSession::StopReason reason);
    // Server error code (e.g. "grant_revoked") for diagnostics.  Contains no
    // secrets; emitted before stopped() on server-confirmed failures.
    void failureDetail(const QString& serverCode);
    // Emitted once when the server reports both participants activated for
    // this attempt.  Still not a streaming-ready claim.
    void bothParticipantsActivated();
    // Emitted when our own activation was recorded but the peer's was not
    // (yet); a later read may still confirm.  Never a readiness claim.
    void activationRecorded();

private:
    enum class Purpose {
        None,
        Create,         // POST /v1/sessions
        DiagnoseCreate, // GET /v1/sessions/current (read-only classification)
        Poll,           // GET /v1/sessions/{id}
        Renew,          // POST /v1/sessions/{id}/renew
        Ticket,         // POST /v1/sessions/{id}/tickets (exactly once)
        Activate,       // POST /v1/sessions/{id}/activate (exactly once)
        ConfirmActivation, // GET /v1/sessions/current (scoped, read-only)
        Close           // DELETE /v1/sessions/{id} (explicit user close only)
    };

    struct InFlight {
        bool active = false;
        quint64 tag = 0;
        Purpose purpose = Purpose::None;
        quint64 generation = 0;
        qint64 startMonoMs = 0;
    };

    struct Snapshot {
        QString id;
        QString grantId;
        QString hostId;
        QString hostInstallationId;
        QString clientInstallationId;
        int hostKeyVersion = 0;
        int clientKeyVersion = 0;
        QString state;
        QString closedReason;
        qint64 leaseUntil = 0;
        qint64 offeredUntil = 0;
        qint64 createdAt = 0;
        bool isOpen = false;
    };

    bool isLive() const;
    bool configurationComplete() const;
    // Exact scope check: grant, this installation, expected host, expected
    // host installation, both key versions.  Set-specific id checks are the
    // caller's business.
    bool snapshotInExpectedScope(const Snapshot& snapshot) const;
    // True only when every canonical identifier and bounded integer is valid.
    bool parseSnapshot(const QJsonObject& object, Snapshot& out) const;

    void setState(State state);
    void failTerminal(StopReason reason, const QString& serverCode = QString());
    void closeTerminal(StopReason reason);

    void sendCreate();
    void sendDiagnoseCreate();
    void sendPoll();
    void sendRenew();
    void sendTicket();
    void sendConfirmActivation();
    void sendClose();
    quint64 dispatch(const QByteArray& method, const QString& path, const QJsonObject& body,
                     Purpose purpose);

    void handleFinished(quint64 tag, const KanadeHttpReply& reply);
    void handleCreateReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handleDiagnoseReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handlePollReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handleRenewReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handleTicketReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handleActivationReply(const InFlight& flight, const KanadeHttpReply& reply);
    void handleConfirmActivationReply(const KanadeHttpReply& reply);
    void handleCloseReply(const KanadeHttpReply& reply);

    // Applies an `activation` object from any session-bearing reply.  Sets
    // localActivationRecorded/activationConfirmed from the server's own booleans
    // for THIS session only; a malformed object fails closed (returns false)
    // without touching the lease gate.
    bool applyActivationObject(const QJsonObject& activation, const QString& sessionId);

    // Adopts an offered/active snapshot from the CREATE reply.  Enforces the
    // creation-age window so a previous-run session is never resurrected.
    bool adoptCreatedSnapshot(const Snapshot& snapshot, qint64 serverTime,
                              qint64 requestStartMonoMs);
    // Establishes/refreshes the lease gate from a confirmed response.
    // Returns false (and leaves the gate untouched) when the server window is
    // malformed/over TTL, the existing gate has already expired, or the new
    // ABSOLUTE deadline does not strictly advance the stored one.
    // allowInitial may be true only for the accepted-snapshot transition that
    // opens the gate for the first time; every read/renew passes false.
    bool setLeaseFromServer(qint64 leaseUntil, qint64 serverTime, qint64 requestStartMonoMs,
                            bool allowInitial);
    bool offerStillValid() const;
    void enterActive(const Snapshot& snapshot, qint64 serverTime, qint64 requestStartMonoMs);
    void armOfferGate(qint64 offeredUntil, qint64 serverTime, qint64 requestStartMonoMs);
    void expireOfferLocally();
    void expireLeaseLocally();

    void onWatchdog();
    void abortInFlight();
    void stopTimers();
    void finalizeClosed();
    void resetForStart(const QString& grantId);

    qint64 monotonicNowMs() const;
    qint64 wallNowSecs() const;

    static bool extractServerTime(const QJsonObject& root, qint64& out);
    static QString extractErrorCode(const QByteArray& body);

    KanadeHttpTransport* m_transport;
    bool m_transportProvidesCredentials = false;
    QString m_origin; // normalized "https://host[:port]"; empty until valid
    QString m_installationId;
    QString m_accessToken; // memory-only
    ExpectedTarget m_target;

    Timing m_timing;
    std::function<qint64()> m_monotonicFn;
    std::function<qint64()> m_wallFn;

    State m_state = State::Idle;
    StopReason m_stopReason = StopReason::None;
    bool m_stoppedEmitted = false;
    quint64 m_generation = 0;

    QString m_grantId;
    QString m_sessionId;

    InFlight m_inFlight;

    // Lease gate (Active).  -1/0 while no lease is held.
    qint64 m_leaseMonoDeadlineMs = -1;
    qint64 m_leaseWallDeadlineSecs = 0;
    // Offer gate (Offering).
    qint64 m_offerMonoDeadlineMs = -1;
    qint64 m_offerWallDeadlineSecs = 0;

    // Activation (exactly one attempt per run).  The ticket and the proof are
    // local variables inside the ticket handler; only the digest is retained.
    bool m_activationSubmitted = false;
    bool m_activationInFlight = false;
    bool m_localActivationRecorded = false;
    bool m_activationConfirmed = false;
    bool m_activationEmitted = false;
    QByteArray m_activationBinding; // 32 raw bytes; wire form derived on send
    ActivationSigner m_activationSigner;

    QTimer m_renewTimer;
    QTimer m_offerPollTimer;
    QTimer m_watchdogTimer;
};

} // namespace Kanade

#endif // KANADESESSION_H
