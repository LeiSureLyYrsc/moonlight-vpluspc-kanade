#include "kanadesession.h"

#include "managedendpoint.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#endif

// Contract constants mirroring Kanade persistence/sessions.py.  The server is
// always authoritative; these are the local upper bounds a response is checked
// against, and a response outside them is REFUSED rather than clamped.
namespace {
// LEASE_TTL_SECONDS: a confirmed response can never open a local gate
// longer than this, regardless of the lease_until it carries.
constexpr qint64 kLeaseTtlCapSeconds = 90;
// OFFER_TTL_SECONDS: cap for the local offer window.
constexpr qint64 kOfferTtlCapSeconds = 60;
// Maximum age (server_time - created_at) of a session adopted from the
// CREATE reply.  Anything older belongs to a previous run and must never be
// resurrected (plan: restart re-authorizes).
constexpr qint64 kAdoptionWindowSeconds = 120;
// Tolerated server/client clock skew for created_at sanity checks.
constexpr qint64 kCreatedAtSkewSeconds = 5;
// Upper bound for key versions; the server schema is a 32-bit integer.
constexpr int kKeyVersionMax = 2147483647;

const QString kSessionsPath = QStringLiteral("/v1/sessions");
const QString kCurrentPath = QStringLiteral("/v1/sessions/current");

// Absolute deadline anchoring helper for the OFFER window.  (Leases use
// setLeaseFromServer(), which refuses a malformed/over-long window instead of
// clamping it.)
qint64 clampRemaining(qint64 serverRemaining, qint64 capSeconds)
{
    if (serverRemaining < 0) {
        return 0;
    }
    return serverRemaining > capSeconds ? capSeconds : serverRemaining;
}
} // namespace

namespace Kanade {

KanadeSession::KanadeSession(KanadeHttpTransport* transport, QObject* parent)
    : QObject(parent)
    , m_transport(transport)
{
    Q_ASSERT(m_transport != nullptr);
    // Same-thread delivery is a hard requirement (see header).
    Q_ASSERT(m_transport->thread() == thread());

    m_monotonicFn = []() -> qint64 {
#ifdef Q_OS_WIN
        return static_cast<qint64>(GetTickCount64());
#else
        static QElapsedTimer timer = [] {
            QElapsedTimer t;
            t.start();
            return t;
        }();
        return timer.elapsed();
#endif
    };
    m_wallFn = []() { return QDateTime::currentSecsSinceEpoch(); };

    connect(m_transport, &KanadeHttpTransport::finished,
            this, &KanadeSession::handleFinished);

    m_renewTimer.setSingleShot(false);
    m_offerPollTimer.setSingleShot(false);
    m_watchdogTimer.setSingleShot(false);

    connect(&m_renewTimer, &QTimer::timeout, this, [this] {
        if (m_state != State::Active || m_inFlight.active) {
            return;
        }
        if (!hasValidLease()) {
            expireLeaseLocally();
            return;
        }
        sendRenew();
    });

    connect(&m_offerPollTimer, &QTimer::timeout, this, [this] {
        if (m_state != State::Offering || m_inFlight.active) {
            return;
        }
        if (!offerStillValid()) {
            expireOfferLocally();
            return;
        }
        sendPoll();
    });

    // The watchdog is the fail-closed backstop: it re-checks BOTH clocks so a
    // sleeping/suspended machine (monotonic clock paused) still stops at the
    // wall-clock deadline after resume, and vice versa.
    connect(&m_watchdogTimer, &QTimer::timeout, this, &KanadeSession::onWatchdog);
}

bool KanadeSession::isLive() const
{
    return m_state == State::Creating || m_state == State::Diagnosing
        || m_state == State::Offering || m_state == State::Active
        || m_state == State::Closing;
}

bool KanadeSession::setServerOrigin(const QUrl& origin)
{
    if (isLive()) {
        return false;
    }
    QString canonical;
    if (!ManagedEndpointContext::validateApiOrigin(origin.toString(), &canonical).ok()) {
        return false;
    }
    m_origin = canonical;
    return true;
}

bool KanadeSession::setInstallationId(const QString& installationId)
{
    if (isLive() || !ManagedEndpointContext::isCanonicalUuid4(installationId)) {
        return false;
    }
    m_installationId = installationId;
    return true;
}

bool KanadeSession::setAccessToken(const QString& token)
{
    if (isLive() || token.isEmpty()) {
        return false;
    }
    m_accessToken = token;
    return true;
}

bool KanadeSession::setTransportProvidesCredentials(bool provided)
{
    if (isLive()) {
        return false;
    }
    m_transportProvidesCredentials = provided;
    return true;
}

bool KanadeSession::setTiming(const Timing& timing)
{
    if (isLive()) {
        return false;
    }
    if (timing.renewIntervalMs <= 0 || timing.offerPollIntervalMs <= 0
        || timing.watchdogIntervalMs <= 0 || timing.requestTimeoutMs <= 0) {
        return false;
    }
    m_timing = timing;
    return true;
}

bool KanadeSession::setExpectedTarget(const ExpectedTarget& target)
{
    if (isLive()) {
        return false;
    }
    if (!ManagedEndpointContext::isCanonicalUuid4(target.hostId)
        || !ManagedEndpointContext::isCanonicalUuid4(target.hostInstallationId)
        || target.hostKeyVersion < 1 || target.hostKeyVersion > kKeyVersionMax
        || target.clientKeyVersion < 1 || target.clientKeyVersion > kKeyVersionMax) {
        return false;
    }
    m_target = target;
    return true;
}

void KanadeSession::setClockForTesting(std::function<qint64()> monotonicMs,
                                       std::function<qint64()> wallClockSecs)
{
    if (monotonicMs) {
        m_monotonicFn = std::move(monotonicMs);
    }
    if (wallClockSecs) {
        m_wallFn = std::move(wallClockSecs);
    }
}

qint64 KanadeSession::monotonicNowMs() const
{
    return m_monotonicFn();
}

qint64 KanadeSession::wallNowSecs() const
{
    return m_wallFn();
}

bool KanadeSession::hasValidLease() const
{
    return m_leaseMonoDeadlineMs >= 0
        && monotonicNowMs() < m_leaseMonoDeadlineMs
        && wallNowSecs() < m_leaseWallDeadlineSecs;
}

qint64 KanadeSession::leaseRemainingMs() const
{
    if (!hasValidLease()) {
        return 0;
    }
    const qint64 monoRemaining = m_leaseMonoDeadlineMs - monotonicNowMs();
    const qint64 wallRemaining = (m_leaseWallDeadlineSecs - wallNowSecs()) * 1000;
    return qMin(monoRemaining, wallRemaining);
}

bool KanadeSession::offerStillValid() const
{
    return m_offerMonoDeadlineMs >= 0
        && monotonicNowMs() < m_offerMonoDeadlineMs
        && wallNowSecs() < m_offerWallDeadlineSecs;
}

bool KanadeSession::configurationComplete() const
{
    return !m_origin.isEmpty()
        && ManagedEndpointContext::isCanonicalUuid4(m_installationId)
        && (!m_accessToken.isEmpty() || m_transportProvidesCredentials)
        && ManagedEndpointContext::isCanonicalUuid4(m_target.hostId)
        && ManagedEndpointContext::isCanonicalUuid4(m_target.hostInstallationId)
        && m_target.hostKeyVersion >= 1 && m_target.clientKeyVersion >= 1;
}

void KanadeSession::setState(State state)
{
    if (m_state == state) {
        return;
    }
    m_state = state;
    emit stateChanged(state);
}

void KanadeSession::abortInFlight()
{
    if (m_inFlight.active) {
        m_transport->abort(m_inFlight.tag);
        m_inFlight = InFlight{};
    }
}

void KanadeSession::stopTimers()
{
    m_renewTimer.stop();
    m_offerPollTimer.stop();
    m_watchdogTimer.stop();
}

void KanadeSession::failTerminal(StopReason reason, const QString& serverCode)
{
    ++m_generation; // every late reply from here on is stale
    abortInFlight();
    stopTimers();
    m_leaseMonoDeadlineMs = -1;
    m_offerMonoDeadlineMs = -1;
    m_stopReason = reason;
    setState(State::Failed);
    if (!serverCode.isEmpty()) {
        emit failureDetail(serverCode);
    }
    if (!m_stoppedEmitted) {
        m_stoppedEmitted = true;
        emit stopped(reason);
    }
}

void KanadeSession::closeTerminal(StopReason reason)
{
    ++m_generation;
    abortInFlight();
    stopTimers();
    m_leaseMonoDeadlineMs = -1;
    m_offerMonoDeadlineMs = -1;
    m_stopReason = reason;
    setState(State::Closed);
    if (!m_stoppedEmitted) {
        m_stoppedEmitted = true;
        emit stopped(reason);
    }
}

void KanadeSession::finalizeClosed()
{
    stopTimers();
    abortInFlight();
    m_leaseMonoDeadlineMs = -1;
    m_offerMonoDeadlineMs = -1;
    setState(State::Closed);
    if (m_stopReason == StopReason::Logout) {
        m_accessToken.clear();
    }
    if (!m_stoppedEmitted) {
        m_stoppedEmitted = true;
        emit stopped(m_stopReason);
    }
}

void KanadeSession::resetForStart(const QString& grantId)
{
    ++m_generation;
    stopTimers();
    m_inFlight = InFlight{};
    m_state = State::Idle; // force a stateChanged for the new attempt
    m_stopReason = StopReason::None;
    m_stoppedEmitted = false;
    m_grantId = grantId;
    m_sessionId.clear();
    m_leaseMonoDeadlineMs = -1;
    m_leaseWallDeadlineSecs = 0;
    m_offerMonoDeadlineMs = -1;
    m_offerWallDeadlineSecs = 0;
    // A new run can never inherit a previous run's activation: the server
    // scopes activation to one session row and one ticket, and a stale
    // "confirmed" flag is a fabricated success.
    m_activationSubmitted = false;
    m_activationInFlight = false;
    m_localActivationRecorded = false;
    m_activationConfirmed = false;
    m_activationEmitted = false;
    m_activationBinding.clear();
    m_activationSigner = ActivationSigner();
}

void KanadeSession::start(const QString& grantId)
{
    if (isLive()) {
        qWarning("KanadeSession: start() ignored while an attempt is running");
        return;
    }

    resetForStart(grantId);

    // Fail closed on any unusable configuration; nothing is sent.
    if (!configurationComplete()
        || !ManagedEndpointContext::isCanonicalUuid4(grantId)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    setState(State::Creating);
    m_watchdogTimer.start(m_timing.watchdogIntervalMs);
    sendCreate();
}

void KanadeSession::cancel()
{
    if (!isLive() || m_state == State::Closing) {
        // Not running, or cleanup is already underway: exactly one DELETE.
        return;
    }
    if (m_stopReason != StopReason::Logout) {
        m_stopReason = StopReason::UserCancelled;
    }
    ++m_generation;
    abortInFlight();
    stopTimers();
    // Local gate closes immediately; cleanup below never reopens it.
    m_leaseMonoDeadlineMs = -1;
    m_offerMonoDeadlineMs = -1;
    setState(State::Closing);
    if (!m_sessionId.isEmpty()) {
        // Only an id from this attempt's own create reply is ever addressed.
        sendClose();
        return;
    }
    // The create outcome is unknown, so no server-side session can be
    // attributed to this attempt.  Nothing is adopted and nothing is deleted;
    // an orphaned offer expires on its own within the offer TTL and the local
    // stop is already complete.
    finalizeClosed();
}

void KanadeSession::logout()
{
    if (!isLive()) {
        m_accessToken.clear();
        return;
    }
    // Set the reason BEFORE the stop so an immediate finalize reports Logout.
    m_stopReason = StopReason::Logout;
    if (m_state == State::Closing) {
        // Cleanup already underway: only the reason/token handling changes.
        return;
    }
    cancel();
}

quint64 KanadeSession::dispatch(const QByteArray& method, const QString& path,                                const QJsonObject& body, Purpose purpose)
{
    KanadeHttpRequest request;
    request.origin = m_origin;
    request.method = method;
    request.path = path;
    request.body = body;
    request.bearerToken = m_accessToken.toUtf8();
    request.timeoutMs = m_timing.requestTimeoutMs;

    const quint64 tag = m_transport->send(request);
    m_inFlight.active = true;
    m_inFlight.tag = tag;
    m_inFlight.purpose = purpose;
    m_inFlight.generation = m_generation;
    m_inFlight.startMonoMs = monotonicNowMs();
    return tag;
}

void KanadeSession::sendCreate()
{
    QJsonObject body;
    body.insert(QStringLiteral("grant_id"), m_grantId);
    // route_class is intentionally omitted: it is diagnostic-only server-side.
    dispatch("POST", kSessionsPath, body, Purpose::Create);
}

void KanadeSession::sendDiagnoseCreate()
{
    dispatch("GET", kCurrentPath, QJsonObject(), Purpose::DiagnoseCreate);
}

void KanadeSession::sendPoll()
{
    dispatch("GET", kSessionsPath + QLatin1Char('/') + m_sessionId,
             QJsonObject(), Purpose::Poll);
}

void KanadeSession::sendRenew()
{
    dispatch("POST", kSessionsPath + QLatin1Char('/') + m_sessionId
                 + QStringLiteral("/renew"),
             QJsonObject(), Purpose::Renew);
}

void KanadeSession::sendConfirmActivation()
{
    dispatch("GET", kCurrentPath, QJsonObject(), Purpose::ConfirmActivation);
}

void KanadeSession::sendClose()
{
    dispatch("DELETE", kSessionsPath + QLatin1Char('/') + m_sessionId,
             QJsonObject(), Purpose::Close);
}

void KanadeSession::handleFinished(quint64 tag, const KanadeHttpReply& reply)
{
    if (!m_inFlight.active || tag != m_inFlight.tag) {
        return; // unknown or already-aborted request: drop
    }
    if (m_inFlight.generation != m_generation) {
        m_inFlight = InFlight{}; // previous run generation: drop (no resurrection)
        return;
    }
    const InFlight flight = m_inFlight;
    m_inFlight = InFlight{};

    switch (flight.purpose) {
    case Purpose::Create:
        handleCreateReply(flight, reply);
        break;
    case Purpose::DiagnoseCreate:
        handleDiagnoseReply(flight, reply);
        break;
    case Purpose::Poll:
        handlePollReply(flight, reply);
        break;
    case Purpose::Renew:
        handleRenewReply(flight, reply);
        break;
    case Purpose::Ticket:
        handleTicketReply(flight, reply);
        break;
    case Purpose::Activate:
        handleActivationReply(flight, reply);
        break;
    case Purpose::ConfirmActivation:
        handleConfirmActivationReply(reply);
        break;
    case Purpose::Close:
        handleCloseReply(reply);
        break;
    case Purpose::None:
        break;
    }
}

bool KanadeSession::extractServerTime(const QJsonObject& root, qint64& out)
{
    const QJsonValue value = root.value(QStringLiteral("server_time"));
    if (!value.isDouble()) {
        return false;
    }
    out = static_cast<qint64>(value.toDouble());
    return out > 0;
}

QString KanadeSession::extractErrorCode(const QByteArray& body)
{
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        return QString();
    }
    const QJsonValue detail = doc.object().value(QStringLiteral("detail"));
    if (detail.isObject()) {
        const QJsonValue code = detail.toObject().value(QStringLiteral("code"));
        if (code.isString()) {
            return code.toString();
        }
    }
    return QString();
}

bool KanadeSession::parseSnapshot(const QJsonObject& object, Snapshot& out) const
{
    auto uuidField = [&object](const char* name, QString& target) {
        const QJsonValue value = object.value(QLatin1String(name));
        if (!value.isString()) {
            return false;
        }
        target = value.toString();
        return ManagedEndpointContext::isCanonicalUuid4(target);
    };
    if (!uuidField("id", out.id)
        || !uuidField("grant_id", out.grantId)
        || !uuidField("host_id", out.hostId)
        || !uuidField("host_installation_id", out.hostInstallationId)
        || !uuidField("client_installation_id", out.clientInstallationId)) {
        return false;
    }

    auto keyVersionField = [&object](const char* name, int& target) {
        const QJsonValue value = object.value(QLatin1String(name));
        if (!value.isDouble()) {
            return false;
        }
        const double number = value.toDouble();
        if (number < 1 || number > kKeyVersionMax) {
            return false;
        }
        const int version = static_cast<int>(number);
        if (static_cast<double>(version) != number) {
            return false;
        }
        target = version;
        return true;
    };
    if (!keyVersionField("host_key_version", out.hostKeyVersion)
        || !keyVersionField("client_key_version", out.clientKeyVersion)) {
        return false;
    }

    const QJsonValue state = object.value(QStringLiteral("state"));
    if (!state.isString()) {
        return false;
    }
    out.state = state.toString();
    if (out.state != QStringLiteral("offered") && out.state != QStringLiteral("active")
        && out.state != QStringLiteral("closed") && out.state != QStringLiteral("expired")) {
        return false;
    }

    auto intField = [&object](const char* name, qint64& target, bool allowNull) {
        const QJsonValue value = object.value(QLatin1String(name));
        if (value.isNull() || value.isUndefined()) {
            if (allowNull) {
                target = 0;
                return true;
            }
            return false;
        }
        if (!value.isDouble()) {
            return false;
        }
        target = static_cast<qint64>(value.toDouble());
        return true;
    };
    if (!intField("lease_until", out.leaseUntil, true)
        || !intField("offered_until", out.offeredUntil, false)
        || !intField("created_at", out.createdAt, false)) {
        return false;
    }

    const QJsonValue closedReason = object.value(QStringLiteral("closed_reason"));
    if (closedReason.isString()) {
        out.closedReason = closedReason.toString();
    } else if (!closedReason.isNull() && !closedReason.isUndefined()) {
        return false;
    }

    const QJsonValue isOpen = object.value(QStringLiteral("is_open"));
    if (!isOpen.isBool()) {
        return false;
    }
    out.isOpen = isOpen.toBool();
    return true;
}

bool KanadeSession::snapshotInExpectedScope(const Snapshot& snapshot) const
{
    return snapshot.grantId == m_grantId
        && snapshot.clientInstallationId == m_installationId
        && snapshot.hostId == m_target.hostId
        && snapshot.hostInstallationId == m_target.hostInstallationId
        && snapshot.hostKeyVersion == m_target.hostKeyVersion
        && snapshot.clientKeyVersion == m_target.clientKeyVersion;
}

bool KanadeSession::setLeaseFromServer(qint64 leaseUntil, qint64 serverTime,
                                       qint64 requestStartMonoMs, bool allowInitial)
{
    if (leaseUntil <= 0 || serverTime <= 0 || requestStartMonoMs < 0) {
        return false;
    }
    const qint64 serverWindow = leaseUntil - serverTime;
    // The server mints at most LEASE_TTL_SECONDS; a larger window was not
    // minted by this contract.  It is REFUSED, not clamped: clamping would
    // quietly grant a longer gate than the server ever promised.
    if (serverWindow <= 1 || serverWindow > kLeaseTtlCapSeconds) {
        return false;
    }
    // One second is subtracted for second-level quantization, so a lease that
    // is already effectively over can never be opened.
    const qint64 remainingMs = (serverWindow - 1) * 1000;
    // ABSOLUTE deadline anchored on OUR request-start instant: network and
    // scheduling delay eat into the lease instead of extending it, and nothing
    // is recomputed from a later "now".
    const qint64 candidateMono = requestStartMonoMs + remainingMs;
    const qint64 now = monotonicNowMs();

    if (m_leaseMonoDeadlineMs >= 0) {
        // An expired gate is never revived by a late or out-of-order reply.
        if (now >= m_leaseMonoDeadlineMs) {
            return false;
        }
        // A confirmation must STRICTLY advance the stored absolute deadline;
        // equal or lower (replay, delayed reply, clock confusion) leaves the
        // gate untouched.
        if (candidateMono <= m_leaseMonoDeadlineMs) {
            return false;
        }
    } else if (!allowInitial) {
        // Only the accepted-snapshot transition may establish the gate.  Reads,
        // a scoped recovery read or the peer's renewal can never create one.
        return false;
    }

    m_leaseMonoDeadlineMs = candidateMono;
    // Wall-clock floor: never later than the server's own lease_until, and
    // never later than now + the quantization-corrected remaining.  This makes
    // a wall-clock jump or a suspend/resume able to shorten only.
    const qint64 wallByRemaining = wallNowSecs() + (serverWindow - 1);
    m_leaseWallDeadlineSecs = qMin(leaseUntil, wallByRemaining);
    return true;
}

void KanadeSession::armOfferGate(qint64 offeredUntil, qint64 serverTime,
                                 qint64 requestStartMonoMs)
{
    const qint64 remaining = clampRemaining(offeredUntil - serverTime - 1, kOfferTtlCapSeconds);
    m_offerMonoDeadlineMs = requestStartMonoMs + remaining * 1000;
    m_offerWallDeadlineSecs = qMin(offeredUntil, wallNowSecs() + kOfferTtlCapSeconds);
}

bool KanadeSession::adoptCreatedSnapshot(const Snapshot& snapshot, qint64 serverTime,
                                         qint64 requestStartMonoMs)
{
    // Creation-age window: only the offer THIS attempt just created may be
    // adopted.  A same-grant session from a previous run is "unrelated" and
    // must never be resurrected.
    if (snapshot.createdAt > serverTime + kCreatedAtSkewSeconds
        || serverTime - snapshot.createdAt > kAdoptionWindowSeconds) {
        return false;
    }

    m_sessionId = snapshot.id;

    if (snapshot.state == QStringLiteral("active")) {
        if (snapshot.leaseUntil <= serverTime) {
            return false; // "active" with a dead lease is not adoptable
        }
        enterActive(snapshot, serverTime, requestStartMonoMs);
        return true;
    }

    // state == offered
    armOfferGate(snapshot.offeredUntil, serverTime, requestStartMonoMs);
    setState(State::Offering);
    m_offerPollTimer.start(m_timing.offerPollIntervalMs);
    // First look right away; the host may already have accepted.
    if (offerStillValid()) {
        sendPoll();
    } else {
        expireOfferLocally();
    }
    return true;
}

void KanadeSession::enterActive(const Snapshot& snapshot, qint64 serverTime,
                                qint64 requestStartMonoMs)
{
    // Only the accepted-snapshot transition may establish the gate.
    setLeaseFromServer(snapshot.leaseUntil, serverTime, requestStartMonoMs,
                       /*allowInitial=*/true);
    if (!hasValidLease()) {
        expireLeaseLocally();
        return;
    }
    m_offerPollTimer.stop();
    if (m_state == State::Active) {
        // Already active: a confirming read only moves the gate on a strictly
        // greater deadline (handled above).  No re-announcement.
        return;
    }
    setState(State::Active);
    m_renewTimer.start(m_timing.renewIntervalMs);
    // "Kanade lease active" only -- never a streaming-ready indication.
    emit authorized();
}

void KanadeSession::expireOfferLocally()
{
    closeTerminal(StopReason::OfferExpired);
}

void KanadeSession::expireLeaseLocally()
{
    failTerminal(StopReason::LeaseExpired);
}

void KanadeSession::onWatchdog()
{
    if (m_state == State::Offering && !offerStillValid()) {
        expireOfferLocally();
    } else if (m_state == State::Active && !hasValidLease()) {
        expireLeaseLocally();
    } else if (m_state == State::Active && m_localActivationRecorded && !m_inFlight.active) {
        // A one-sided receipt is normal while the host is activating. Poll the
        // scoped session without allowing read-only replies to renew our lease.
        sendConfirmActivation();
    }
}

void KanadeSession::handleCreateReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        // Ambiguous: the offer may or may not exist server-side.  Classify it
        // with one read-only diagnostic; the create itself is NEVER replayed.
        setState(State::Diagnosing);
        sendDiagnoseCreate();
        return;
    }

    if (reply.httpStatus != 201) {
        // Definitive refusal: the server processed and rejected the offer.
        const QString code = extractErrorCode(reply.body);
        if (reply.httpStatus == 401
            || (reply.httpStatus == 403 && code != QStringLiteral("grant_revoked"))) {
            failTerminal(StopReason::AuthFailed, code);
        } else if (code == QStringLiteral("grant_revoked")) {
            failTerminal(StopReason::GrantRevoked, code);
        } else if (code == QStringLiteral("session_already_open")) {
            failTerminal(StopReason::CreateConflict, code);
        } else {
            failTerminal(StopReason::ProtocolError, code);
        }
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    Snapshot snapshot;
    if (!doc.isObject()
        || !extractServerTime(doc.object(), serverTime)
        || !parseSnapshot(doc.object().value(QStringLiteral("session")).toObject(), snapshot)
        || !snapshotInExpectedScope(snapshot)
        || !snapshot.isOpen
        || (snapshot.state != QStringLiteral("offered")
            && snapshot.state != QStringLiteral("active"))) {
        // A 201 we cannot fully verify is treated as hostile/corrupt.  We do
        // not adopt it and we do not steer mutations from it; any orphaned
        // server-side offer dies on its own within the offer TTL.
        failTerminal(StopReason::ProtocolError);
        return;
    }

    if (!adoptCreatedSnapshot(snapshot, serverTime, flight.startMonoMs)) {
        failTerminal(StopReason::ProtocolError);
    }
}

void KanadeSession::handleDiagnoseReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    Q_UNUSED(flight);
    // This reply NEVER adopts a session and NEVER opens the lease gate.  It
    // only classifies why the create outcome is unknown.
    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        failTerminal(StopReason::CreateUnverified);
        return;
    }
    if (reply.httpStatus == 401 || reply.httpStatus == 403) {
        failTerminal(StopReason::AuthFailed, extractErrorCode(reply.body));
        return;
    }
    if (reply.httpStatus != 200) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    if (!doc.isObject() || !extractServerTime(doc.object(), serverTime)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    const QJsonValue sessionValue = doc.object().value(QStringLiteral("session"));
    if (sessionValue.isNull() || sessionValue.isUndefined()) {
        // Proven: the create never took effect.  Do NOT auto-retry here.
        failTerminal(StopReason::CreateNotApplied);
        return;
    }

    Snapshot snapshot;
    if (!parseSnapshot(sessionValue.toObject(), snapshot)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    if (snapshot.grantId != m_grantId
        || snapshot.clientInstallationId != m_installationId) {
        // Somebody else's / another grant's open session.  Never adopt it,
        // never close it; surface the conflict.
        failTerminal(StopReason::CreateConflict);
        return;
    }
    // Our own grant and installation, but the create reply was lost, so we
    // cannot prove this snapshot is the one our request produced.  Fail
    // closed: no adoption, no lease, no DELETE.  The server offer TTL ends it.
    failTerminal(StopReason::CreateUnverified);
}

void KanadeSession::handlePollReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        // Transient read failure: the offer deadline is the guard.  The next
        // scheduled poll retries the READ (reads are safe to repeat).
        return;
    }
    if (reply.httpStatus == 401 || reply.httpStatus == 403) {
        failTerminal(StopReason::AuthFailed, extractErrorCode(reply.body));
        return;
    }
    if (reply.httpStatus == 404) {
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (reply.httpStatus != 200) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    Snapshot snapshot;
    if (!doc.isObject()
        || !extractServerTime(doc.object(), serverTime)
        || !parseSnapshot(doc.object().value(QStringLiteral("session")).toObject(), snapshot)
        || snapshot.id != m_sessionId
        || !snapshotInExpectedScope(snapshot)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    if (snapshot.state == QStringLiteral("offered")) {
        // Still waiting.  The offer deadline fixed at adoption is NOT
        // extended from later reads.
        return;
    }
    if (snapshot.state == QStringLiteral("active")) {
        enterActive(snapshot, serverTime, flight.startMonoMs);
        // A read may report the peer's activation, but it never confirms OUR
        // side and never moves the lease gate beyond what enterActive allows.
        applyActivationObject(doc.object().value(QStringLiteral("activation")).toObject(),
                             m_sessionId);
        return;
    }
    if (snapshot.state == QStringLiteral("expired")) {
        closeTerminal(StopReason::OfferExpired);
        return;
    }
    closeTerminal(StopReason::ServerClosed);
}

void KanadeSession::handleRenewReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    if (m_state != State::Active) {
        return;
    }
    // A confirmation that arrives after our own last confirmed deadline is
    // stale by definition and must not resurrect the lease.
    if (!hasValidLease()) {
        expireLeaseLocally();
        return;
    }
    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        // Uncertain mutation: NOT replayed.  The previously confirmed
        // deadline remains the hard stop; the next scheduled renew (if the
        // gate is still open) is a fresh request, not a replay of this one.
        return;
    }

    const QString code = extractErrorCode(reply.body);
    if (reply.httpStatus == 401
        || (reply.httpStatus == 403 && code != QStringLiteral("grant_revoked"))) {
        failTerminal(StopReason::AuthFailed, code);
        return;
    }
    if (code == QStringLiteral("grant_revoked")) {
        // Confirmed revocation: stop locally at once, fail closed.
        failTerminal(StopReason::GrantRevoked, code);
        return;
    }
    if (code == QStringLiteral("lease_expired")) {
        failTerminal(StopReason::LeaseExpired, code);
        return;
    }
    if (code == QStringLiteral("session_expired") || code == QStringLiteral("offer_expired")) {
        closeTerminal(StopReason::SessionExpired);
        return;
    }
    if (code == QStringLiteral("session_closed")) {
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (reply.httpStatus != 200) {
        failTerminal(StopReason::ProtocolError, code);
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    Snapshot snapshot;
    if (!doc.isObject()
        || !extractServerTime(doc.object(), serverTime)
        || !parseSnapshot(doc.object().value(QStringLiteral("session")).toObject(), snapshot)
        || snapshot.id != m_sessionId
        || !snapshotInExpectedScope(snapshot)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    if (snapshot.state == QStringLiteral("closed")) {
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (snapshot.state != QStringLiteral("active")) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    // Non-advancing confirmations leave the current deadline untouched.  If
    // the gate is still open this is harmless; if it is not, stop.
    setLeaseFromServer(snapshot.leaseUntil, serverTime, flight.startMonoMs,
                       /*allowInitial=*/false);
    applyActivationObject(doc.object().value(QStringLiteral("activation")).toObject(),
                         m_sessionId);
    if (!hasValidLease()) {
        expireLeaseLocally();
    }
}

QByteArray KanadeSession::activationMessage(const QString& sessionId,
                                            const QString& role,
                                            const QString& clientInstallationId,
                                            const QString& hostInstallationId,
                                            int clientKeyVersion,
                                            int hostKeyVersion,
                                            const QString& ticketSha256Hex,
                                            const QString& channelBindingHex)
{
    if (!ManagedEndpointContext::isCanonicalUuid4(sessionId)
        || !ManagedEndpointContext::isCanonicalUuid4(clientInstallationId)
        || !ManagedEndpointContext::isCanonicalUuid4(hostInstallationId)) {
        return QByteArray();
    }
    if (role != QStringLiteral("host") && role != QStringLiteral("client")) {
        return QByteArray();
    }
    if (ticketSha256Hex.size() != 64 || channelBindingHex.size() != 64) {
        return QByteArray();
    }
    const auto isLowerHex = [](const QString& text) {
        for (const QChar c : text) {
            const ushort u = c.unicode();
            const bool ok = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f');
            if (!ok) {
                return false;
            }
        }
        return true;
    };
    if (!isLowerHex(ticketSha256Hex) || !isLowerHex(channelBindingHex)) {
        return QByteArray();
    }
    if (clientKeyVersion < 1 || hostKeyVersion < 1) {
        return QByteArray();
    }

    // Field set and sorted key order must match the server's canonical_json()
    // exactly; QJsonObject iterates sorted and toJson(Compact) is the same
    // compact spelling, so this document IS the signed bytes.
    QJsonObject document;
    document.insert(QStringLiteral("channel_binding"), channelBindingHex);
    document.insert(QStringLiteral("client_installation_id"), clientInstallationId);
    document.insert(QStringLiteral("client_key_version"), clientKeyVersion);
    document.insert(QStringLiteral("host_installation_id"), hostInstallationId);
    document.insert(QStringLiteral("host_key_version"), hostKeyVersion);
    document.insert(QStringLiteral("role"), role);
    document.insert(QStringLiteral("session_id"), sessionId);
    document.insert(QStringLiteral("ticket_sha256"), ticketSha256Hex);
    document.insert(QStringLiteral("version"), 1);
    return QByteArrayLiteral("kanade.session-activation.v1\n")
        + QJsonDocument(document).toJson(QJsonDocument::Compact);
}

bool KanadeSession::beginActivation(const QByteArray& channelBinding32, ActivationSigner signer)
{
    // One attempt per run, only on a live lease, never while another request
    // is in flight (the response must be attributable to this attempt alone).
    if (m_activationSubmitted || m_activationInFlight || m_state != State::Active) {
        return false;
    }
    if (m_inFlight.active || !hasValidLease() || !signer) {
        return false;
    }
    if (channelBinding32.size() != 32) {
        return false;
    }
    m_activationSubmitted = true;
    m_activationBinding = channelBinding32;
    m_activationSigner = std::move(signer);
    sendTicket();
    return true;
}

void KanadeSession::sendTicket()
{
    QJsonObject body;
    // The purpose field is reserved server-side and never used for scoping; it
    // is sent empty so no caller can steer the ticket's role.
    dispatch("POST", kSessionsPath + QLatin1Char('/') + m_sessionId
                 + QStringLiteral("/tickets"),
             body, Purpose::Ticket);
}

void KanadeSession::handleTicketReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    Q_UNUSED(flight);
    if (m_state != State::Active) {
        return;
    }
    if (m_activationInFlight) {
        return; // duplicate reply already handled
    }

    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        // AMBIGUOUS: a ticket may exist server-side, and tickets are NOT
        // replayed.  The attempt ends here; the offer/lease TTL is the bound.
        m_activationSubmitted = true;
        failTerminal(StopReason::ActivationFailed);
        return;
    }
    const QString code = extractErrorCode(reply.body);
    if (reply.httpStatus == 401
        || (reply.httpStatus == 403 && code != QStringLiteral("grant_revoked"))) {
        failTerminal(StopReason::AuthFailed, code);
        return;
    }
    if (code == QStringLiteral("grant_revoked")) {
        failTerminal(StopReason::GrantRevoked, code);
        return;
    }
    if (code == QStringLiteral("lease_expired")) {
        failTerminal(StopReason::LeaseExpired, code);
        return;
    }
    if (code == QStringLiteral("session_closed")) {
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (reply.httpStatus != 200 && reply.httpStatus != 201) {
        failTerminal(StopReason::ProtocolError, code);
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    if (!doc.isObject()) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    const QJsonObject root = doc.object();
    const QString ticket = root.value(QStringLiteral("ticket")).toString();
    const QString role = root.value(QStringLiteral("role")).toString();
    const QString ticketSession = root.value(QStringLiteral("session_id")).toString();
    const QJsonValue expiry = root.value(QStringLiteral("expires_at"));
    if (ticket.isEmpty() || ticket.size() > 256
        || role != QStringLiteral("client")
        // The ticket response ALWAYS names its session; a mismatch means the
        // reply belongs somewhere else and must never be signed here.
        || ticketSession != m_sessionId
        || !expiry.isDouble() || !(expiry.toDouble() > 0)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }

    // The signed message uses only authoritative values: this attempt's
    // session id, this installation's own role/key version, the configured
    // peer, and digests.  The ticket appears only as its SHA-256.
    const QByteArray wire =
        m_activationBinding.toBase64(QByteArray::Base64UrlEncoding
                                     | QByteArray::OmitTrailingEquals);
    if (wire.size() != 43) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    const QString ticketSha256 =
        QString::fromLatin1(QCryptographicHash::hash(ticket.toUtf8(), QCryptographicHash::Sha256)
                                .toHex());
    const QByteArray message =
        activationMessage(m_sessionId, QStringLiteral("client"), m_installationId,
                          m_target.hostInstallationId, m_target.clientKeyVersion,
                          m_target.hostKeyVersion, ticketSha256,
                          QString::fromLatin1(m_activationBinding.toHex()));
    if (message.isEmpty()) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    const QByteArray proof = m_activationSigner(ticket, message);
    // The signer captured the installation seed by value; drop it as soon as the
    // one proof it can produce exists, whether or not the result is usable.
    m_activationSigner = ActivationSigner();
    // The signer must return the canonical padded 64-byte spelling; anything
    // else is a local failure and is never sent.
    const QByteArray rawProof =
        QByteArray::fromBase64(proof, QByteArray::Base64Encoding
                                          | QByteArray::AbortOnBase64DecodingErrors);
    if (proof.size() != 88 || rawProof.size() != 64 || rawProof.toBase64() != proof) {
        failTerminal(StopReason::ActivationFailed);
        return;
    }

    m_activationInFlight = true;
    QJsonObject body;
    body.insert(QStringLiteral("version"), 1);
    body.insert(QStringLiteral("ticket"), ticket);
    body.insert(QStringLiteral("channel_binding"), QString::fromLatin1(wire));
    body.insert(QStringLiteral("proof"), QString::fromLatin1(proof));
    dispatch("POST", kSessionsPath + QLatin1Char('/') + m_sessionId
                 + QStringLiteral("/activate"),
             body, Purpose::Activate);
}

bool KanadeSession::applyActivationObject(const QJsonObject& activation, const QString& sessionId)
{
    // Only the common booleans are meaningful.  Anything else fails closed
    // without touching the lease gate: activation truth comes from the server
    // and never from a peer, a ticket or a local timer.
    if (activation.isEmpty() || sessionId.isEmpty() || sessionId != m_sessionId) {
        return false;
    }
    const QJsonValue hostValue = activation.value(QStringLiteral("host"));
    const QJsonValue clientValue = activation.value(QStringLiteral("client"));
    if (!hostValue.isObject() || !clientValue.isObject()) {
        return false;
    }
    const QJsonValue hostActivated = hostValue.toObject().value(QStringLiteral("activated"));
    const QJsonValue clientActivated = clientValue.toObject().value(QStringLiteral("activated"));
    const QJsonValue both = activation.value(QStringLiteral("both_activated"));
    if (!hostActivated.isBool() || !clientActivated.isBool() || !both.isBool()) {
        return false;
    }
    // The server's derived flag must agree with the per-side flags; a
    // contradiction is corrupt data, not a licence to guess.
    if (both.toBool() != (hostActivated.toBool() && clientActivated.toBool())) {
        return false;
    }
    if ((both.toBool() && (!m_activationSubmitted || !hasValidLease())) ||
        (m_activationConfirmed && !both.toBool())) {
        return false;
    }

    // This process is the `client` participant: only that side's flag may be
    // read as "our activation was recorded".
    m_localActivationRecorded = clientActivated.toBool();
    if (both.toBool()) {
        m_activationConfirmed = true;
        if (!m_activationEmitted) {
            m_activationEmitted = true;
            emit bothParticipantsActivated();
        }
    } else if (m_localActivationRecorded) {
        emit activationRecorded();
    }
    return true;
}

void KanadeSession::handleActivationReply(const InFlight& flight, const KanadeHttpReply& reply)
{
    m_activationInFlight = false;
    if (m_state != State::Active) {
        return; // stopped while the activation was in flight
    }

    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        // AMBIGUOUS: the activation may or may not have been recorded.  It is
        // never replayed.  The scoped recovery read is the only permitted
        // follow-up, and it cannot extend the lease gate.
        sendConfirmActivation();
        return;
    }

    const QString code = extractErrorCode(reply.body);
    if (reply.httpStatus == 401
        || (reply.httpStatus == 403 && code != QStringLiteral("grant_revoked"))) {
        failTerminal(StopReason::AuthFailed, code);
        return;
    }
    if (code == QStringLiteral("grant_revoked")) {
        failTerminal(StopReason::GrantRevoked, code);
        return;
    }
    if (code == QStringLiteral("lease_expired")) {
        failTerminal(StopReason::LeaseExpired, code);
        return;
    }
    if (code == QStringLiteral("session_closed") || code == QStringLiteral("session_expired")
        || code == QStringLiteral("activation_conflict")
        || code == QStringLiteral("activation_mismatch")
        || code == QStringLiteral("session_key_version_stale")) {
        // The server has closed the session; stop locally, no retry.
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (code == QStringLiteral("ticket_invalid")
        || code == QStringLiteral("activation_proof_invalid")
        || code == QStringLiteral("channel_binding_invalid")) {
        failTerminal(StopReason::ActivationFailed, code);
        return;
    }
    if (reply.httpStatus != 200) {
        failTerminal(StopReason::ProtocolError, code);
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    Snapshot snapshot;
    if (!doc.isObject() || !extractServerTime(doc.object(), serverTime)
        || !parseSnapshot(doc.object().value(QStringLiteral("session")).toObject(),
                          snapshot)
        || snapshot.id != m_sessionId || !snapshotInExpectedScope(snapshot)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    if (snapshot.state == QStringLiteral("closed")
        || snapshot.state == QStringLiteral("expired")) {
        closeTerminal(StopReason::ServerClosed);
        return;
    }
    if (!hasValidLease()) {
        expireLeaseLocally();
        return;
    }
    // Activation proves the handshake; it is NOT this end's lease renewal.
    Q_UNUSED(flight);
    if (snapshot.state != QStringLiteral("active") || snapshot.leaseUntil <= serverTime ||
        doc.object().value(QStringLiteral("role")).toString() != QStringLiteral("client") ||
        !applyActivationObject(doc.object().value(QStringLiteral("activation")).toObject(), m_sessionId) ||
        !m_localActivationRecorded) {
        failTerminal(StopReason::ProtocolError);
    }
}

void KanadeSession::handleConfirmActivationReply(const KanadeHttpReply& reply)
{
    // Read-only scoped recovery: it NEVER adopts a session, NEVER opens or
    // extends the lease gate, and NEVER emits authorized().
    if (reply.error != KanadeHttpReply::Error::None || reply.httpStatus >= 500) {
        if (!m_localActivationRecorded)
            failTerminal(StopReason::ActivationUnconfirmed);
        return;
    }
    if (reply.httpStatus == 401 || reply.httpStatus == 403) {
        failTerminal(StopReason::AuthFailed, extractErrorCode(reply.body));
        return;
    }
    if (reply.httpStatus != 200) {
        failTerminal(StopReason::ActivationUnconfirmed);
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(reply.body);
    qint64 serverTime = 0;
    if (!doc.isObject() || !extractServerTime(doc.object(), serverTime)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    const QJsonObject root = doc.object();
    const QJsonValue sessionValue = root.value(QStringLiteral("session"));
    if (sessionValue.isNull() || sessionValue.isUndefined()) {
        // No open session for this installation: the activation attempt is
        // abandoned, nothing is retried and nothing is deleted.
        failTerminal(StopReason::CreateNotApplied);
        return;
    }
    Snapshot snapshot;
    if (!parseSnapshot(sessionValue.toObject(), snapshot) || snapshot.id != m_sessionId
        || !snapshotInExpectedScope(snapshot)) {
        failTerminal(StopReason::ActivationUnconfirmed);
        return;
    }
    if (root.value(QStringLiteral("role")).toString() != QStringLiteral("client")) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    if (!hasValidLease()) {
        expireLeaseLocally();
        return;
    }
    if (snapshot.state != QStringLiteral("active") || snapshot.leaseUntil <= serverTime ||
        !applyActivationObject(root.value(QStringLiteral("activation")).toObject(), m_sessionId)) {
        failTerminal(StopReason::ProtocolError);
        return;
    }
    if (!m_localActivationRecorded || (m_activationEmitted && !m_activationConfirmed)) {
        failTerminal(StopReason::ActivationUnconfirmed);
    }
}

void KanadeSession::handleCloseReply(const KanadeHttpReply& reply)
{
    // Best effort only: the local outcome of an explicit cancel/logout never
    // depends on the DELETE result.  The DELETE is sent exactly once.
    Q_UNUSED(reply);
    finalizeClosed();
}

} // namespace Kanade
