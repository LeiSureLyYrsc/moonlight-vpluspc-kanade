#include "kanadecontroller.h"
#include "kanadeapi.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QMutex>
#include <QMutexLocker>
#include <QPointer>
#include <QRandomGenerator>
#include <QTimer>
#include <QUuid>
#include <QVariantMap>
#include <QtConcurrent/QtConcurrentRun>

#include <memory>

#include "kanadehttptransport.h"
#include "kanaderuntime.h"
#include "kanadesession.h"
#include "kanadesidecar.h"

#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
#include "managednativecontroller.h"
#include "streaming/session.h"
#endif

// ---------------------------------------------------------------------------
// Contract constants (verified read-only against Kanade @ 4353a153)
// ---------------------------------------------------------------------------

namespace {

// Result of the serialized identity preparation task (see prepareIdentity).
struct IdentityPrep {
    enum class Outcome {
        Loaded,  // an identity existed and is valid (may still be pending)
        Created, // none existed; a fresh pending key was generated + persisted
        Failed   // storage unsupported/corrupt/tampered/ACL-unprovable/write
    };
    Outcome outcome = Outcome::Failed;
    Kanade::InstallationIdentity identity;
};

// Pair-request poll cadence: the server TTL is 120 s, so a 2 s read is cheap
// and never hammers the control plane.
constexpr int kPairPollIntervalMs = 2000;
// Extra grace after the server-reported expiry before the local poll stops.
constexpr qint64 kPairExpiryGraceSeconds = 5;

const QString kLoginPath = QStringLiteral("/v1/auth/login");
const QString kMePath = QStringLiteral("/v1/auth/me");
const QString kInstallationChallengePath = QStringLiteral("/v1/installations/challenge");
const QString kInstallationsPath = QStringLiteral("/v1/installations");
const QString kDeviceChallengePath = QStringLiteral("/v1/auth/device-challenge");
const QString kDeviceTokenPath = QStringLiteral("/v1/auth/device-token");
const QString kDevicesPath = QStringLiteral("/v1/devices");
const QString kPairRequestsPath = QStringLiteral("/v1/pair-requests");
const QString kGrantsPath = QStringLiteral("/v1/grants/");

QString loginErrorForResult(const KanadeApi::Result& result)
{
    using ErrorKind = KanadeApi::ErrorKind;
    switch (result.kind) {
    case ErrorKind::None:
        return QString();
    case ErrorKind::InvalidOrigin:
        return QStringLiteral("insecure_origin");
    case ErrorKind::Network:
    case ErrorKind::Timeout:
        return QStringLiteral("network_error");
    case ErrorKind::Tls:
        return QStringLiteral("tls_error");
    case ErrorKind::Redirect:
        // A redirect is always a cross-origin move here (same-origin moves would
        // still be refused); it is never followed.
        return QStringLiteral("origin_mismatch");
    case ErrorKind::BodyTooLarge:
    case ErrorKind::ParseError:
        return QStringLiteral("protocol_error");
    case ErrorKind::Cancelled:
        return QStringLiteral("cancelled");
    case ErrorKind::HttpError:
        break;
    }

    // Fixed server-code allowlist.  Anything else is reported generically;
    // the raw code/body never reaches the UI or logs.
    static const QHash<QString, QString> kCodes = {
        {QStringLiteral("invalid_credentials"), QStringLiteral("invalid_credentials")},
        {QStringLiteral("too_many_attempts"), QStringLiteral("too_many_attempts")},
        {QStringLiteral("too_many_requests"), QStringLiteral("rate_limited")},
        {QStringLiteral("cooldown"), QStringLiteral("rate_limited")},
        {QStringLiteral("user_disabled"), QStringLiteral("user_disabled")},
        {QStringLiteral("token_expired"), QStringLiteral("session_expired")},
        {QStringLiteral("token_invalid"), QStringLiteral("unauthorized")},
        {QStringLiteral("token_missing"), QStringLiteral("unauthorized")},
        {QStringLiteral("installation_revoked"), QStringLiteral("unauthorized")},
        {QStringLiteral("device_required"), QStringLiteral("unauthorized")},
        {QStringLiteral("installation_not_found"), QStringLiteral("not_found")},
        {QStringLiteral("pair_unavailable"), QStringLiteral("pair_unavailable")},
        {QStringLiteral("request_conflict"), QStringLiteral("conflict")},
        {QStringLiteral("pair_denied"), QStringLiteral("conflict")},
        {QStringLiteral("not_found"), QStringLiteral("not_found")},
    };
    const auto it = kCodes.constFind(result.serverCode);
    if (it != kCodes.constEnd())
        return it.value();

    switch (result.httpStatus) {
    case 401:
        return QStringLiteral("unauthorized");
    case 403:
        return QStringLiteral("forbidden");
    case 404:
        return QStringLiteral("not_found");
    case 409:
        return QStringLiteral("conflict");
    case 422:
        return QStringLiteral("invalid_request");
    case 429:
        return QStringLiteral("rate_limited");
    default:
        break;
    }
    if (result.httpStatus >= 500)
        return QStringLiteral("server_error");
    return QStringLiteral("operation_failed");
}

bool isCanonicalUuidString(const QString& value)
{
    if (value.size() != 36)
        return false;
    for (int i = 0; i < 36; ++i) {
        const QChar c = value.at(i);
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != QLatin1Char('-'))
                return false;
        }
        else if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                   (c >= QLatin1Char('a') && c <= QLatin1Char('f')))) {
            return false;
        }
    }
    return true;
}

// Server-side installation views are JSON objects with id/role/public_key.
} // namespace

// ---------------------------------------------------------------------------
// Construction / teardown
// ---------------------------------------------------------------------------

KanadeController::KanadeController(QString approvedRoot, QObject* parent)
    : QObject(parent)
    , m_approvedRoot(std::move(approvedRoot))
{
#ifdef Q_OS_WIN
    // Non-Windows builds have no DPAPI storage, so the control plane is
    // reported unsupported instead of pretending to work with a plaintext
    // fallback.  On Windows the store is compiled in by default (opt-out with
    // KANADE_DISABLE_WIN32_IDENTITY for platforms/packaging that must not carry
    // it), so the support flag comes from the store itself rather than a
    // duplicated macro test: a build that opted out reports unsupported and
    // every storage call still fails closed.
    m_supported = Kanade::IdentityStore::platformSupported();
#else
    m_supported = false;
#endif
    m_pairPollTimer.setInterval(kPairPollIntervalMs);
    m_pairPollTimer.setSingleShot(true);
    connect(&m_pairPollTimer, &QTimer::timeout, this, &KanadeController::onPairPollTimeout);

    // One worker: every load/save/forget of the installation file is serialized
    // through it, so overlapping login generations can never interleave a
    // load->generate->save pair against the same scoped file.
    m_identityPool.setMaxThreadCount(1);
    m_identityPool.setExpiryTimeout(-1);

    m_store = std::make_shared<Kanade::IdentityStore>(
        m_supported ? identityRoot() : QString());
}

KanadeController::~KanadeController()
{
    // Worker tasks hold value copies only; in-flight completions are dropped by
    // destroying the API (KanadeApi's destructor never runs application code).
    //
    // Order: managed session, then sidecar, then transport, then (by member
    // declaration order) the KanadeApi those two borrow.  `deleteLater()` is
    // wrong here (the event loop may never run again), so the sidecar unique_ptr
    // is reset directly: its destructor stops the worker and reaps the child.
    m_onlineSession.reset();
    revokeNative(Kanade::NativeReason::Stopped);
    m_sidecar.reset();
    // Native workers can still own a captured controller and our mutex. Join
    // before member destruction, after the route and local lease are dead.
    m_identityPool.waitForDone();
    m_onlineTransport.reset();
    m_onlineSeed.fill('\0');
    m_onlineSeed.clear();
}

QString KanadeController::identityRoot() const
{
    if (!m_approvedRoot.isEmpty())
        return m_approvedRoot;
    // Approved D-drive tree for this workspace build (plan 3.4: "path limited
    // to the approved D-drive tree"; no C-drive staging, no roaming).
    // Product packaging must pass its own approved root to the constructor.
    return QStringLiteral("D:/Github/RemoteAPP/.cache/kanade-moonlight-qt/identity");
}

QString KanadeController::originString(const QUrl& origin)
{
    return origin.isValid() ? origin.toString() : QString();
}

QString KanadeController::origin() const
{
    return m_api ? originString(m_api->origin()) : QString();
}

void KanadeController::createApiIfNeeded()
{
    if (m_api)
        return;
    m_api = std::make_unique<KanadeApi>();
    connect(m_api.get(), &KanadeApi::authenticationLost, this, [this]() {
        // The refresh path failed closed inside KanadeApi: no usable
        // credentials remain.  End the session locally; never retry.
        endSession(/*remoteBestEffort=*/false);
        setErrorCode(QStringLiteral("unauthorized"));
    });
}

// ---------------------------------------------------------------------------
// Small state helpers
// ---------------------------------------------------------------------------

void KanadeController::setErrorCode(const QString& code)
{
    if (m_errorCode == code)
        return;
    m_errorCode = code;
    emit errorCodeChanged();
}

void KanadeController::setPairState(const QString& state)
{
    if (m_pairState == state)
        return;
    m_pairState = state;
    emit pairStateChanged();
}

void KanadeController::setDevices(QVariantList devices)
{
    m_devices = std::move(devices);
    emit devicesChanged();
}

bool KanadeController::isCurrent(quint64 generation, const QUrl& origin) const
{
    return generation == m_generation && m_api && m_api->origin() == origin;
}

void KanadeController::beginOp(quint64 generation)
{
    if (generation != m_generation)
        return;
    ++m_busy;
    emit stateChanged();
}

void KanadeController::endOp(quint64 generation)
{
    if (generation != m_generation)
        return; // stale operation: its budget no longer belongs to this run
    if (m_busy > 0)
        --m_busy;
    emit stateChanged();
}

// Ends the current session: every in-flight reply is invalidated FIRST, then
// local state is dropped.  Nothing can revive the old generation afterwards.
void KanadeController::endSession(bool remoteBestEffort)
{
    ++m_generation; // invalidates every outstanding callback
    m_busy = 0;
    stopPairPoll();
    m_pending = PendingPair();

    // Never leave a managed path running for an account that is going away.
    teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::Logout);
    m_onlineSeed.fill('\0');
    m_onlineSeed.clear();
    m_onlineClientKeyVersion = 0;
    m_onlineGrantId.clear();
    m_onlineHostId.clear();

    if (m_api) {
        m_api->abortAll();
        // Best-effort remote logout uses the credentials dropped just now and
        // cannot touch state belonging to a newer session.
        if (remoteBestEffort)
            m_api->logoutBestEffort();
    }

    m_authenticated = false;
    m_installationId.clear();
    m_userId.clear();
    setDevices(QVariantList());
    setPairState(QString());
    resetNativeBridge(QStringLiteral("unavailable"));
    emit stateChanged();
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

void KanadeController::login(const QString& serviceUrl, const QString& login,
                             const QString& password)
{
    // Emit BEFORE any validation: an invalid service URL or empty field would
    // otherwise skip the one thing that must happen before a password can ever
    // exist.  Idempotent at the receiver (sticky per-process flag).
    Q_EMIT sensitiveOperationStarted();
    m_dumpsSuppressed = true;

    if (!m_supported || login.isEmpty() || password.isEmpty())
        return;

    QUrl origin;
    if (!KanadeApi::normalizeOrigin(serviceUrl, origin)) {
        setErrorCode(QStringLiteral("insecure_origin"));
        return;
    }
    // kanadeidentity.h scopes DPAPI entropy by the canonical origin and rejects
    // IPv6 literals; refuse them here too instead of failing later with an
    // opaque storage error.
    if (origin.host().contains(QLatin1Char(':'))) {
        setErrorCode(QStringLiteral("insecure_origin"));
        return;
    }

    // Switching services (or accounts) ends the previous session first: no
    // token, device row or pending request crosses an origin or account change.
    endSession(/*remoteBestEffort=*/true);
    setErrorCode(QString());

    createApiIfNeeded();
    if (!m_api->setOrigin(origin)) {
        // Refused because usable credentials are still held: fail closed
        // rather than re-point them at another host.
        setErrorCode(QStringLiteral("origin_mismatch"));
        return;
    }

    const quint64 generation = m_generation;
    beginOp(generation);

    QJsonObject body;
    body.insert(QStringLiteral("login"), login);
    body.insert(QStringLiteral("password"), password);
    m_api->post(kLoginPath, body, /*authenticated=*/false,
                [this, generation, origin](const KanadeApi::Result& result) {
                    if (!isCurrent(generation, origin))
                        return; // stale origin/session: drop silently
                    if (result.kind != KanadeApi::ErrorKind::None) {
                        endOp(generation);
                        setErrorCode(loginErrorForResult(result));
                        return;
                    }
                    afterLogin(result.body, generation, origin);
                });
}

void KanadeController::afterLogin(const QJsonObject& tokenPair, quint64 generation,
                                  const QUrl& origin)
{
    if (!KanadeApi::tokenPairIsUsable(tokenPair)) {
        endOp(generation);
        setErrorCode(QStringLiteral("protocol_error"));
        return;
    }
    m_api->adoptTokenPair(tokenPair);
    // Never trust the login payload for identity: confirm through /auth/me.
    verifyMe(generation, origin);
}

void KanadeController::verifyMe(quint64 generation, const QUrl& origin)
{
    m_api->get(kMePath, [this, generation, origin](const KanadeApi::Result& result) {
        if (!isCurrent(generation, origin))
            return;
        if (result.kind != KanadeApi::ErrorKind::None) {
            endOp(generation);
            const QString code = loginErrorForResult(result);
            if (code == QStringLiteral("unauthorized")
                || code == QStringLiteral("session_expired")) {
                endSession(/*remoteBestEffort=*/false);
            }
            setErrorCode(code);
            return;
        }

        const QJsonObject user = result.body.value(QStringLiteral("user")).toObject();
        const QString userId = user.value(QStringLiteral("id")).toString();
        if (!isCanonicalUuidString(userId)) {
            endOp(generation);
            setErrorCode(QStringLiteral("protocol_error"));
            return;
        }

        const QJsonValue installationValue = result.body.value(QStringLiteral("installation"));
        if (installationValue.isObject()) {
            // Device-bound token: it must really belong to the key we hold.
            const QJsonObject installation = installationValue.toObject();
            const QString installationId = installation.value(QStringLiteral("id")).toString();
            const QString role = installation.value(QStringLiteral("role")).toString();
            if (!isCanonicalUuidString(installationId)
                || role != QStringLiteral("client")
                || m_installationId.isEmpty() || installationId != m_installationId) {
                // A device token for another installation must never be used.
                endSession(/*remoteBestEffort=*/true);
                setErrorCode(QStringLiteral("unauthorized"));
                return;
            }
            m_userId = userId;
            m_authenticated = true;
            emit stateChanged();
            // loadDevices owns the remaining busy budget for this operation.
            loadDevices(generation, origin);
            return;
        }

        // Account token (installation == null): it authenticates the user only.
        // The device step comes next; keep the busy budget across it.
        m_userId = userId;
        prepareIdentity(generation, origin);
    });
}

void KanadeController::prepareIdentity(quint64 generation, const QUrl& origin)
{
    if (!m_store) {
        endOp(generation);
        setErrorCode(QStringLiteral("identity_storage_failed"));
        return;
    }

    // One atomic worker task: load, and only when the store truthfully reports
    // "nothing stored", generate + persist the pending key in the SAME task.
    // Splitting load and save into two pool jobs would let a second login
    // generation observe NotFound before the first write lands, mint a second
    // key, and overwrite the enrolled one.  The single-thread pool plus this
    // single task gives load->generate->save atomicity per (origin, user).
    auto store = m_store;
    const QString userId = m_userId;
    auto* watcher = new QFutureWatcher<IdentityPrep>(this);
    connect(watcher, &QFutureWatcher<IdentityPrep>::finished, this,
            [this, watcher, generation, origin]() {
                const IdentityPrep prep = watcher->result();
                watcher->deleteLater();
                if (!isCurrent(generation, origin))
                    return; // stale generation: its key is simply left sealed

                switch (prep.outcome) {
                case IdentityPrep::Outcome::Loaded:
                    m_installationId = prep.identity.installationId;
                    m_onlineSeed = prep.identity.privateKey;
                    m_onlineClientKeyVersion = prep.identity.keyVersion;
                    if (!prep.identity.installationId.isEmpty())
                        beginDeviceLogin(generation, origin, prep.identity);
                    else
                        beginEnrollment(generation, origin, prep.identity);
                    return;
                case IdentityPrep::Outcome::Created:
                    m_onlineSeed = prep.identity.privateKey;
                    m_onlineClientKeyVersion = prep.identity.keyVersion;
                    beginEnrollment(generation, origin, prep.identity);
                    return;
                case IdentityPrep::Outcome::Failed:
                default:
                    // Corrupt, tampered, reparse-point, unprovable ACL or a
                    // failed write: fail closed.  Never mint an ephemeral key.
                    endOp(generation);
                    setErrorCode(QStringLiteral("identity_storage_failed"));
                    return;
                }
            });
    watcher->setFuture(QtConcurrent::run(&m_identityPool, [store, origin, userId]() {
        IdentityPrep prep;
        Kanade::InstallationIdentity identity;
        const auto loaded = store->loadResult(origin, userId, identity);
        switch (loaded) {
        case Kanade::IdentityStore::LoadResult::Ok:
            prep.outcome = IdentityPrep::Outcome::Loaded;
            prep.identity = identity;
            return prep;
        case Kanade::IdentityStore::LoadResult::NotFound:
            break;
        case Kanade::IdentityStore::LoadResult::Unsupported:
        case Kanade::IdentityStore::LoadResult::Error:
        default:
            prep.outcome = IdentityPrep::Outcome::Failed;
            return prep;
        }

        identity = Kanade::generateIdentity();
        if (identity.privateKey.isEmpty() || identity.publicKey.isEmpty()) {
            prep.outcome = IdentityPrep::Outcome::Failed;
            return prep;
        }
        // Persist the PENDING key BEFORE any network call: a lost enrollment
        // response is then retried with this same key, never a second one.
        if (!store->save(origin, userId, identity)) {
            prep.outcome = IdentityPrep::Outcome::Failed;
            return prep;
        }
        prep.outcome = IdentityPrep::Outcome::Created;
        prep.identity = identity;
        return prep;
    }));
}

void KanadeController::beginEnrollment(quint64 generation, const QUrl& origin,
                                       const Kanade::InstallationIdentity& identity)
{
    QJsonObject body;
    body.insert(QStringLiteral("role"), QStringLiteral("client"));
    body.insert(QStringLiteral("public_key"), QString::fromLatin1(identity.publicKey));
    body.insert(QStringLiteral("key_version"), identity.keyVersion);
    // No label: the client does not use one, and the canonical enrollment
    // message always carries "label":null (kanadeidentity.cpp).

    m_api->post(kInstallationChallengePath, body, /*authenticated=*/true,
                [this, generation, origin, identity](const KanadeApi::Result& result) {
                    if (!isCurrent(generation, origin))
                        return;
                    if (result.kind != KanadeApi::ErrorKind::None) {
                        endOp(generation);
                        setErrorCode(loginErrorForResult(result));
                        return;
                    }

                    // Signing (and the byte-exact canonical rebuild) must not
                    // run on the UI thread.
                    const QString userId = m_userId;
                    const QJsonObject challenge = result.body;
                    auto* watcher = new QFutureWatcher<QByteArray>(this);
                    connect(watcher, &QFutureWatcher<QByteArray>::finished, this,
                            [this, watcher, generation, origin, identity, challenge,
                             userId]() {
                                const QByteArray proof = watcher->result();
                                watcher->deleteLater();
                                if (!isCurrent(generation, origin))
                                    return;
                                if (proof.isEmpty()) {
                                    // Canonical rebuild mismatch / role echo /
                                    // key mismatch / crypto failure: fail closed.
                                    endOp(generation);
                                    setErrorCode(QStringLiteral("protocol_error"));
                                    return;
                                }

                                QJsonObject create;
                                create.insert(QStringLiteral("challenge_id"),
                                              challenge.value(QStringLiteral("challenge_id")));
                                create.insert(QStringLiteral("proof"),
                                              QString::fromLatin1(proof));
                                m_api->post(kInstallationsPath, create,
                                            /*authenticated=*/true,
                                            [this, generation, origin, identity](
                                                const KanadeApi::Result& r) {
                                                if (!isCurrent(generation, origin))
                                                    return;
                                                if (r.kind != KanadeApi::ErrorKind::None) {
                                                    endOp(generation);
                                                    setErrorCode(loginErrorForResult(r));
                                                    return;
                                                }

                                                const QJsonObject installation =
                                                    r.body.value(QStringLiteral("installation"))
                                                        .toObject();
                                                const QString installationId =
                                                    installation.value(QStringLiteral("id"))
                                                        .toString();
                                                if (!isCanonicalUuidString(installationId)
                                                    || installation.value(QStringLiteral("role"))
                                                           .toString()
                                                        != QStringLiteral("client")) {
                                                    endOp(generation);
                                                    setErrorCode(QStringLiteral("protocol_error"));
                                                    return;
                                                }

                                                Kanade::InstallationIdentity enrolled = identity;
                                                enrolled.installationId = installationId;
                                                m_installationId = installationId;

                                                // Persist the assigned id before
                                                // using any credential.
                                                auto saveStore = m_store;
                                                const QString userId = m_userId;
                                                auto* saveWatcher =
                                                    new QFutureWatcher<bool>(this);
                                                connect(saveWatcher,
                                                        &QFutureWatcher<bool>::finished, this,
                                                        [this, saveWatcher, generation,
                                                         origin, enrolled, userId,
                                                         r]() {
                                                            const bool saved =
                                                                saveWatcher->result();
                                                            saveWatcher->deleteLater();
                                                            if (!isCurrent(generation, origin))
                                                                return;
                                                            if (!saved) {
                                                                endOp(generation);
                                                                setErrorCode(QStringLiteral(
                                                                    "identity_storage_failed"));
                                                                return;
                                                            }
                                                            const QJsonValue tokens =
                                                                r.body.value(
                                                                    QStringLiteral("tokens"));
                                                            if (tokens.isObject()) {
                                                                adoptDeviceTokens(
                                                                    tokens.toObject(),
                                                                    generation, origin,
                                                                    enrolled);
                                                            }
                                                            else {
                                                                // created:false /
                                                                // tokens:null:
                                                                // idempotent
                                                                // recovery via
                                                                // device login.
                                                                beginDeviceLogin(
                                                                    generation, origin,
                                                                    enrolled);
                                                            }
                                                        });
                                                saveWatcher->setFuture(QtConcurrent::run(
                                                    &m_identityPool,
                                                    [saveStore, origin, userId, enrolled]() {
                                                        return saveStore->save(origin, userId,
                                                                               enrolled);
                                                    }));
                                            });
                            });
                    watcher->setFuture(QtConcurrent::run(
                        &m_identityPool, [origin, userId, identity, challenge]() {
                            return Kanade::signRegistration(origin, userId, identity, challenge);
                        }));
                });
}

void KanadeController::beginDeviceLogin(quint64 generation, const QUrl& origin,
                                        const Kanade::InstallationIdentity& identity)
{
    QJsonObject body;
    body.insert(QStringLiteral("installation_id"), identity.installationId);

    // Unauthenticated by contract: possession of the installation key is the
    // credential (auth.py device_challenge/device_token).
    m_api->post(kDeviceChallengePath, body, /*authenticated=*/false,
                [this, generation, origin, identity](const KanadeApi::Result& result) {
                    if (!isCurrent(generation, origin))
                        return;
                    if (result.kind != KanadeApi::ErrorKind::None) {
                        endOp(generation);
                        setErrorCode(loginErrorForResult(result));
                        return;
                    }

                    const QString userId = m_userId;
                    const QJsonObject challenge = result.body;
                    auto* watcher = new QFutureWatcher<QByteArray>(this);
                    connect(watcher, &QFutureWatcher<QByteArray>::finished, this,
                            [this, watcher, generation, origin, identity, challenge,
                             userId]() {
                                const QByteArray proof = watcher->result();
                                watcher->deleteLater();
                                if (!isCurrent(generation, origin))
                                    return;
                                if (proof.isEmpty()) {
                                    endOp(generation);
                                    setErrorCode(QStringLiteral("protocol_error"));
                                    return;
                                }

                                QJsonObject tokenBody;
                                tokenBody.insert(QStringLiteral("challenge_id"),
                                                 challenge.value(QStringLiteral("challenge_id")));
                                tokenBody.insert(QStringLiteral("proof"),
                                                 QString::fromLatin1(proof));
                                m_api->post(kDeviceTokenPath, tokenBody,
                                            /*authenticated=*/false,
                                            [this, generation, origin, identity](
                                                const KanadeApi::Result& r) {
                                                if (!isCurrent(generation, origin))
                                                    return;
                                                if (r.kind != KanadeApi::ErrorKind::None) {
                                                    endOp(generation);
                                                    setErrorCode(loginErrorForResult(r));
                                                    return;
                                                }
                                                adoptDeviceTokens(r.body, generation, origin,
                                                                  identity);
                                            });
                            });
                    watcher->setFuture(QtConcurrent::run(
                        &m_identityPool, [origin, userId, identity, challenge]() {
                            return Kanade::signDeviceToken(origin, userId, identity, challenge);
                        }));
                });
}

void KanadeController::adoptDeviceTokens(const QJsonObject& tokenPair, quint64 generation,
                                         const QUrl& origin,
                                         const Kanade::InstallationIdentity& identity)
{
    if (!KanadeApi::tokenPairIsUsable(tokenPair)) {
        endOp(generation);
        setErrorCode(QStringLiteral("protocol_error"));
        return;
    }

    m_installationId = identity.installationId;
    m_onlineSeed = identity.privateKey;
    m_onlineClientKeyVersion = identity.keyVersion;
    // The account token family is no longer needed: revoke it best-effort
    // BEFORE adopting the device credential (the request uses a snapshot, so it
    // cannot affect the new tokens).
    m_api->logoutBestEffort();
    m_api->adoptTokenPair(tokenPair);

    // Final gate: the device token must resolve to this very installation.
    verifyMe(generation, origin);
}

void KanadeController::refreshDevices()
{
    if (!m_supported || !m_authenticated || !m_api)
        return;
    if (m_busy > 0)
        return; // one operation at a time from the UI
    setErrorCode(QString());
    const quint64 generation = m_generation;
    beginOp(generation);
    loadDevices(generation, m_api->origin());
}

void KanadeController::loadDevices(quint64 generation, const QUrl& origin)
{
    if (!m_api || !isCurrent(generation, origin)) {
        endOp(generation); // release the caller's budget; nothing will run
        return;
    }

    m_api->get(kDevicesPath, [this, generation, origin](const KanadeApi::Result& result) {
        if (!isCurrent(generation, origin))
            return;
        if (result.kind != KanadeApi::ErrorKind::None) {
            endOp(generation);
            const QString code = loginErrorForResult(result);
            if (code == QStringLiteral("unauthorized")
                || code == QStringLiteral("session_expired")) {
                endSession(/*remoteBestEffort=*/false);
            }
            setErrorCode(code);
            return;
        }

        const QString currentInstallation =
            result.body.value(QStringLiteral("current_installation_id")).toString();
        if (!isCanonicalUuidString(currentInstallation)
            || (!m_installationId.isEmpty() && currentInstallation != m_installationId)) {
            // The snapshot is not for the installation we authenticated as.
            endSession(/*remoteBestEffort=*/true);
            setErrorCode(QStringLiteral("protocol_error"));
            return;
        }

        QVariantList devices;
        const QJsonArray rows = result.body.value(QStringLiteral("devices")).toArray();
        for (const QJsonValue& value : rows) {
            const QJsonObject row = value.toObject();
            const QString grantId = row.value(QStringLiteral("grant_id")).toString();
            const QString clientInstallation =
                row.value(QStringLiteral("client_installation_id")).toString();
            if (!isCanonicalUuidString(grantId)
                || clientInstallation != currentInstallation) {
                continue; // never surface another installation's authorization
            }

            QString name = row.value(QStringLiteral("host_display_name")).toString();
            if (name.isEmpty())
                name = row.value(QStringLiteral("host_id")).toString();

            QVariantMap device;
            device.insert(QStringLiteral("grantId"), grantId);
            device.insert(QStringLiteral("hostId"),
                          row.value(QStringLiteral("host_id")).toString());
            device.insert(QStringLiteral("name"), name);
            device.insert(QStringLiteral("connectionState"),
                          row.value(QStringLiteral("connection_state")).toString());
            // Kanade cannot observe Sunshine certificate trust; the contract
            // always says "unknown" and the UI must show it as such.
            device.insert(QStringLiteral("nativePairing"),
                          row.value(QStringLiteral("native_pairing")).toString());
            devices.append(device);
        }

        endOp(generation);
        setDevices(devices);
    });
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

void KanadeController::addDevice(const QString& deviceCode, const QString& method,
                                 const QString& password)
{
    if (!m_supported || !m_authenticated || !m_api)
        return;
    const QString code = deviceCode.trimmed();
    if (code.isEmpty() || (method != QStringLiteral("password")
                           && method != QStringLiteral("confirm"))) {
        setErrorCode(QStringLiteral("invalid_request"));
        return;
    }
    if (method == QStringLiteral("password") && password.isEmpty()) {
        setErrorCode(QStringLiteral("invalid_request"));
        return;
    }

    const quint64 generation = m_generation;
    const QUrl origin = m_api->origin();

    // Idempotency key lifecycle (Kanade replays a stored outcome WITHOUT
    // re-running the password check, so this matters):
    //   * Same code+method: reuse the key, so a retry after an AMBIGUOUS
    //     outcome (no response / network drop) is an idempotent replay and
    //     cannot mint a second request.
    //   * A DIFFERENT code or method is a new request and gets a new key.
    //   * A definitive server rejection retires the key (see the completion
    //     below) so the user can retry with the corrected password as a fresh
    //     request instead of replaying the rejected one.
    if (m_pending.idempotencyKey.isEmpty() || m_pending.code != code
        || m_pending.method != method) {
        m_pending.idempotencyKey =
            QUuid::createUuid().toString(QUuid::WithoutBraces);
    }
    m_pending.code = code;
    m_pending.method = method;

    setErrorCode(QString());
    beginOp(generation);

    QJsonObject body;
    body.insert(QStringLiteral("device_code"), code);
    body.insert(QStringLiteral("method"), method);
    if (method == QStringLiteral("password"))
        body.insert(QStringLiteral("password"), password);
    body.insert(QStringLiteral("idempotency_key"), m_pending.idempotencyKey);

    m_api->post(kPairRequestsPath, body, /*authenticated=*/true,
                [this, generation, origin](const KanadeApi::Result& result) {
                    if (!isCurrent(generation, origin))
                        return;
                    if (result.kind != KanadeApi::ErrorKind::None) {
                        endOp(generation);
                        const QString failure = loginErrorForResult(result);
                        // Retire the key only on a definitive answer (retrying
                        // with a corrected password must be a new request).  An
                        // ambiguous failure keeps it so the retry replays.
                        if (result.kind == KanadeApi::ErrorKind::HttpError
                            || result.kind == KanadeApi::ErrorKind::ParseError
                            || result.kind == KanadeApi::ErrorKind::BodyTooLarge) {
                            m_pending.idempotencyKey.clear();
                        }
                        setErrorCode(failure);
                        return;
                    }
                    endOp(generation);
                    handlePairSnapshot(result.body, generation, origin);
                });
}

void KanadeController::handlePairSnapshot(const QJsonObject& snapshot, quint64 generation,
                                          const QUrl& origin)
{
    if (!isCurrent(generation, origin))
        return;

    const QString requestId = snapshot.value(QStringLiteral("id")).toString();
    const QString state = snapshot.value(QStringLiteral("state")).toString();
    if (!isCanonicalUuidString(requestId) || state.isEmpty())
        return;

    // A late snapshot for a different request is stale: ignore it rather than
    // overwriting the current attempt.
    if (!m_pending.requestId.isEmpty() && requestId != m_pending.requestId)
        return;

    m_pending.requestId = requestId;
    m_pending.expiresAt =
        qint64(snapshot.value(QStringLiteral("expires_at")).toDouble());

    if (state == QStringLiteral("pending")) {
        setPairState(state);
        // Keep observing; onPairPollTimeout() itself defers while busy, so a
        // single timer is enough and no poll is ever lost.
        if (!m_pairPollTimer.isActive())
            m_pairPollTimer.start();
        return;
    }

    // Terminal for this attempt: pending/approved/denied/expired/cancelled.
    stopPairPoll();
    m_pending = PendingPair();
    setPairState(state);

    if (state == QStringLiteral("approved")) {
        // Either the password path completed immediately or a host approved
        // after a cancel attempt: in both cases the grant now exists.
        setErrorCode(QString());
        const quint64 refreshGeneration = m_generation;
        beginOp(refreshGeneration);
        loadDevices(refreshGeneration, origin);
    }
}

void KanadeController::onPairPollTimeout()
{
    if (!m_authenticated || !m_api || m_pending.requestId.isEmpty())
        return;
    if (m_busy > 0) {
        m_pairPollTimer.start(); // try again shortly; still a read-only poll
        return;
    }

    // Local expiry guard: stop reading once the server TTL plus grace passed.
    // The server snapshot remains authoritative for the final state; this only
    // bounds our polling.
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (m_pending.expiresAt > 0 && now > m_pending.expiresAt + kPairExpiryGraceSeconds) {
        stopPairPoll();
        setPairState(QStringLiteral("expired"));
        m_pending = PendingPair();
        return;
    }

    const quint64 generation = m_generation;
    const QUrl origin = m_api->origin();
    beginOp(generation);
    m_api->get(kPairRequestsPath + QLatin1Char('/') + m_pending.requestId,
               [this, generation, origin](const KanadeApi::Result& result) {
                   if (!isCurrent(generation, origin))
                       return;
                   if (result.kind != KanadeApi::ErrorKind::None) {
                       endOp(generation);
                       const QString code = loginErrorForResult(result);
                       if (code == QStringLiteral("unauthorized")
                           || code == QStringLiteral("session_expired")) {
                           endSession(/*remoteBestEffort=*/false);
                       }
                       setErrorCode(code);
                       if (code == QStringLiteral("not_found")) {
                           // The request vanished server side; stop pretending
                           // it is pending.
                           stopPairPoll();
                           m_pending = PendingPair();
                           setPairState(QStringLiteral("expired"));
                       }
                       else if (code == QStringLiteral("network_error")) {
                           // Read-only retry is safe; try again shortly.
                           m_pairPollTimer.start();
                       }
                       return;
                   }
                   endOp(generation);
                   handlePairSnapshot(result.body, generation, origin);
               });
}

void KanadeController::stopPairPoll()
{
    m_pairPollTimer.stop();
}

void KanadeController::cancelPair()
{
    if (!m_supported || !m_authenticated || !m_api || m_pending.requestId.isEmpty())
        return;

    const quint64 generation = m_generation;
    const QUrl origin = m_api->origin();
    setErrorCode(QString());
    beginOp(generation);
    m_pairPollTimer.stop();

    m_api->post(kPairRequestsPath + QLatin1Char('/') + m_pending.requestId
                    + QStringLiteral("/cancel"),
                QJsonObject(), /*authenticated=*/true,
                [this, generation, origin](const KanadeApi::Result& result) {
                    if (!isCurrent(generation, origin))
                        return;
                    endOp(generation);

                    if (result.kind == KanadeApi::ErrorKind::None) {
                        handlePairSnapshot(result.body, generation, origin);
                        return;
                    }

                    const QString code = loginErrorForResult(result);
                    if (code == QStringLiteral("conflict")) {
                        // Already decided (e.g. approved) despite our cancel:
                        // read the authoritative snapshot and report it.  The
                        // cancel is never claimed to have succeeded.
                        const quint64 readGeneration = m_generation;
                        m_api->get(kPairRequestsPath + QLatin1Char('/')
                                       + m_pending.requestId,
                                   [this, readGeneration, origin](
                                       const KanadeApi::Result& read) {
                                       if (!isCurrent(readGeneration, origin))
                                           return;
                                       if (read.kind == KanadeApi::ErrorKind::None) {
                                           handlePairSnapshot(read.body, readGeneration,
                                                              origin);
                                       }
                                       else {
                                           setErrorCode(loginErrorForResult(read));
                                       }
                                   });
                        return;
                    }

                    setErrorCode(code);
                    if (code == QStringLiteral("network_error"))
                        m_pairPollTimer.start(); // still pending; keep observing
                });
}

void KanadeController::removeGrant(const QString& grantId)
{
    if (!m_supported || !m_authenticated || !m_api || !isCanonicalUuidString(grantId))
        return;

    const quint64 generation = m_generation;
    const QUrl origin = m_api->origin();
    setErrorCode(QString());
    beginOp(generation);

    m_api->del(kGrantsPath + grantId, [this, generation, origin](const KanadeApi::Result& result) {
        if (!isCurrent(generation, origin))
            return;
        if (result.kind != KanadeApi::ErrorKind::None) {
            endOp(generation);
            const QString code = loginErrorForResult(result);
            setErrorCode(code);
            if (code == QStringLiteral("unauthorized")
                || code == QStringLiteral("session_expired")) {
                endSession(/*remoteBestEffort=*/false);
            }
            return;
        }
        endOp(generation);
        // The server snapshot is authoritative; re-read the device list rather
        // than mutating it locally.
        const quint64 refreshGeneration = m_generation;
        beginOp(refreshGeneration);
        loadDevices(refreshGeneration, origin);
    });
}

// ---------------------------------------------------------------------------
// Sign-out / forget
// ---------------------------------------------------------------------------

void KanadeController::logout()
{
    if (!m_supported)
        return;
    endSession(/*remoteBestEffort=*/true);
    setErrorCode(QString());
}

void KanadeController::forgetInstallation()
{
    if (!m_supported || !m_api || !m_store)
        return;

    const QUrl origin = m_api->origin();
    const QString userId = m_userId;
    const QString installationId = m_installationId;

    endSession(/*remoteBestEffort=*/true);

    if (!origin.isValid() || userId.isEmpty() || installationId.isEmpty()) {
        // Nothing scoped to delete: the session is already gone locally.
        setErrorCode(QString());
        emit stateChanged();
        return;
    }

    // File deletion runs on the serialized identity worker: it must not block
    // the UI thread, and it must not interleave with a simultaneous load/save.
    const quint64 forgetGeneration = ++m_generation;
    m_busy = 0;
    emit stateChanged();

    auto store = m_store;
    auto* watcher = new QFutureWatcher<bool>(this);
    connect(watcher, &QFutureWatcher<bool>::finished, this,
            [this, watcher, forgetGeneration]() {
                const bool forgotten = watcher->result();
                watcher->deleteLater();
                // The session was already ended.  If a newer generation started
                // meanwhile, that operation owns the error property now.
                if (m_generation != forgetGeneration)
                    return;
                setErrorCode(forgotten ? QString()
                                       : QStringLiteral("identity_storage_failed"));
            });
    watcher->setFuture(QtConcurrent::run(&m_identityPool, [store, origin, userId]() {
        return store->forget(origin, userId);
    }));
}

#ifdef KANADE_CONTROLLER_TEST
void KanadeController::setSslConfigurationForTesting(const QSslConfiguration& configuration)
{
    createApiIfNeeded();
    m_api->setSslConfiguration(configuration);
}
#endif

// ---------------------------------------------------------------------------
// Managed online session
// ---------------------------------------------------------------------------

namespace {
// Fixed, non-secret token for a session StopReason (QML-facing).
QString stopReasonToken(Kanade::KanadeSession::StopReason reason)
{
    using R = Kanade::KanadeSession::StopReason;
    switch (reason) {
    case R::None:
        return QStringLiteral("none");
    case R::UserCancelled:
        return QStringLiteral("user_cancelled");
    case R::Logout:
        return QStringLiteral("logout");
    case R::ServerClosed:
        return QStringLiteral("server_closed");
    case R::GrantRevoked:
        return QStringLiteral("grant_revoked");
    case R::LeaseExpired:
        return QStringLiteral("lease_expired");
    case R::OfferExpired:
        return QStringLiteral("offer_expired");
    case R::SessionExpired:
        return QStringLiteral("session_expired");
    case R::ProtocolError:
        return QStringLiteral("protocol_error");
    case R::NetworkFailure:
        return QStringLiteral("network_failure");
    case R::AuthFailed:
        return QStringLiteral("auth_failed");
    case R::CreateConflict:
        return QStringLiteral("create_conflict");
    case R::CreateNotApplied:
        return QStringLiteral("create_not_applied");
    case R::CreateUnverified:
        return QStringLiteral("create_unverified");
    case R::ActivationFailed:
        return QStringLiteral("activation_failed");
    case R::ActivationUnconfirmed:
        return QStringLiteral("activation_unconfirmed");
    }
    return QStringLiteral("protocol_error");
}

QString onlineStateToken(Kanade::KanadeSession::State state)
{
    using S = Kanade::KanadeSession::State;
    switch (state) {
    case S::Idle:
        return QStringLiteral("idle");
    case S::Creating:
        return QStringLiteral("creating");
    case S::Diagnosing:
        return QStringLiteral("creating");
    case S::Offering:
        return QStringLiteral("offering");
    case S::Active:
        return QStringLiteral("active");
    case S::Closing:
        return QStringLiteral("closing");
    case S::Closed:
        return QStringLiteral("closed");
    case S::Failed:
        return QStringLiteral("failed");
    }
    return QStringLiteral("failed");
}

} // namespace

bool KanadeController::configureManagedRuntime(const Kanade::ManagedRuntimeConfig& config,
                                               QString* reason)
{
    Kanade::ManagedRuntimeValidation validation;
    if (!Kanade::validateManagedRuntimeConfig(config, validation)) {
        if (reason != nullptr) {
            *reason = validation.detail;
        }
        m_runtimeConfigured = false;
        Q_EMIT onlineChanged();
        return false;
    }
    m_runtime = config;
    m_runtimeConfigured = true;
    if (reason != nullptr) {
        reason->clear();
    }
    Q_EMIT onlineChanged();
    return true;
}

bool KanadeController::configureManagedRuntimeFromFile(const QString& approvedRoot,
                                                       const QString& configFilePath,
                                                       QString* reason)
{
    Kanade::ManagedRuntimeConfig config;
    Kanade::ManagedRuntimeValidation validation;
    if (!Kanade::loadManagedRuntimeConfig(approvedRoot, configFilePath, config, validation)) {
        if (reason != nullptr) {
            *reason = validation.detail;
        }
        m_runtimeConfigured = false;
        Q_EMIT onlineChanged();
        return false;
    }
    return configureManagedRuntime(config, reason);
}

bool KanadeController::configureManagedRuntimeForTesting(const Kanade::ManagedRuntimeConfig& config,
                                                         QString* reason)
{
    return configureManagedRuntime(config, reason);
}

void KanadeController::setOnlineErrorCode(const QString& code)
{
    if (m_onlineErrorCode == code) {
        return;
    }
    m_onlineErrorCode = code;
    Q_EMIT onlineChanged();
}

bool KanadeController::onlineSupported() const
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    return false;
#else
    return Kanade::managedPortPolicyAvailable() && m_runtimeConfigured && m_supported &&
        m_authenticated && !m_installationId.isEmpty();
#endif
}

QString KanadeController::onlineState() const
{
    if (m_onlineSession != nullptr) {
        return onlineStateToken(m_onlineSession->state());
    }
    return m_onlineErrorCode.isEmpty() ? QStringLiteral("idle") : QStringLiteral("failed");
}

QString KanadeController::onlineStopReason() const
{
    if (m_onlineSession != nullptr) {
        return stopReasonToken(m_onlineSession->stopReason());
    }
    return QStringLiteral("none");
}

QString KanadeController::onlineSessionId() const
{
    return m_onlineSession != nullptr ? m_onlineSession->sessionId() : QString();
}

bool KanadeController::activationConfirmed() const
{
    return m_onlineSession != nullptr && m_onlineSession->activationConfirmed();
}

bool KanadeController::leaseValid() const
{
    return m_onlineSession != nullptr && m_onlineSession->hasValidLease();
}

int KanadeController::leaseRemainingMs() const
{
    if (m_onlineSession == nullptr) {
        return 0;
    }
    const qint64 remaining = m_onlineSession->leaseRemainingMs();
    // Floor to whole seconds: QML must never see a value that rounds the gate
    // open, and 0 means closed.
    return remaining <= 0 ? 0 : int(remaining / 1000);
}

void KanadeController::disableCredentialDumps()
{
    // One-way and process-wide at the receiver.  Re-emitting is harmless and
    // is the only way to be sure the flag was set before a password widget
    // existed.
    m_dumpsSuppressed = true;
    Q_EMIT sensitiveOperationStarted();
    Q_EMIT onlineChanged();
}

bool KanadeController::selectedRowMatchesRuntime(const QString& grantId,
                                                 const QString& hostId) const
{
    // The selection is only a *pointer*: it must name a row this installation
    // actually holds, on the pinned host, from the current origin.  The peer's
    // installation id / key version / public key are never taken from here.
    if (!isCanonicalUuidString(grantId) || !isCanonicalUuidString(hostId)) {
        return false;
    }
    if (!m_runtimeConfigured || hostId != m_runtime.hostId) {
        return false;
    }
    for (const QVariant& value : m_devices) {
        const QVariantMap row = value.toMap();
        if (row.value(QStringLiteral("grantId")).toString() != grantId) {
            continue;
        }
        if (row.value(QStringLiteral("hostId")).toString() != m_runtime.hostId) {
            return false;
        }
        return true;
    }
    return false;
}

bool KanadeController::canStartOnlineSessionForGrant(const QString& grantId,
                                                      const QString& hostId) const
{
    if (!onlineSupported() || !m_api || m_installationId != m_runtime.clientInstallationId
        || m_onlineClientKeyVersion != m_runtime.clientKeyVersion || m_onlineSeed.size() != 44
        || originString(m_api->origin()) != m_runtime.apiOrigin
        || !selectedRowMatchesRuntime(grantId, hostId)) {
        return false;
    }

    // Do not offer a second attempt while one is live or closing.  Failed and
    // closed runs are terminal and may be explicitly retried by the user.
    if (m_onlineSession != nullptr) {
        const auto state = m_onlineSession->state();
        if (state != Kanade::KanadeSession::State::Idle
            && state != Kanade::KanadeSession::State::Closed
            && state != Kanade::KanadeSession::State::Failed) {
            return false;
        }
    }
    return true;
}

void KanadeController::startOnlineSessionForGrant(const QString& grantId, const QString& hostId)
{
    if (!Kanade::managedPortPolicyAvailable()) {
        setOnlineErrorCode(QStringLiteral("unsupported"));
        return;
    }
    if (m_onlineSession != nullptr
        && m_onlineSession->state() != Kanade::KanadeSession::State::Idle
        && m_onlineSession->state() != Kanade::KanadeSession::State::Closed
        && m_onlineSession->state() != Kanade::KanadeSession::State::Failed) {
        return; // one managed attempt at a time
    }
    if (!m_runtimeConfigured || !m_supported) {
        setOnlineErrorCode(QStringLiteral("runtime_unconfigured"));
        return;
    }
    if (!m_authenticated || !m_api || m_installationId.isEmpty()) {
        setOnlineErrorCode(QStringLiteral("identity_unavailable"));
        return;
    }
    // The pinned client identity must be the one this process authenticated as;
    // a mismatch means the manifest belongs to another installation.
    if (m_installationId != m_runtime.clientInstallationId
        || m_onlineClientKeyVersion != m_runtime.clientKeyVersion) {
        setOnlineErrorCode(QStringLiteral("identity_unavailable"));
        return;
    }
    if (m_onlineSeed.size() != 44) {
        setOnlineErrorCode(QStringLiteral("identity_unavailable"));
        return;
    }
    if (!selectedRowMatchesRuntime(grantId, hostId)) {
        // The row is not this installation's current authorization for the
        // pinned host; surface it as a protocol/selection failure, never a
        // silent fallback.
        setOnlineErrorCode(QStringLiteral("peer_key_unavailable"));
        return;
    }
    // The origin must be the pinned one; a different service is a different
    // trust scope and can never borrow this manifest.
    if (originString(m_api->origin()) != m_runtime.apiOrigin) {
        setOnlineErrorCode(QStringLiteral("origin_mismatch"));
        return;
    }

    teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
    setOnlineErrorCode(QString());
    m_onlineReady = false;
    Q_EMIT onlineReadyChanged();

    m_onlineGrantId = grantId;
    m_onlineHostId = hostId;
    m_onlineRunId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_onlineExporterWire.clear();
    // One generation per attempt: the native guard is bound to it, so a stale
    // proof from a previous run can never match.
    m_onlineRunGeneration = 1;
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    m_pendingNativeRevoke = false;
#endif


    if (!m_onlineTransport) {
        // Owned by unique_ptr with NO QObject parent: a parented object plus a
        // unique_ptr would be deleted twice.  Declaration order guarantees the
        // transport dies before the KanadeApi it borrows.
        m_onlineTransport
            = std::make_unique<Kanade::KanadeApiTransport>(m_api.get(), nullptr);
    }
    // Same rule for the session: no QObject parent, unique_ptr owns it.
    m_onlineSession
        = std::make_unique<Kanade::KanadeSession>(m_onlineTransport.get(), nullptr);

    Kanade::KanadeSession::Timing timing;
    m_onlineSession->setTiming(timing);
    if (!m_onlineSession->setServerOrigin(m_api->origin())) {
        failOnline(QStringLiteral("runtime_unconfigured"), Kanade::KanadeSession::StopReason::ProtocolError);
        return;
    }
    if (!m_onlineSession->setInstallationId(m_runtime.clientInstallationId)) {
        failOnline(QStringLiteral("identity_unavailable"), Kanade::KanadeSession::StopReason::ProtocolError);
        return;
    }
    // The bearer lives only in KanadeApi; the transport attaches it.
    m_onlineSession->setTransportProvidesCredentials(true);

    Kanade::KanadeSession::ExpectedTarget target;
    target.hostId = m_runtime.hostId;
    target.hostInstallationId = m_runtime.hostInstallationId;
    target.hostKeyVersion = m_runtime.hostKeyVersion;
    target.clientKeyVersion = m_runtime.clientKeyVersion;
    if (!m_onlineSession->setExpectedTarget(target)) {
        failOnline(QStringLiteral("runtime_unconfigured"), Kanade::KanadeSession::StopReason::ProtocolError);
        return;
    }

    connect(m_onlineSession.get(), &Kanade::KanadeSession::stateChanged, this,
            [this] { pullOnlineState(); });
    connect(m_onlineSession.get(), &Kanade::KanadeSession::authorized, this,
            &KanadeController::onOnlineAuthorized);
    connect(m_onlineSession.get(), &Kanade::KanadeSession::bothParticipantsActivated, this,
            &KanadeController::onOnlineActivationConfirmed);
    connect(m_onlineSession.get(), &Kanade::KanadeSession::stopped, this,
            [this](Kanade::KanadeSession::StopReason) {
                // Synchronous invalidation before any signal: the typed gate
                // must already be shut when QML hears about the stop.
                m_onlineReady = false;
                m_onlineIpcVerified = false;
                m_onlineIpcSequence = 0;
                teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
                pullOnlineState();
                Q_EMIT onlineReadyChanged();
            });

    m_leaseTimer.setInterval(1000);
    m_leaseTimer.setSingleShot(false);
    connect(&m_leaseTimer, &QTimer::timeout, this, &KanadeController::onLeaseTick,
            Qt::UniqueConnection);
    m_leaseTimer.start();

    Q_EMIT onlineChanged();
    m_onlineSession->start(grantId);
    pullOnlineState();
}

void KanadeController::cancelOnlineSession()
{
    if (m_onlineSession == nullptr) {
        return;
    }
    // Local-first: the session closes its own gate immediately, sends at most
    // one best-effort remote close for an id it owns, and the sidecar is told
    // to stop right after.  No fallback path is opened.
    m_onlineSession->cancel();
    teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
    pullOnlineState();
}

void KanadeController::clearOnlineError()
{
    setOnlineErrorCode(QString());
}

void KanadeController::pullOnlineState()
{
    Q_EMIT onlineChanged();
    Q_EMIT onlineLeaseChanged();
}

void KanadeController::failOnline(const QString& errorCode,
                                  Kanade::KanadeSession::StopReason reason)
{
    Q_UNUSED(reason);
    setOnlineErrorCode(errorCode);
    teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
    pullOnlineState();
}

void KanadeController::teardownOnline(bool remoteBestEffort,
                                      Kanade::KanadeSession::StopReason reason)
{
    Q_UNUSED(remoteBestEffort);
    Q_UNUSED(reason);
    // ORDER MATTERS and nothing here may block the GUI thread.
    //
    // 1. Close the local gates that QML/other lanes read FIRST.  These are plain
    //    bools/enums plus a sidecar stop request, so visibility is immediate even
    //    if a pool worker is mid-network.
    m_onlineReady = false;
    m_onlineIpcVerified = false;
    m_onlineIpcSequence = 0;
    m_sidecarAuthorized = false;
    m_onlineExporterWire.clear();
    if (m_leaseTimer.isActive()) {
        m_leaseTimer.stop();
    }

    // 2. Native invalidation.  revokeNative kills the shared lease guard
    //    lock-free and synchronously (that is the security action), then marks the
    //    gate Dead if the object mutex is free.  Cleanup only is deferred.
    revokeNative(Kanade::NativeReason::Stopped);

    // 3. Sidecar: request the stop, drop our connections so a late frame cannot
    //    re-enter this controller, and let it delete itself after its thread ends.
    if (m_sidecar != nullptr) {
        Kanade::KanadeSidecar* sidecar = m_sidecar.release();
        sidecar->disconnect(this);
        sidecar->stopSidecar();
        sidecar->deleteLater();
        // Freeze the native sidecar-side view too: a stopped sidecar can never be
        // a verified runtime.
        m_onlineIpcVerified = false;
    }

    // 4. Session: never destroyed from inside one of its own signal emissions
    //    (cancel()/expire emit `stopped` synchronously), so detach and let the
    //    event loop delete it once the emitting stack has unwound.
    if (m_onlineSession != nullptr) {
        Kanade::KanadeSession* session = m_onlineSession.release();
        session->disconnect(this);
        session->deleteLater();
    }

    // 5. Reset the QML-facing native bridge state and drop OUR reference.  The
    //    guard was already revoked in step 2 (lock-free); a worker still inside
    //    the object keeps it alive through its own shared_ptr, so nothing is
    //    destroyed underneath it and a later run can never reach it.
    resetNativeBridge(QStringLiteral("unavailable"));
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    m_nativeGuard.reset();
    m_native.reset();
#endif
}

void KanadeController::bindNativeRun()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    // No native path exists in a control-plane fixture: the gate stays closed
    // and `onlineReady` can never become true.  This is not a product build.
    return;
#else
    // Called once the online attempt is Active with a live lease.  The native
    // object is created HERE (never on idle) and is only ever fed values from
    // the validated runtime manifest and this attempt's own confirmed lease.
    if (m_native != nullptr || m_onlineSession == nullptr) {
        return;
    }
    if (!m_onlineSession->hasValidLease() || m_onlineSession->sessionId().isEmpty()) {
        return;
    }
    m_nativeHostAppVersion = m_runtime.hostAppVersion;

    Kanade::ManagedEndpointSpec spec;
    spec.apiOrigin = m_runtime.apiOrigin;
    spec.hostId = m_runtime.hostId;
    spec.grantId = m_onlineGrantId;
    spec.sessionId = m_onlineSession->sessionId();
    spec.clientInstallationId = m_runtime.clientInstallationId;
    spec.hostInstallationId = m_runtime.hostInstallationId;
    spec.clientKeyVersion = m_runtime.clientKeyVersion;
    spec.hostKeyVersion = m_runtime.hostKeyVersion;
    m_onlineRunGeneration = m_onlineRunGeneration == 0 ? 1 : m_onlineRunGeneration;
    spec.runGeneration = m_onlineRunGeneration;
    spec.confirmedDeadlineMs = m_onlineSession->leaseDeadlineMonotonicMs();

    Kanade::ValidationResult reason;
    const auto context = Kanade::ManagedEndpointContext::create(
        spec, Kanade::managedMonotonicNowMs(), reason);
    if (!context) {
        // The values do not form a valid managed context (misconfiguration or a
        // lease that is not bounded); the native path stays closed.
        setOnlineErrorCode(QStringLiteral("runtime_unconfigured"));
        return;
    }

    auto native = std::make_shared<Kanade::ManagedNativeController>();
    QString why;
    if (!native->begin(*context, &why)) {
        setOnlineErrorCode(why.isEmpty() ? QStringLiteral("runtime_unconfigured") : why);
        return;
    }
    native->setHostDisplayName(QString());
    // A thread-safe handle to the SAME guard the gate uses: revocation can then
    // happen immediately from any path, without the mutex a worker may hold.
    m_nativeGuard = native->leaseGuard();
    m_native = native;
#endif // KANADE_CONTROL_PLANE_TEST_ONLY
    // A fresh native run starts with no pairing state and no stale app rows.
    if (!m_nativeApps.isEmpty()) {
        m_nativeApps.clear();
        Q_EMIT nativeAppsChanged();
    }
    ++m_nativeOpGeneration;
    m_nativePin.clear();
    setNativeState(QStringLiteral("idle"), /*busy=*/false, QString());
}

void KanadeController::bindNativeReady()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    // No native gate exists here, so nothing can be marked ready.  onlineReady
    // is separately forced false in onSidecarReady(), keeping the fixture honest
    // rather than fabricating a launchable state.
    return;
#else
    // Called ONLY from the verified `ready` frame, and only after the server
    // confirmed both_activated.  Both steps are grounded in that one frame's
    // monotonic IPC sequence:
    //   * binding uses (readySeq - 1) -- the preceding accepted frame reserve --
    //     so the gate's "strictly newer sequence" rule still holds for ready;
    //   * the ready proof uses readySeq itself.
    if (m_native == nullptr || m_onlineSession == nullptr) {
        return;
    }
    if (!m_onlineIpcVerified || !m_onlineSession->activationConfirmed()) {
        return;
    }
    // Always build the proof from the CURRENT lease, never from a cached value.
    const qint64 proofDeadline = m_onlineSession->leaseDeadlineMonotonicMs();
    if (proofDeadline <= 0) {
        return;
    }
    const quint64 readySeq = m_onlineIpcSequence;
    if (readySeq < 1) {
        return; // a ready frame with no accepted predecessor cannot be grounded
    }

    QString failure;
    {
        // Copy what the calls need, then work on the captured instance so a
        // concurrent teardown cannot swap the object underneath this sequence.
        const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
        if (native == nullptr) {
            return;
        }
        const QString sessionId = m_onlineSession->sessionId();
        const quint64 generation = m_onlineRunGeneration;
        QMutexLocker locker(&m_nativeMutex);
        // Fold in the owner's own CURRENT confirmed lease before arming.  The
        // 1 s tick is the only other thing that advances the shared guard, so a
        // confirmation landing between the last tick and this frame would
        // otherwise leave the guard behind the owner's session.  observe() is
        // the same strict path the tick uses (equal deadline = no-op; lower /
        // foreign / elapsed / over-cap = fail closed), so this can only follow a
        // deadline Kanade itself confirmed.
        QString leaseWhy;
        if (!native->tickLease(proofDeadline, &leaseWhy)) {
            failure = leaseWhy.isEmpty() ? QStringLiteral("lease_expired") : leaseWhy;
        } else {
            // The transport id is this run's immutable id (a UUID, never a
            // secret): both the binding and the proof name the SAME transport.
            Kanade::RuntimeBinding binding;
            binding.sessionId = sessionId;
            binding.runGeneration = generation;
            binding.transportId = m_onlineRunId;
            binding.ipcSequence = readySeq - 1;
            binding.leaseDeadlineMs = proofDeadline;
            binding.ipcVerified = true;

            QString why;
            if (!native->runtimeBound(binding, &why)) {
                failure = why.isEmpty() ? QStringLiteral("sidecar_unverified") : why;
            } else {
                Kanade::ReadyProof proof;
                proof.sessionId = sessionId;
                proof.runGeneration = generation;
                proof.transportId = m_onlineRunId;
                proof.ipcSequence = readySeq;
                // Identical deadline: the proof may only tighten, never extend.
                proof.leaseDeadlineMs = proofDeadline;
                proof.ipcVerified = true;
                if (!native->runtimeReady(proof, &why)) {
                    failure = why.isEmpty() ? QStringLiteral("runtime_unconfigured") : why;
                }
            }
        }
    }
    // The lock is released BEFORE any error path that may revoke: revokeNative()
    // takes the same non-recursive mutex, so calling it inside would deadlock.
    if (!failure.isEmpty()) {
        // Fail closed and tell the TRUTH: this run is not ready, so the readiness
        // fact must drop before the error is surfaced and the run is stopped.
        m_onlineReady = false;
        m_onlineIpcVerified = false;
        Q_EMIT onlineReadyChanged();
        setOnlineErrorCode(failure);
        revokeNative(Kanade::NativeReason::ReadyProofUnverified);
        // Stop the run: an activation-confirmed session whose native gate cannot
        // be armed must not keep a sidecar relaying or a lease renewing.  The
        // identical guard/sidecar then fail closed from their own clocks, and the
        // existing session is interrupted by the normal cancel path (never by
        // touching any other Session instance).
        if (m_onlineSession != nullptr) {
            m_onlineSession->cancel();
        }
        teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
        pullOnlineState();
    }
#endif
}

void KanadeController::revokeNative(Kanade::NativeReason reason)
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    Q_UNUSED(reason);
    return;
#else
    // STEP 1 (synchronous, lock-free, unconditional): close the lease window
    // itself.  The guard is thread-safe and shared with the gate, so this
    // invalidates every permission check immediately even while a worker is
    // blocked inside NvHTTP and even if this object's mutex is held.  This is
    // the actual security action; everything below is cleanup bookkeeping.
    if (m_nativeGuard != nullptr) {
        m_nativeGuard->revoke(reason);
    }
    auto* stream = qobject_cast<Session*>(m_issuedNativeStream.data());
    if (stream && stream == Session::get()) {
        stream->interrupt();
    }

    // STEP 2 (cleanup): try to mark the gate Dead now.  If a worker holds the
    // mutex, defer the object-level revoke -- the lease is already dead, so the
    // gate's own `permitsLocked()` refuses every call regardless.
    if (m_nativeMutex.tryLock()) {
        if (m_native != nullptr) {
            m_native->revoke(reason);
        }
        m_nativeMutex.unlock();
        m_pendingNativeRevoke = false;
        return;
    }
    m_pendingNativeRevoke = true;
    m_pendingNativeRevokeReason = reason;
#endif
}

void KanadeController::applyPendingNativeRevoke()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    return;
#else
    // Runs on the UI thread after a worker finished.  Security was already
    // handled synchronously by revokeNative() (guard->revoke is lock-free); this
    // only marks the object-level gate Dead so no native call is permitted.
    if (!m_pendingNativeRevoke) {
        return;
    }
    const Kanade::NativeReason reason = m_pendingNativeRevokeReason;
    m_pendingNativeRevoke = false;
    if (m_nativeMutex.tryLock()) {
        if (m_native != nullptr) {
            m_native->revoke(reason);
        }
        m_nativeMutex.unlock();
    }
#endif
}

// ---------------------------------------------------------------------------
// Native bridge (QML-facing)
// ---------------------------------------------------------------------------

namespace {

#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
// A transient 4-digit PIN.  Generated locally per attempt, never persisted, and
// it is the ONLY thing a user ever types into the host's own PIN dialog.
QString generateTransientPin()
{
    quint32 word = 0;
    QRandomGenerator::system()->fillRange(&word, 1);
    const quint32 value = 1000 + (word % 9000u);
    return QString::number(value);
}
#endif

} // namespace

void KanadeController::setNativeState(const QString& pairingState, bool busy,
                                      const QString& errorCode)
{
    bool changed = false;
    if (m_nativePairingState != pairingState) {
        m_nativePairingState = pairingState;
        changed = true;
    }
    if (m_nativeBusy != busy) {
        m_nativeBusy = busy;
        changed = true;
    }
    if (m_nativeErrorCode != errorCode) {
        m_nativeErrorCode = errorCode;
        changed = true;
    }
    if (changed) {
        Q_EMIT nativeChanged();
    }
}

void KanadeController::resetNativeBridge(const QString& pairingState)
{
    // Any in-flight native task is invalidated BEFORE the visible state drops:
    // a late pair/applist result must never apply to a stopped run.
    ++m_nativeOpGeneration;
    m_nativePin.clear();
    m_nativeHostAppVersion.clear();
    // Never block here: resetNativeBridge is called from teardown paths.  A
    // busy worker already means the gate was at most Bound, and the deferred
    // revoke finishes after it releases the mutex.
    revokeNative(Kanade::NativeReason::Stopped);
    if (!m_nativeApps.isEmpty()) {
        m_nativeApps.clear();
        Q_EMIT nativeAppsChanged();
    }
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    m_nativeAppObjects.clear();
#endif
    setNativeState(pairingState, /*busy=*/false, QString());
}

bool KanadeController::nativeAvailable() const
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    return false;
#else
    return m_onlineReady && m_native != nullptr;
#endif
}

void KanadeController::beginNativePairing()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    setNativeState(QStringLiteral("unavailable"), false,
                   QStringLiteral("unsupported"));
    return;
#else
    if (!nativeAvailable() || m_nativeBusy) {
        if (!nativeAvailable()) {
            setNativeState(QStringLiteral("unavailable"), false,
                           QStringLiteral("not_ready"));
        }
        return;
    }
    // The host application version comes from the pinned manifest, never from
    // QML and never from the device directory.
    if (m_runtime.hostAppVersion.isEmpty()) {
        setNativeState(QStringLiteral("failed"), false,
                       QStringLiteral("host_version_unpinned"));
        return;
    }

    m_nativePin = generateTransientPin();
    m_nativeHostAppVersion = m_runtime.hostAppVersion;
    const quint64 op = ++m_nativeOpGeneration;
    setNativeState(QStringLiteral("pairing"), /*busy=*/true, QString());

    // Capture the native instance and its generation BY VALUE: a task that
    // started for one run must never operate on a later run's object, even if
    // m_native is replaced while this task is queued or running.  The shared_ptr
    // also keeps the object alive for the duration of the blocking exchange.
    const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
    const QString pin = m_nativePin;
    const QString appVersion = m_nativeHostAppVersion;
    if (native == nullptr) {
        setNativeState(QStringLiteral("failed"), /*busy=*/false,
                       QStringLiteral("not_ready"));
        return;
    }
    auto* watcher = new QFutureWatcher<NativePairResult>(this);
    connect(watcher, &QFutureWatcher<NativePairResult>::finished, this,
            [this, watcher, op] {
                const NativePairResult result = watcher->result();
                watcher->deleteLater();
                // Apply any revoke deferred while the worker held the mutex
                // BEFORE acting on the result, so a run revoked mid-pair can
                // never surface "paired".
                applyPendingNativeRevoke();
                if (op != m_nativeOpGeneration || m_pendingNativeRevoke) {
                    m_nativePin.clear();
                    return; // superseded by a stop/revoke: drop the result
                }
                m_nativePin.clear();
                if (result.ok) {
                    setNativeState(QStringLiteral("paired"), /*busy=*/false, QString());
                } else if (result.pinWrong) {
                    setNativeState(QStringLiteral("pinRejected"), /*busy=*/false,
                                   QStringLiteral("pin_wrong"));
                } else {
                    setNativeState(QStringLiteral("failed"), /*busy=*/false,
                                   result.reason.isEmpty()
                                       ? QStringLiteral("pair_failed")
                                       : result.reason);
                }
            });
    // The worker uses ITS OWN captured native instance, but the object is also
    // reachable from the UI (createNativeStream/stop), so calls are still
    // serialized by m_nativeMutex.  Security does NOT depend on that mutex any
    // more: revokeNative() kills the shared lease guard first, lock-free.
    watcher->setFuture(QtConcurrent::run(&m_identityPool, [this, native, pin, appVersion] {
        NativePairResult result;
        QMutexLocker locker(&m_nativeMutex);
        bool pinWrong = false;
        QString why;
        result.ok = native->pairWithPin(appVersion, pin, &pinWrong, &why);
        result.pinWrong = pinWrong;
        result.reason = why;
        return result;
    }));
#endif
}

void KanadeController::refreshNativeApps()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    setNativeState(QStringLiteral("unavailable"), false,
                   QStringLiteral("unsupported"));
    return;
#else
    if (!nativeAvailable() || m_nativeBusy) {
        return;
    }
    const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
    if (native == nullptr) {
        setNativeState(QStringLiteral("failed"), false, QStringLiteral("not_ready"));
        return;
    }
    {
        QMutexLocker locker(&m_nativeMutex);
        if (native->ephemeralCertificate().isNull()) {
            setNativeState(QStringLiteral("failed"), false,
                           QStringLiteral("not_paired"));
            return;
        }
    }
    const quint64 op = ++m_nativeOpGeneration;
    setNativeState(QStringLiteral("loadingApps"), /*busy=*/true, QString());

    auto* watcher = new QFutureWatcher<NativeAppListResult>(this);
    connect(watcher, &QFutureWatcher<NativeAppListResult>::finished, this,
            [this, watcher, op] {
                const NativeAppListResult result = watcher->result();
                watcher->deleteLater();
                // Apply a deferred revoke before consuming the result.
                applyPendingNativeRevoke();
                if (op != m_nativeOpGeneration || m_pendingNativeRevoke) {
                    return;
                }
                if (!result.ok) {
                    setNativeState(QStringLiteral("failed"), /*busy=*/false,
                                   result.reason.isEmpty() ? QStringLiteral("applist_failed")
                                                           : result.reason);
                    return;
                }
                QVariantList apps;
                for (const NativeAppEntry& entry : result.apps) {
                    QVariantMap row;
                    row.insert(QStringLiteral("appId"), entry.appId);
                    row.insert(QStringLiteral("name"), entry.name);
                    apps.append(row);
                }
                m_nativeApps = apps;
                m_nativeAppObjects = result.appsNative;
                Q_EMIT nativeAppsChanged();
                setNativeState(QStringLiteral("appsReady"), /*busy=*/false, QString());
            });
    // The worker uses ITS OWN captured instance; the shared lease guard is the
    // real security boundary, so a concurrent revoke does not depend on this
    // mutex.  The mutex only keeps the native object's own state coherent
    // against UI-thread calls (createNativeStream/stop).
    watcher->setFuture(QtConcurrent::run(&m_identityPool, [this, native] {
        NativeAppListResult result;
        QMutexLocker locker(&m_nativeMutex);
        QString why;
        result.ok = native->fetchAppList(&result.appsNative, &why);
        result.reason = why;
        for (const NvApp& app : qAsConst(result.appsNative)) {
            NativeAppEntry entry;
            entry.appId = QString::number(app.id);
            entry.name = app.name;
            result.apps.append(entry);
        }
        return result;
    }));
#endif
}

QObject* KanadeController::createNativeStream(const QString& appId)
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    Q_UNUSED(appId);
    return nullptr;
#else
    if (!nativeAvailable() || m_nativeBusy || m_native == nullptr || m_issuedNativeStream) {
        return nullptr;
    }
    // The app id must be one we actually fetched: QML cannot invent an id and
    // reach the host with it.
    bool known = false;
    for (const QVariant& value : qAsConst(m_nativeApps)) {
        if (value.toMap().value(QStringLiteral("appId")).toString() == appId) {
            known = true;
            break;
        }
    }
    if (!known) {
        return nullptr;
    }
    // The app object must be one WE fetched; QML only ever supplied an opaque id.
    QMutexLocker locker(&m_nativeMutex);
    const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
    if (native == nullptr) {
        return nullptr;
    }
    for (const NvApp& candidate : qAsConst(m_nativeAppObjects)) {
        if (QString::number(candidate.id) == appId) {
            NvApp app = candidate;
            Session* session = native->createSession(app, /*preferences=*/nullptr);
            m_issuedNativeStream = session;
            return session;
        }
    }
    return nullptr;
#endif
}

void KanadeController::discardUnstartedNativeStream(QObject* stream)
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    Q_UNUSED(stream);
#else
    if (stream && stream == m_issuedNativeStream.data() && stream != Session::get()) {
        // Only called when the segue could not even be constructed. No SDL
        // worker for this object has started, and no LAN object is eligible.
        m_issuedNativeStream.clear();
        stream->deleteLater();
    }
#endif
}

void KanadeController::stopNativeApp()
{
#ifdef KANADE_CONTROL_PLANE_TEST_ONLY
    setNativeState(QStringLiteral("unavailable"), false,
                   QStringLiteral("unsupported"));
    return;
#else
    // Only the explicit host-app action may send a native cancel. It must use
    // the still-live pinned path; logout/revoke never enters this method.
    if (!nativeAvailable() || m_nativeBusy || m_native == nullptr)
        return;
    ++m_nativeOpGeneration;
    const quint64 op = m_nativeOpGeneration;
    const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
    setNativeState(QStringLiteral("stopped"), true, QString());
    auto* watcher = new QFutureWatcher<void>(this);
    connect(watcher, &QFutureWatcher<void>::finished, this, [this, watcher, op] {
        watcher->deleteLater();
        if (op == m_nativeOpGeneration)
            cancelOnlineSession();
    });
    watcher->setFuture(QtConcurrent::run(&m_identityPool, [this, native] {
        QMutexLocker locker(&m_nativeMutex);
        native->stop();
    }));
#endif
}

void KanadeController::onLeaseTick()
{
    if (m_onlineSession == nullptr) {
        // A live sidecar without a session is a half-open managed path: it must
        // never keep relaying.  Shut it down instead of idling.
        if (m_sidecar != nullptr) {
            teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
        }
        Q_EMIT onlineLeaseChanged();
        return;
    }
    const bool valid = m_onlineSession->hasValidLease();
    const qint64 deadline = m_onlineSession->leaseDeadlineMonotonicMs();
    if (!valid || deadline <= 0) {
        // Local gate closed: the sidecar's gate must not outlive it.  Stop it
        // now (its own clock check is a backstop, never the authority) and
        // invalidate the typed facts synchronously.
        m_onlineReady = false;
        m_onlineIpcVerified = false;
        m_onlineIpcSequence = 0;
        m_sidecarAuthorized = false;
        // The native guard is revoked from the LOCAL gate's clock, not from a
        // signal: this is the fail-closed path the plan requires.  revokeNative
        // closes the shared guard lock-free, then marks the gate Dead if free.
        revokeNative(Kanade::NativeReason::LeaseExpired);
        // Drop our reference only after the revoke; a worker holding the object
        // keeps it alive until it finishes.
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
        m_nativeGuard.reset();
        m_native.reset();
#endif
        if (m_sidecar != nullptr) {
            Kanade::KanadeSidecar* sidecar = m_sidecar.release();
            sidecar->disconnect(this);
            sidecar->stopSidecar();
            sidecar->deleteLater();
        }
        Q_EMIT onlineReadyChanged();
        Q_EMIT onlineLeaseChanged();
        return;
    }
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    if (m_native != nullptr) {
        // The 1 s watchdog OBSERVES the confirmed deadline; it does not demand
        // a strictly later one.  The server confirms a later lease roughly every
        // 30 s, so most of these ticks repeat the current deadline - that is
        // "no news", and tickLease() therefore succeeds without moving
        // anything.  It still fails closed (and returns false) on an expired or
        // revoked lease, a foreign run, a lower deadline or an over-cap
        // confirmation.  The object is not thread-safe; take a copy of the
        // pointer and tryLock (never block the tick behind a worker).
        const std::shared_ptr<Kanade::ManagedNativeController> native = m_native;
        if (m_nativeMutex.tryLock()) {
            const bool observed = native->tickLease(deadline);
            m_nativeMutex.unlock();
            if (!observed) {
                // Terminal (expired/revoked/refused confirmation).  The lock is
                // already released, so use the ONE existing cancellation path:
                // it clears the readiness facts, revokes the native gate/lease,
                // stops the sidecar and closes the session.  Nothing is renewed
                // and no partial teardown is duplicated here.
                cancelOnlineSession();
                return;
            }
        }
        // If the mutex is busy the guard still expires on its own clock, which
        // is the conservative direction: no extension is ever granted here.
    }
#endif
    // Only a sidecar that already received its single `authorize` may be
    // renewed, and only with a STRICTLY greater absolute deadline (its gate
    // rejects repeats and never extends from the peer's view).  This runs only
    // after the native observation above accepted the deadline.
    if (m_sidecar != nullptr && m_sidecarAuthorized) {
        m_sidecar->renewLease(deadline);
    }
    Q_EMIT onlineLeaseChanged();
}

void KanadeController::onOnlineAuthorized()
{
    // "Kanade lease active" only.  The native ready gate stays closed until a
    // real sidecar `ready` frame plus a both_activated confirmation arrive.
    // The sidecar is launched HERE, not earlier: it must never run before the
    // offer was accepted and the lease gate opened.
    if (m_sidecar == nullptr && m_onlineSession != nullptr) {
        const QString sessionId = m_onlineSession->sessionId();
        const QByteArray exporterSeed = m_onlineSeed;
        const qint64 deadline = m_onlineSession->leaseDeadlineMonotonicMs();
        if (!sessionId.isEmpty() && exporterSeed.size() == 44 && deadline > 0) {
            auto sidecar = std::make_unique<Kanade::KanadeSidecar>(nullptr);
            Kanade::SidecarPlan plan;
            plan.approvedRoot = m_runtime.approvedRoot;
            plan.executablePath = m_runtime.sidecarExecutablePath;
            plan.executableSha256 = m_runtime.sidecarExecutableSha256;
            plan.hostId = m_runtime.hostId;
            plan.hostInstallationId = m_runtime.hostInstallationId;
            plan.hostKeyVersion = m_runtime.hostKeyVersion;
            plan.hostPublicKey = m_runtime.hostPublicKey;
            plan.localQuic = m_runtime.localQuic.toString();
            plan.peerQuic = m_runtime.peerQuic.toString();
            plan.handshakeTimeoutMs = m_runtime.handshakeTimeoutMs;
            QString reason;
            if (!sidecar->configure(plan, &reason)) {
                setOnlineErrorCode(reason.isEmpty() ? QStringLiteral("runtime_unconfigured")
                                                   : reason);
                return;
            }
            // The native object is driven by the runtime's own verified frames:
            // `channel` marks it bound (arm), `ready` marks it ready.
            connect(sidecar.get(), &Kanade::KanadeSidecar::channelReady, this,
                    &KanadeController::onSidecarChannel);
            connect(sidecar.get(), &Kanade::KanadeSidecar::ready, this,
                    &KanadeController::onSidecarReady);
            connect(sidecar.get(), &Kanade::KanadeSidecar::faulted, this,
                    [this](Kanade::SidecarFault, const QString& reason) {
                        onSidecarFault(reason);
                    });
            connect(sidecar.get(), &Kanade::KanadeSidecar::stopped, this,
                    &KanadeController::onSidecarStopped);
            m_sidecar = std::move(sidecar);
            m_sidecar->start(sessionId, m_onlineRunId, exporterSeed, deadline);
        }
    }
    // The native object exists only while a genuinely live managed attempt does.
    bindNativeRun();
    pullOnlineState();
}

void KanadeController::onOnlineActivationConfirmed()
{
    // The server confirmed both participants proved the same binding.  This is
    // the ONLY point at which the sidecar may be authorized: its state machine
    // accepts `authorize` exactly once, only after `channel`, and only then may
    // it listen and report `ready`.  Authorizing before this (or waiting for
    // `ready` to authorize) would deadlock the contract.
    if (m_sidecar != nullptr && !m_sidecarAuthorized && m_onlineSession != nullptr) {
        const qint64 deadline = m_onlineSession->leaseDeadlineMonotonicMs();
        if (deadline > 0 && m_onlineSession->hasValidLease()) {
            m_sidecar->authorize(deadline);
            m_sidecarAuthorized = true;
        }
    }
    m_onlineReady = m_onlineIpcVerified && m_onlineSession != nullptr
        && m_onlineSession->activationConfirmed();
    if (m_onlineReady) {
        bindNativeReady();
    }
    Q_EMIT onlineReadyChanged();
    pullOnlineState();
}

void KanadeController::onSidecarChannel(const QByteArray& exporter)
{
    if (m_onlineSession == nullptr || exporter.size() != 32) {
        return;
    }
    m_onlineExporterWire =
        QString::fromLatin1(exporter.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    if (m_onlineExporterWire.size() != 43) {
        m_onlineExporterWire.clear();
        return;
    }
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    // The sidecar's `channel` frame carries the exporter needed for activation;
    // it does NOT mean "listening".  The native gate is therefore NOT bound
    // here: binding happens on the verified `ready` frame (bindNativeReady),
    // grounded in that frame's preceding accepted sequence.
#endif
    // Activation uses the sidecar's verified exporter, signed with the
    // installation seed held for this authenticated session only.  The signer
    // is a value copy: it cannot outlive the seed's clear on logout.
    if (m_onlineSeed.size() != 44) {
        return;
    }
    const QByteArray seed = m_onlineSeed;
    if (!m_onlineSession->beginActivation(
        exporter, [seed](const QString& ticket, const QByteArray& message) {
            Q_UNUSED(ticket);
            return Kanade::signActivationProof(seed, message);
        })) {
        setOnlineErrorCode(QStringLiteral("activation_failed"));
        cancelOnlineSession();
    }
}

void KanadeController::onSidecarReady()
{
    // A verified `ready` frame is necessary but NOT sufficient: the typed
    // native gate also requires the server's both_activated confirmation for
    // this exact session.  Record the IPC fact; expose "ready" only when both
    // hold, so QML can never see a ready state from the pipe alone.
    m_onlineIpcVerified = true;
    if (m_sidecar != nullptr) {
        m_onlineIpcSequence = m_sidecar->inboundSequence();
    }
    m_onlineReady = m_onlineSession != nullptr && m_onlineSession->activationConfirmed()
        && m_onlineIpcVerified;
    // Late-arriving authorization: the sidecar only reaches `ready` after it
    // was authorized, but if the server's confirmation races the pipe frame the
    // authorize call is issued here exactly once (never a second time).
    if (m_sidecar != nullptr && !m_sidecarAuthorized && m_onlineSession != nullptr
        && m_onlineSession->activationConfirmed()) {
        const qint64 deadline = m_onlineSession->leaseDeadlineMonotonicMs();
        if (deadline > 0 && m_onlineSession->hasValidLease()) {
            m_sidecar->authorize(deadline);
            m_sidecarAuthorized = true;
        }
    }
    if (m_onlineReady) {
        bindNativeReady();
    }
    Q_EMIT onlineReadyChanged();
    pullOnlineState();
}

void KanadeController::onSidecarFault(const QString& reason)
{
    // A sidecar fault never falls back to LAN and never keeps a half-open
    // managed path: invalidate the IPC fact and the native guard FIRST
    // (synchronously, before any signal), then stop the session locally.
    m_onlineIpcVerified = false;
    m_onlineIpcSequence = 0;
    m_onlineReady = false;
    revokeNative(Kanade::NativeReason::RuntimeBindingUnverified);
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    m_nativeGuard.reset();
    m_native.reset();
#endif
    Q_EMIT onlineReadyChanged();
    setOnlineErrorCode(reason.isEmpty() ? QStringLiteral("sidecar_protocol_error") : reason);
    if (m_onlineSession != nullptr) {
        m_onlineSession->cancel();
    }
    teardownOnline(/*remoteBestEffort=*/false, Kanade::KanadeSession::StopReason::None);
    pullOnlineState();
}

void KanadeController::onSidecarStopped()
{
    m_onlineIpcVerified = false;
    m_onlineIpcSequence = 0;
    m_onlineReady = false;
    // A stopped sidecar can never be a ready runtime.
    revokeNative(Kanade::NativeReason::Stopped);
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    m_nativeGuard.reset();
    m_native.reset();
#endif
    Q_EMIT onlineReadyChanged();
    pullOnlineState();
}

