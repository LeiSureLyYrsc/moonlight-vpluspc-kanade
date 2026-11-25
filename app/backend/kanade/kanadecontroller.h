#pragma once

#ifndef KANADECONTROLLER_H
#define KANADECONTROLLER_H

#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QPointer>
#include <QSslConfiguration>
#include <QString>
#include <QThreadPool>
#include <QTimer>
#include <QUrl>
#include <QVariantList>

#include <functional>
#include <memory>
#include <optional>

#include "kanadeidentity.h"
#include "kanaderuntime.h"
#include "kanadesession.h"

// The managed NATIVE controller is the only part of this lane that needs
// NvHTTP/Session/common-c (i.e. a full GameStream build).  A headless
// control-plane fixture (kanade_control / kanade_https) defines
// KANADE_CONTROL_PLANE_TEST_ONLY: the product binding is then compiled out and
// `onlineReady` can never become true there -- the fixture has no native path,
// so reporting readiness would be a fabricated success.  Production builds must
// NEVER define this macro.
//
// managednative.h itself is header-only value/gate types (Qt Core +
// managedendpoint.h, no NvHTTP/Session/common-c), so it is ALWAYS included: the
// stable `Kanade::NativeReason` enum and the gate/guard types are needed even in
// a headless fixture (e.g. to declare revokeNative).  Only the implementing
// controller and NvApp need the guard.
#include "managednative.h"

#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
#include "managednativecontroller.h"
#include "backend/nvapp.h"
#endif

class KanadeApi;

namespace Kanade {
class KanadeApiTransport;
class KanadeSession;
class KanadeSidecar;
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
class ManagedNativeController;
#endif
} // namespace Kanade

// Kanade online-mode controller (P1 client control plane).
//
// This is the single C++ object the QML layer (gui/KanadeDevices.qml, exposed
// as the "KanadeController" singleton) talks to.  It owns account login, the
// client installation identity, the two authorization methods, the device
// snapshot, sign-out and "forget this installation".  It performs no streaming,
// no sidecar I/O and no data-plane mapping: the page it backs must keep the
// connect action disabled, because this class has no way to make it true.
//
// Contract notes (verified read-only against Kanade api/auth.py and
// api/pairing.py at 4353a153):
//   * POST /v1/auth/login -> TokenPair whose `installation` is NULL: it is an
//     ACCOUNT credential and grants no device authority.
//   * POST /v1/installations/challenge (account Bearer) -> ChallengeOut carrying
//     only top-level challenge_id/nonce/expires_at/canonical_message/purpose/
//     role/public_key.  This client sends no label, so the canonical enrollment
//     message carries "label":null, exactly as kanadeidentity.h rebuilds it.
//   * POST /v1/installations -> InstallationCreatedOut
//     {installation:{id,owner_id,role,public_key,key_version,...}, created,
//     tokens}.  Re-posting the same active key returns 200 created:false
//     tokens:null, which is the idempotent recovery path.
//   * POST /v1/auth/device-challenge and /v1/auth/device-token are
//     UNAUTHENTICATED: possession of the installation key is the credential.
//     The device-login canonical message embeds user_id, so a locally verified
//     account user id that does not match makes signing fail closed.
//   * /v1/devices devices[] is this installation's own grants; hosts[] is the
//     owner view.  connection_state is "unknown" when the session lane has no
//     row, so it is never presented as "connectable".
//
// Security properties this class is responsible for (plan 2, 3.3, 3.4):
//   * Account vs device credentials stay distinct.  Every flow ends with
//     GET /v1/auth/me confirming the user id and, for the device step, that the
//     token really is device-bound with installation id and role "client"
//     matching the key held locally.  A mismatching token is discarded unused.
//   * The installation seed is persisted BEFORE POST /v1/installations, so a
//     lost response is recovered idempotently with the same key instead of
//     minting a second identity.  Only LoadResult::NotFound may generate a new
//     key; Error (corrupt/tampered/unprovable ACL) and Unsupported fail closed
//     with "identity_storage_failed" -- never a fresh ephemeral key and never a
//     permissive root.
//   * Only the canonical message rebuilt locally is signed (kanadeidentity.h).
//     This class never signs a server-supplied string.
//   * Credentials are memory-only.  Passwords exist as parameters and inside
//     the in-flight request body only; tokens live only inside KanadeApi; the
//     only disk artifact is the DPAPI-sealed installation seed.  Nothing is
//     logged.
//   * Generation invalidation: each async step captures the run generation and
//     the canonical origin it started for.  Sign-out, authentication loss, a
//     service-URL switch or "forget" bumps the generation and aborts in-flight
//     replies, so a late reply can neither revive a stale origin, re-open the
//     previous account's devices, nor clear the credentials of a session that
//     replaced it.
//   * No blind mutation replay.  A pairing create carries a client-chosen
//     idempotency key reused only when the user retries the same
//     (code, method); it is never re-sent automatically.  Cancel and remove are
//     explicit actions.  When the server snapshot says a request was approved
//     after a cancel, that truth wins: the device list is refreshed and the
//     cancel is never reported as having succeeded.
//   * Logout is local-first: the local session ends even if the service is
//     unreachable.  The remote family logout is one best-effort request using
//     the credentials that were just dropped, so it cannot clear a newer
//     session.
//
// Threading: all members live on the thread that created the controller.  Key
// generation, DPAPI load/save and challenge signing cannot stall the UI, so
// they run through QtConcurrent; results are delivered back on the owning
// thread with the generation guard re-checked.  Workers capture value copies
// (store, origin, user id, identity), never `this`.
class KanadeController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool supported READ supported NOTIFY stateChanged)
    Q_PROPERTY(bool authenticated READ authenticated NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(QString origin READ origin NOTIFY stateChanged)
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(QString pairState READ pairState NOTIFY pairStateChanged)
    Q_PROPERTY(QString errorCode READ errorCode NOTIFY errorCodeChanged)

    // --- Managed online session (additive; existing API unchanged) -----------
    Q_PROPERTY(bool onlineSupported READ onlineSupported NOTIFY onlineChanged)
    Q_PROPERTY(QString onlineState READ onlineState NOTIFY onlineChanged)
    Q_PROPERTY(QString onlineStopReason READ onlineStopReason NOTIFY onlineChanged)
    Q_PROPERTY(QString onlineErrorCode READ onlineErrorCode NOTIFY onlineChanged)
    Q_PROPERTY(QString onlineSessionId READ onlineSessionId NOTIFY onlineChanged)
    Q_PROPERTY(bool activationConfirmed READ activationConfirmed NOTIFY onlineChanged)
    Q_PROPERTY(bool onlineReady READ onlineReady NOTIFY onlineReadyChanged)
    Q_PROPERTY(bool leaseValid READ leaseValid NOTIFY onlineLeaseChanged)
    Q_PROPERTY(int leaseRemainingMs READ leaseRemainingMs NOTIFY onlineLeaseChanged)

    // --- Native managed path (QML-facing) -----------------------------------
    // nativePairingState: "unavailable" | "idle" | "pairing" | "pinRejected"
    //                     | "paired" | "loadingApps" | "appsReady" | "failed"
    //                     | "stopped"
    Q_PROPERTY(QString nativePairingState READ nativePairingState NOTIFY nativeChanged)
    // [{ "appId": <id>, "name": <display> }] in host order; display only, never
    // a dial target and never an address.
    Q_PROPERTY(QVariantList nativeApps READ nativeApps NOTIFY nativeAppsChanged)
    Q_PROPERTY(bool nativeBusy READ nativeBusy NOTIFY nativeChanged)
    // The transient PIN generated for THIS pairing attempt, empty outside it.
    // Never persisted, never logged, and sent only to the native PIN exchange
    // on the loopback managed endpoint.
    Q_PROPERTY(QString nativePin READ nativePin NOTIFY nativeChanged)
    Q_PROPERTY(QString nativeErrorCode READ nativeErrorCode NOTIFY nativeChanged)

public:
    // approvedRoot: absolute directory that may hold the DPAPI-sealed
    // installation identity.  Empty selects the product default (see
    // identityRoot()).  Tests inject a scratch directory.
    explicit KanadeController(QString approvedRoot = QString(), QObject* parent = nullptr);
    ~KanadeController() override;

    bool supported() const { return m_supported; }
    bool authenticated() const { return m_authenticated; }
    bool busy() const { return m_busy > 0; }
    QString origin() const;
    QVariantList devices() const { return m_devices; }
    QString pairState() const { return m_pairState; }
    QString errorCode() const { return m_errorCode; }

    bool onlineSupported() const;
    QString onlineState() const;
    QString onlineStopReason() const;
    QString onlineErrorCode() const { return m_onlineErrorCode; }
    QString onlineSessionId() const;
    bool activationConfirmed() const;
    bool onlineReady() const { return m_onlineReady; }
    bool leaseValid() const;
    int leaseRemainingMs() const;

    QString nativePairingState() const { return m_nativePairingState; }
    QVariantList nativeApps() const { return m_nativeApps; }
    bool nativeBusy() const { return m_nativeBusy; }
    QString nativePin() const { return m_nativePin; }
    QString nativeErrorCode() const { return m_nativeErrorCode; }

    // --- Native managed path (C++ only; never QML) --------------------------
    // The managed native controller bound to this online run, or null.  It is a
    // separate object (owned by the native lane) so the QML surface stays one
    // small enum, and a caller cannot drive native operations without passing
    // through it.  Absent entirely in a KANADE_CONTROL_PLANE_TEST_ONLY fixture
    // (that file is not even included there), so the accessor does not exist.
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    Kanade::ManagedNativeController* managedNative() const { return m_native.get(); }
#endif
    quint64 onlineRunGeneration() const { return m_onlineRunGeneration; }

    // --- Native bridge for QML (designer contract) --------------------------
    //
    // These are the ONLY native entry points QML may call.  They are inert and
    // report "unavailable" unless the managed run reached a verified ready
    // state, so a page can never start native work on an unverified path.
    Q_INVOKABLE void beginNativePairing();
    Q_INVOKABLE void refreshNativeApps();
    // Returns a Session* (as QObject*) ready for StreamSegue, or null when the
    // app id is unknown or the gate is not open.  Ownership passes to the
    // caller (StreamSegue).
    Q_INVOKABLE QObject* createNativeStream(const QString& appId);
    Q_INVOKABLE void discardUnstartedNativeStream(QObject* stream);
    Q_INVOKABLE void stopNativeApp();
    // Account login.  serviceUrl must be a bare https origin; anything else is
    // rejected locally with "insecure_origin" before any network activity.
    // Any previous session (including a different origin) is ended first.
    Q_INVOKABLE void login(const QString& serviceUrl, const QString& login,
                           const QString& password);

    // Local-first sign-out: ends this session immediately, then makes one
    // best-effort remote logout of the family it held.  The sealed installation
    // identity is kept for the next login of the SAME account, which must be
    // verified again through /auth/me.
    Q_INVOKABLE void logout();

    // Re-reads GET /v1/devices (read-only, safe to repeat).
    Q_INVOKABLE void refreshDevices();

    // method: "password" (device code + add password; grant issued immediately)
    //         "confirm"  (device code; the host must approve)
    Q_INVOKABLE void addDevice(const QString& deviceCode, const QString& method,
                               const QString& password);

    // Cancels the pending confirmation request (requester only).  If the server
    // snapshot says it was already approved, that state wins and the device
    // list is refreshed.
    Q_INVOKABLE void cancelPair();

    // Revokes this installation's authorization for one host.  Never removes
    // Sunshine native pairing.
    Q_INVOKABLE void removeGrant(const QString& grantId);

    // Deletes the local sealed identity ("forget this installation"), after
    // signing out.  Remote revocation is a separate explicit action.
    Q_INVOKABLE void forgetInstallation();

    // Asks the host process to stop writing crash dumps for the rest of this
    // process's life.  Called by the online page before any password field can
    // be focused, and emitted from login() as a fallback.  One-way: nothing
    // re-enables dumps (a dump written after a credential existed is exactly
    // what this must prevent).
    Q_INVOKABLE void disableCredentialDumps();

    // --- Managed online session (additive) ----------------------------------
    //
    // QML names ONLY an authorization row it already displays:
    // startOnlineSessionForGrant(grantId, hostId).  The peer's installation id,
    // key version and public key are NOT directory fields (Kanade
    // GET /v1/devices carries only grant_id/host_id/client_installation_id);
    // they come from the operator's runtime configuration file, and the
    // selected row must match it exactly.  There is deliberately no QML-visible
    // overload that accepts a key or an endpoint.
    Q_INVOKABLE void startOnlineSessionForGrant(const QString& grantId, const QString& hostId);
    // Side-effect-free UI eligibility check.  The start method repeats every
    // trust/runtime validation before doing work; this only opens the CTA before
    // onlineReady, which is necessarily a result of starting the session.
    Q_INVOKABLE bool canStartOnlineSessionForGrant(const QString& grantId,
                                                   const QString& hostId) const;
    Q_INVOKABLE void cancelOnlineSession();
    Q_INVOKABLE void clearOnlineError();

    // C++-only production configuration (called once from app/main.cpp).
    // `config` must already be the validated object from
    // Kanade::loadManagedRuntimeConfig(); this overload re-validates it.
    // Returns false and reports `reason` (non-secret) on any problem, leaving
    // the controller unconfigured (onlineSupported() stays false).
    bool configureManagedRuntime(const Kanade::ManagedRuntimeConfig& config,
                                 QString* reason = nullptr);

    // Path-based variant used by the startup reader: loads, validates and
    // installs in one step.  Both the configuration file and the sidecar
    // executable must live under `approvedRoot` (an absolute D: directory with
    // no reparse point).
    bool configureManagedRuntimeFromFile(const QString& approvedRoot,
                                         const QString& configFilePath,
                                         QString* reason = nullptr);

    // C++-only test seam: a fully validated plan without file I/O.
    bool configureManagedRuntimeForTesting(const Kanade::ManagedRuntimeConfig& config,
                                           QString* reason = nullptr);

#ifdef KANADE_CONTROLLER_TEST
    // Test-only: install a QSslConfiguration that trusts ONLY the synthetic
    // test CA (tests/kanade_control/fixtures).  Verification itself stays on;
    // this never adds anything to the OS trust store and does not exist in
    // production builds (the macro is defined only by the test project).
    void setSslConfigurationForTesting(const QSslConfiguration& configuration);
#endif

signals:
    void stateChanged();
    void devicesChanged();
    void pairStateChanged();
    void errorCodeChanged();

    // Managed online session.
    void onlineChanged();
    void onlineLeaseChanged();
    void onlineReadyChanged();

    // Native managed path (QML-facing).
    void nativeChanged();
    void nativeAppsChanged();

    // Emitted before ANY operation that can handle a credential (a login
    // attempt, valid or not, and the explicit disableCredentialDumps() call).
    // The embedding application connects this directly to a sticky, per-process
    // switch that stops crash-dump creation.  Nothing else is implied: it does
    // not abort, does not log, and has no effect on processes that never start
    // a login.
    void sensitiveOperationStarted();

private:
    struct PendingPair {
        QString requestId;
        QString idempotencyKey;
        QString code;
        QString method;
        qint64 expiresAt = 0; // server epoch seconds
    };

    static QString originString(const QUrl& origin);

    void createApiIfNeeded();
    void endSession(bool remoteBestEffort);
    void setErrorCode(const QString& code);
    void setPairState(const QString& state);
    void setDevices(QVariantList devices);

    // True only while this generation and origin still own the session; every
    // async continuation re-checks it before touching state.
    bool isCurrent(quint64 generation, const QUrl& origin) const;
    void beginOp(quint64 generation);
    void endOp(quint64 generation);

    void afterLogin(const QJsonObject& tokenPair, quint64 generation, const QUrl& origin);
    void verifyMe(quint64 generation, const QUrl& origin);
    void prepareIdentity(quint64 generation, const QUrl& origin);
    void beginEnrollment(quint64 generation, const QUrl& origin,
                         const Kanade::InstallationIdentity& identity);
    void beginDeviceLogin(quint64 generation, const QUrl& origin,
                          const Kanade::InstallationIdentity& identity);
    void adoptDeviceTokens(const QJsonObject& tokenPair, quint64 generation, const QUrl& origin,
                           const Kanade::InstallationIdentity& identity);
    void loadDevices(quint64 generation, const QUrl& origin);

    void handlePairSnapshot(const QJsonObject& snapshot, quint64 generation, const QUrl& origin);
    void stopPairPoll();
    void onPairPollTimeout();

    // Managed online session plumbing.
    void teardownOnline(bool remoteBestEffort, Kanade::KanadeSession::StopReason reason);
    void pullOnlineState();
    void setOnlineErrorCode(const QString& code);
    void onOnlineAuthorized();
    void onOnlineActivationConfirmed();
    void onSidecarChannel(const QByteArray& exporter);
    void onSidecarReady();
    void onSidecarFault(const QString& reason);
    void onSidecarStopped();
    // Declared unconditionally: the definitions in kanadecontroller.cpp carry
    // their own KANADE_CONTROL_PLANE_TEST_ONLY no-op bodies (the fixture has no
    // native path), and unconditional call sites (onOnlineAuthorized,
    // onOnlineActivationConfirmed, the native worker completions) reference
    // them in every build configuration.  Only the state they touch beyond the
    // no-op branch lives behind the macro.
    void bindNativeRun();
    void bindNativeReady();
    void applyPendingNativeRevoke();
    // Declared unconditionally: `Kanade::NativeReason` comes from the
    // always-included, header-only managednative.h, and teardown paths reference
    // this even in a headless fixture (where it is a no-op with a Q_UNUSED body).
    void revokeNative(Kanade::NativeReason reason);

    // Native bridge plumbing.
    bool nativeAvailable() const;
    void setNativeState(const QString& pairingState, bool busy, const QString& errorCode);
    void resetNativeBridge(const QString& pairingState);
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    struct NativePairResult {
        bool ok = false;
        bool pinWrong = false;
        QString reason;
    };
    struct NativeAppEntry {
        QString appId;
        QString name;
    };
    struct NativeAppListResult {
        bool ok = false;
        QString reason;
        QList<NativeAppEntry> apps;
        QList<NvApp> appsNative;
    };
#endif
    void failOnline(const QString& errorCode, Kanade::KanadeSession::StopReason reason);
    void onLeaseTick();
    // Exact owner check for a selected device row (never trusts QML input).
    bool selectedRowMatchesRuntime(const QString& grantId, const QString& hostId) const;

    QString identityRoot() const;

    // Serializes this installation's identity file work.  A second login
    // generation must not run a concurrent load->generate->save against the same
    // (origin, user) file: that could persist a key whose peer write then loses,
    // leaving the server enrolled for a key we no longer hold.  One dedicated
    // worker thread means load/save/forget never interleave and never touch the
    // UI thread.  Workers capture value copies only.
    QThreadPool m_identityPool;

    std::unique_ptr<KanadeApi> m_api;
    std::shared_ptr<Kanade::IdentityStore> m_store;
    QTimer m_pairPollTimer;

    QString m_approvedRoot;
    bool m_supported = false;
    bool m_authenticated = false;
    int m_busy = 0;
    quint64 m_generation = 0;

    QString m_errorCode;
    QString m_userId;
    QString m_installationId;
    QVariantList m_devices;

    PendingPair m_pending;
    QString m_pairState;

    // --- Managed online session ---------------------------------------------
    bool m_runtimeConfigured = false;
    Kanade::ManagedRuntimeConfig m_runtime;
    std::unique_ptr<Kanade::KanadeApiTransport> m_onlineTransport;
    std::unique_ptr<Kanade::KanadeSession> m_onlineSession;
    std::unique_ptr<Kanade::KanadeSidecar> m_sidecar;
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    // shared_ptr, not unique_ptr: a pool worker that is mid-exchange keeps the
    // object alive and works on THAT instance, so a later run can never be
    // touched by an earlier task's completion.  Destruction is therefore
    // deferred to the last reference instead of racing the worker.
    std::shared_ptr<Kanade::ManagedNativeController> m_native;
    // A copy of this run's thread-safe lease guard, taken at bind time.  It lets
    // any fail-closed path revoke the lease window SYNCHRONOUSLY without waiting
    // for m_nativeMutex (which a worker may hold across network I/O).
    std::shared_ptr<Kanade::LiveLeaseGuard> m_nativeGuard;
    QPointer<QObject> m_issuedNativeStream;
#endif // KANADE_CONTROL_PLANE_TEST_ONLY
    // The lease watchdog runs for every online attempt, including a headless
    // control-plane fixture, so it is NOT part of the native-only block above.
    QTimer m_leaseTimer;

    QString m_onlineErrorCode;
    QString m_onlineGrantId;
    QString m_onlineHostId;
    QString m_onlineRunId;
    QString m_onlineExporterWire; // cached canonical base64url of the exporter
    bool m_onlineReady = false;
    bool m_onlineIpcVerified = false;
    quint64 m_onlineIpcSequence = 0;
    bool m_sidecarAuthorized = false;
    quint64 m_onlineRunGeneration = 0;
    bool m_dumpsSuppressed = false;

    // Native bridge state (QML-facing, non-secret).
    QString m_nativePairingState = QStringLiteral("unavailable");
    QVariantList m_nativeApps;
    bool m_nativeBusy = false;
    QString m_nativePin;
    QString m_nativeErrorCode;
    // Pinned host application version for the native PIN exchange, taken from
    // the bootstrap manifest; never a QML-supplied value.
    QString m_nativeHostAppVersion;
    // Guarded by `m_nativeOpGeneration`: a late native task (pair/applist) that
    // started before a stop/revoke must not apply its result.
    quint64 m_nativeOpGeneration = 0;
#ifndef KANADE_CONTROL_PLANE_TEST_ONLY
    // The full NvApp objects behind m_nativeApps.  QML only sees appId/name; the
    // native session needs the object, and it must be one we fetched.
    QList<NvApp> m_nativeAppObjects;
    // The native controller performs blocking network I/O and is NOT internally
    // thread-safe: the GUI thread and the pool worker that runs pair/applist
    // must never touch it at the same time.  Every access takes this mutex.
    mutable QMutex m_nativeMutex;
    // A revoke requested while a worker held m_nativeMutex (blocking I/O) is
    // deferred here instead of blocking the UI; the worker's completion applies
    // it immediately.  UI-thread only.
    bool m_pendingNativeRevoke = false;
    Kanade::NativeReason m_pendingNativeRevokeReason = Kanade::NativeReason::Stopped;
#endif
    // The seed of the identity that is currently authenticated, kept in this
    // object only for the duration of the online attempt so the activation can
    // be signed without a second DPAPI read.  Cleared on logout/endSession.
    QByteArray m_onlineSeed;
    int m_onlineClientKeyVersion = 0;
};

#endif // KANADECONTROLLER_H
