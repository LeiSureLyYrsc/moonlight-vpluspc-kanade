#include "managednativecontroller.h"

#include "backend/nvhttp.h"
#include "backend/nvpairingmanager.h"
#include "streaming/session.h"

#include <QDebug>

// Out-of-line half of the managed native controller.  Everything here is
// single-run and fail-closed: each method re-checks the gate immediately before
// acting, and no method retries, follows a redirect or falls back to an
// unmanaged path.

namespace Kanade {

bool ManagedNativeController::fetchPairingBootstrap(QString* hostAppVersionOut,
                                                   QString* reasonOut)
{
    if (hostAppVersionOut == nullptr) {
        refuse(reasonOut, NativeReason::ContextInvalid, "output string is required");
        return false;
    }
    if ((m_state != State::Bound && m_state != State::Ready) || !m_gate || !m_context) {
        refuse(reasonOut, NativeReason::NotArmed,
               "the pairing bootstrap requires a bound or ready runtime");
        return false;
    }
    if (!m_cert.isNull()) {
        refuse(reasonOut, NativeReason::AlreadyArmed,
               "a managed certificate is already pinned; no re-pairing");
        return false;
    }

    ManagedNativePolicy policy;
    policy.endpoint = pinnedManagedEndpoint();
    policy.gate = m_gate;
    policy.runGeneration = m_gate->runGeneration();
    policy.call = NativeCall::PairCert;

    try {
        NvHTTP http(policy, QSslCertificate());
        const QString serverInfo = http.getManagedPairingBootstrap();
        const QString appVersion = NvHTTP::getXmlString(serverInfo, "appversion");
        if (appVersion.isEmpty()) {
            refuse(reasonOut, NativeReason::ContextInvalid,
                   "managed host did not report an app version");
            return false;
        }
        *hostAppVersionOut = appVersion;
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }
    catch (const std::exception&) {
        refuse(reasonOut, NativeReason::CallNotPermitted, "managed pairing bootstrap failed");
        return false;
    }
}

bool ManagedNativeController::pairWithPin(const QString& hostAppVersion, const QString& pin,
                                         bool* pinWrong, QString* reasonOut)
{
    if (pinWrong) {
        *pinWrong = false;
    }
    // Pairing is permitted while Bound OR Ready: a runtime may report `ready`
    // before a native certificate exists yet (the Go side only guarantees that
    // game ports are bound at `ready`, not that pairing happened first).  The
    // gate itself still enforces a live lease and the PairCert/Pair slots.
    if ((m_state != State::Bound && m_state != State::Ready) || !m_gate || !m_lease
        || !m_context) {
        refuse(reasonOut, NativeReason::NotArmed,
               "native PIN pairing requires a bound or ready runtime");
        return false;
    }
    if (m_certAdopted || !m_cert.isNull()) {
        refuse(reasonOut, NativeReason::AlreadyArmed,
               "a managed certificate is already set for this run; a replaced certificate is "
               "never re-paired automatically");
        return false;
    }
    if (pin.isEmpty()) {
        refuse(reasonOut, NativeReason::ContextInvalid, "PIN must not be empty");
        return false;
    }
    if (m_lease && !m_lease->isLive(managedMonotonicNowMs())) {
        failNow(m_lease->deadReason() == NativeReason::Ok ? NativeReason::LeaseExpired
                                                          : m_lease->deadReason());
        if (reasonOut) {
            *reasonOut = m_failureReason;
        }
        return false;
    }

    ManagedNativePolicy policy;
    policy.endpoint = pinnedManagedEndpoint();
    policy.gate = m_gate;
    policy.runGeneration = m_gate->runGeneration();
    policy.call = NativeCall::PairCert;

    try {
        QString observedVersion;
        if (!fetchPairingBootstrap(&observedVersion, reasonOut) || observedVersion != hostAppVersion ||
            observedVersion != QStringLiteral("7.1.431.-1")) {
            return refuse(reasonOut, NativeReason::ContextInvalid, "unexpected native host version");
        }
        NvPairingManager pairing(policy, QSslCertificate());
        QSslCertificate serverCert;
        const NvPairingManager::PairState state = pairing.pair(hostAppVersion, pin, serverCert);
        switch (state) {
        case NvPairingManager::PAIRED:
            if (serverCert.isNull()) {
                refuse(reasonOut, NativeReason::ContextInvalid,
                       "pairing reported success without a certificate");
                return false;
            }
            m_cert = serverCert;
            m_certAdopted = true;
            if (reasonOut) {
                reasonOut->clear();
            }
            return true;
        case NvPairingManager::PIN_WRONG:
            if (pinWrong) {
                *pinWrong = true;
            }
            refuse(reasonOut, NativeReason::CallNotPermitted, "native pairing rejected the PIN");
            return false;
        case NvPairingManager::ALREADY_IN_PROGRESS:
            refuse(reasonOut, NativeReason::CallNotPermitted,
                   "managed host is already pairing");
            return false;
        case NvPairingManager::FAILED:
        default:
            refuse(reasonOut, NativeReason::CallNotPermitted, "native pairing failed");
            return false;
        }
    }
    catch (const std::exception&) {
        // Never surface a certificate, PIN or stage payload.
        refuse(reasonOut, NativeReason::CallNotPermitted, "native pairing failed");
        return false;
    }
}

bool ManagedNativeController::fetchAppList(QList<NvApp>* appsOut, QString* reasonOut)
{
    if ((m_state != State::Bound && m_state != State::Ready) || !m_gate || !m_context) {
        refuse(reasonOut, NativeReason::NotArmed,
               "native applist requires a bound or ready runtime");
        return false;
    }
    if (appsOut == nullptr) {
        refuse(reasonOut, NativeReason::ContextInvalid, "output list is required");
        return false;
    }
    // Also enforces a live lease at this instant.
    if (!requireLiveCertificate(reasonOut, "native applist requires a pinned certificate")) {
        return false;
    }

    ManagedNativePolicy policy;
    policy.endpoint = pinnedManagedEndpoint();
    policy.gate = m_gate;
    policy.runGeneration = m_gate->runGeneration();
    policy.call = NativeCall::AppList;

    try {
        NvHTTP http(policy, m_cert);
        *appsOut = http.getAppList();
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }
    catch (const std::exception&) {
        refuse(reasonOut, NativeReason::CallNotPermitted, "native applist failed");
        return false;
    }
}

bool ManagedNativeController::runtimeReady(const ReadyProof& proof, QString* reasonOut)
{
    // A `ready` proof does NOT imply a native certificate exists: the runtime
    // guarantees only that its game ports are bound and the peer transport is
    // up.  Native pairing/applist may still be pending, so this step never
    // requires a certificate.  createSession() is where the certificate becomes
    // mandatory.
    if (m_state != State::Bound || !m_gate) {
        refuse(reasonOut, NativeReason::NotArmed,
               "a ready proof is only accepted from a bound runtime");
        return false;
    }
    const NativeResult result = m_gate->markReady(proof, managedMonotonicNowMs());
    if (!result.ok()) {
        failNow(result.reason);
        if (reasonOut) {
            *reasonOut = m_failureReason;
        }
        return false;
    }
    m_failureReason.clear();
    setState(State::Ready, QString());
    if (reasonOut) {
        reasonOut->clear();
    }
    return true;
}

Session* ManagedNativeController::createSession(NvApp& app, StreamingPreferences* preferences,
                                               QString* reasonOut)
{
    if (m_state != State::Ready || !m_gate || !m_lease || !m_context) {
        refuse(reasonOut, NativeReason::NotReady,
               "a managed session requires a verified ready runtime");
        return nullptr;
    }
    if (m_cert.isNull()) {
        refuse(reasonOut, NativeReason::ContextInvalid,
               "a managed session requires a pinned certificate");
        return nullptr;
    }
    if (!m_gate->canOpenManagedStream(managedMonotonicNowMs())) {
        // Covers both a dead/expired lease and the missing common-c pre-send
        // patch: no stream object is created in either case.
        refuse(reasonOut, NativeReason::PresendHookUnavailable,
               "this build cannot open a managed stream (pre-send validator or lease unavailable)");
        return nullptr;
    }
    if (!requireLiveCertificate(reasonOut, "a managed session requires a pinned certificate")) {
        return nullptr;
    }

    ManagedNativeStream stream;
    stream.context = *m_context;
    stream.endpoint = pinnedManagedEndpoint();
    stream.lease = m_lease;
    stream.gate = m_gate;
    stream.serverCert = m_cert; // ephemeral for this run only
    stream.hostName = m_hostName.isEmpty() ? QStringLiteral("Kanade") : m_hostName;

    if (!stream.valid()) {
        refuse(reasonOut, NativeReason::ContextInvalid, "managed stream bundle is invalid");
        return nullptr;
    }

    // State stays Ready: creating the Session does not change the gate state,
    // and a second transition here would emit a spurious stateChanged.
    if (reasonOut) {
        reasonOut->clear();
    }
    return new Session(stream, app, preferences);
}

bool ManagedNativeController::renewLease(qint64 newDeadlineMs, QString* reasonOut)
{
    if (!m_lease || !m_context) {
        refuse(reasonOut, NativeReason::LeaseMissing, "no managed lease is held");
        return false;
    }
    NativeResult why;
    if (!m_lease->extend(managedMonotonicNowMs(), newDeadlineMs, m_context->runGeneration(),
                         m_context->sessionId(), &why)) {
        // A failed renewal leaves the gate untouched; expiry is enforced by the
        // guard itself, so the caller must treat this as "do not contact again".
        failNow(why.reason);
        if (reasonOut) {
            *reasonOut = m_failureReason;
        }
        return false;
    }
    if (reasonOut) {
        reasonOut->clear();
    }
    return true;
}

void ManagedNativeController::stop()
{
    if (m_state == State::Stopped || m_state == State::Failed) {
        return;
    }
    if (!m_gate || !m_context) {
        setState(State::Stopped, QString());
        return;
    }

    const qint64 now = managedMonotonicNowMs();
    NativeResult why;
    if (!m_gate->beginStop(now, &why)) {
        setState(State::Stopped, QString());
        return;
    }

    setState(State::Stopping, QString());

    try {
        ManagedNativePolicy policy;
        policy.endpoint = pinnedManagedEndpoint();
        policy.gate = m_gate;
        policy.runGeneration = m_context->runGeneration();
        policy.call = NativeCall::Quit;

        NvHTTP http(policy, m_cert);
        http.quitApp();
    }
    catch (const std::exception&) {
        // Best effort; the gate is closed below regardless.
    }

    m_gate->finishStop();
    if (m_lease) {
        m_lease->revoke(NativeReason::Stopped);
    }
    setState(State::Stopped, QString());
}

void ManagedNativeController::revoke(NativeReason reason)
{
    if (m_state == State::Stopped || m_state == State::Failed) {
        return;
    }
    if (m_gate) {
        m_gate->revoke(reason);
    }
    if (m_lease) {
        m_lease->revoke(reason);
    }
    setState(State::Failed, nativeReasonToString(reason));
    m_failureReason = nativeReasonToString(reason);
}

QString ManagedNativeController::sessionId() const
{
    return m_context ? m_context->sessionId() : QString();
}

quint64 ManagedNativeController::runGeneration() const
{
    return m_context ? m_context->runGeneration() : 0;
}

bool ManagedNativeController::streamingReady() const
{
    return m_gate && m_gate->canOpenManagedStream(managedMonotonicNowMs());
}

qint64 ManagedNativeController::leaseRemainingMs() const
{
    if (!m_lease) {
        return 0;
    }
    const LiveLeaseSnapshot lease = m_lease->snapshot(managedMonotonicNowMs());
    return lease.live ? qMax<qint64>(0, lease.deadlineMs - managedMonotonicNowMs()) : 0;
}

} // namespace Kanade
