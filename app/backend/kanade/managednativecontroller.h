#pragma once

#ifndef MANAGEDNATIVECONTROLLER_H
#define MANAGEDNATIVECONTROLLER_H

#include <QList>
#include <QSslCertificate>
#include <QString>

#include <functional>
#include <memory>
#include <optional>

#include "managednative.h"
// QList<NvApp> is used in the public signature below, so NvApp must be a complete
// type here (a forward declaration is not enough for QList's inline storage).
#include "backend/nvapp.h"

class Session;
class StreamingPreferences;

// Product-facing integration of the managed native path.
//
// This is the ONE object the controller lane (the QML `KanadeController`) calls
// to turn an already-validated Kanade session into native host operations.  It
// owns the shared lease guard and the gate; it never owns an account credential,
// a token, a ticket or a PIN.
//
// Deliberately NOT a QObject: the controller lane already has one and owns the
// QML-visible `onlineState` enum.  This class reports transitions through a
// callback so it stays header-only (no moc registration, no project-file edit)
// and cannot accidentally become a second source of UI truth.
//
// Call order (every step fails closed, nothing retries):
//   1. begin(context)                       -> Idle -> WaitingForRuntime
//   2. runtimeBound(binding)                -> gate.arm(); discovery/pairing open
//   3a. fetchPairingBootstrap(&appVersion)  -> first pair only; narrow plaintext
//   3b. pairWithPin(appVersion, pin, ...)   -> optional native PIN exchange
//   4. fetchAppList(apps)                   -> native applist
//   5. runtimeReady(proof)                  -> gate.markReady(); stream may build
//   6. createSession(app, prefs, &out)      -> returns a managed Session
//   7. tickLease(deadlineMs)                -> 1 s watchdog observation; a
//                                              repeated deadline is "no news",
//                                              not a failure (renewLease stays
//                                              the strict extension primitive)
//   8. stop() / revoke(reason)              -> terminal
//
// EXACT NATIVE OPERATIONS the runtime/controller must be able to serve, all on
// 127.0.0.1 only (47989 HTTP, 47984 HTTPS, RTSP 48010 arriving later via the
// sidecar's own mapping):
//   GET  /serverinfo   HTTPS, pinned cert, exactly one canonical HttpsPort=47984
//   GET  /serverinfo   HTTP  - ONLY the first-pair bootstrap, before any pin
//   GET  /pair         HTTP  - GameStream pairing stages 1..4 (PIN challenge,
//                              server challenge response, client secret)
//   GET  /pair         HTTPS - stage 5 pairchallenge
//   GET  /applist      HTTPS
//   GET  /launch|/resume HTTPS, plus strict rtspenc://127.0.0.1:48010 reply
//   GET  /cancel       HTTPS - explicit managed stop only
// Nothing else is ever requested by this client, and no operation is retried.
//
// Everything is single-run: after stop()/revoke() a new begin() with a new
// context is required.  streamingReady() is NOT a UI "connected" state - it
// means "the typed gate would permit a native launch right now".
namespace Kanade {

class ManagedNativeController {
public:
    enum class State {
        Idle,               // no context
        WaitingForRuntime,  // context accepted; waiting for the verified binding
        Bound,              // runtime owns the listeners; discovery/pairing open
        Ready,              // runtime reports ready; launch allowed if hook exists
        Stopping,
        Stopped,
        Failed
    };

    // Called on every state transition, on the calling thread only.  `reason` is
    // a stable non-secret string (empty unless the state is Failed).
    using StateCallback = std::function<void(State state, const QString& reason)>;

    ManagedNativeController() = default;

    void setStateCallback(StateCallback callback) { m_onState = std::move(callback); }

    State state() const { return m_state; }
    // Stable, non-secret reason for the last failure (empty when not Failed).
    QString failureReason() const { return m_failureReason; }

    QString sessionId() const;
    quint64 runGeneration() const;

    // True only when a native launch would be permitted *right now*: gate Ready,
    // live lease and the reviewed common-c port-policy patch present.  Never a
    // substitute for the controller's own `onlineState`.
    bool streamingReady() const;
    qint64 leaseRemainingMs() const;
    // The owning runtime may invalidate this independent thread-safe gate
    // synchronously even while a native HTTP worker is blocked.
    std::shared_ptr<LiveLeaseGuard> leaseGuard() const { return m_lease; }

    // Display name only; never a dial target.
    QString hostDisplayName() const { return m_hostName; }

    // Display name supplied by the controller's verified device snapshot.  It is
    // never a dial target and never derived from an address or UUID.
    void setHostDisplayName(const QString& name)
    {
        m_hostName = name.left(128); // bounded: display-only field
    }

    // The ephemeral native certificate for this run.  Null until a successful
    // pairWithPin()/adoptEphemeralCertificate().  NEVER persisted, never merged
    // into a host store, and not a durable pin.
    QSslCertificate ephemeralCertificate() const { return m_cert; }

    // Step 1.  Requires a validated context; the guard is created here with the
    // context's confirmed deadline.  A context that is already past its deadline
    // fails here and the controller goes to Failed.
    bool begin(const ManagedEndpointContext& context, QString* reasonOut = nullptr)
    {
        if (m_state != State::Idle && m_state != State::Stopped && m_state != State::Failed) {
            return refuse(reasonOut, NativeReason::AlreadyArmed, "a managed run is already active");
        }

        NativeResult why;
        auto lease = LiveLeaseGuard::create(context.sessionId(), context.runGeneration(),
                                            context.confirmedDeadlineMs(),
                                            managedMonotonicNowMs(),
                                            ManagedEndpointContext::kLeaseTtlCapMs, &why);
        if (!lease) {
            m_failureReason = nativeReasonToString(why.reason);
            setState(State::Failed, m_failureReason);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }

        m_context = context;
        m_lease = lease;
        m_gate = std::make_shared<ManagedNativeGate>();
        m_cert = QSslCertificate();
        m_certAdopted = false;
        m_failureReason.clear();
        setState(State::WaitingForRuntime, QString());
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }

    // Origin-independent alternative to begin(): the caller supplies the time
    // remaining on its own already-confirmed lease (KanadeSession's
    // leaseRemainingMs()).  Prefer this when the caller's monotonic clock has a
    // different origin; only the interval is trusted and it is clamped to the
    // locally honoured cap.
    bool beginWithRemainingLease(const ManagedEndpointContext& context, qint64 remainingMs,
                                QString* reasonOut = nullptr)
    {
        if (remainingMs <= 0) {
            m_failureReason = nativeReasonToString(NativeReason::LeaseExpired);
            setState(State::Failed, m_failureReason);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }
        if (m_state != State::Idle && m_state != State::Stopped && m_state != State::Failed) {
            return refuse(reasonOut, NativeReason::AlreadyArmed, "a managed run is already active");
        }

        NativeResult why;
        auto lease = LiveLeaseGuard::createFromRemaining(context.sessionId(),
                                                         context.runGeneration(), remainingMs,
                                                         ManagedEndpointContext::kLeaseTtlCapMs,
                                                         &why);
        if (!lease) {
            m_failureReason = nativeReasonToString(why.reason);
            setState(State::Failed, m_failureReason);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }

        m_context = context;
        m_lease = lease;
        m_gate = std::make_shared<ManagedNativeGate>();
        m_cert = QSslCertificate();
        m_certAdopted = false;
        m_failureReason.clear();
        setState(State::WaitingForRuntime, QString());
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }

    // Step 2.  Supplies the verified runtime listen proof (from the sidecar's
    // authenticated `prepared`/listening frame).  Without it nothing is callable.
    bool runtimeBound(const RuntimeBinding& binding, QString* reasonOut = nullptr)
    {
        if (m_state != State::WaitingForRuntime || !m_context || !m_gate) {
            return refuse(reasonOut, NativeReason::AlreadyArmed,
                          "runtime binding is only accepted after begin()");
        }
        if (!m_lease) {
            return refuse(reasonOut, NativeReason::LeaseMissing, "no managed lease is held");
        }
        // The gate refuses a lease deadline AHEAD of the context it arms with.
        // Kanade confirms a later lease roughly every 30 s while the 1 s tick is
        // the only thing that advances the shared guard, so a confirmation can
        // land between two ticks.  Bring the context forward FIRST, using the
        // existing strict ManagedEndpointContext::renewed(): it rejects an
        // equal/lower deadline, a foreign run/session, an elapsed lease and an
        // over-cap span, so this can only ever follow a real confirmation.
        const LiveLeaseSnapshot lease = m_lease->snapshot(managedMonotonicNowMs());
        if (!lease.live) {
            failNow(lease.deadReason == NativeReason::Ok ? NativeReason::LeaseExpired
                                                         : lease.deadReason);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }
        if (lease.sessionId != m_context->sessionId()
            || lease.generation != m_context->runGeneration()) {
            failNow(NativeReason::LeaseGenerationMismatch);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }
        if (lease.deadlineMs > m_context->confirmedDeadlineMs()) {
            ValidationResult refreshWhy;
            const auto refreshed =
                m_context->renewed(lease.deadlineMs, managedMonotonicNowMs(),
                                   m_context->sessionId(), m_context->runGeneration(), refreshWhy);
            if (!refreshed) {
                // A confirmation that cannot be adopted is not a usable lease:
                // fail closed instead of arming on a context that disagrees with
                // the shared guard.
                failNow(NativeReason::LeaseDeadlineInvalid);
                if (reasonOut) {
                    *reasonOut = m_failureReason;
                }
                return false;
            }
            m_context = refreshed;
        }

        const NativeResult result = m_gate->arm(*m_context, m_lease, binding, managedMonotonicNowMs());
        if (!result.ok()) {
            failNow(result.reason);
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }
        m_failureReason.clear();
        setState(State::Bound, QString());
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }

    // Adopts a certificate the caller already pinned (e.g. a previous managed
    // run in the same process).  Refused once a certificate is set.
    bool adoptEphemeralCertificate(const QSslCertificate& certificate, QString* reasonOut = nullptr)
    {
        if (certificate.isNull()) {
            return refuse(reasonOut, NativeReason::ContextInvalid, "certificate is null");
        }
        if (m_certAdopted || !m_cert.isNull()) {
            return refuse(reasonOut, NativeReason::AlreadyArmed,
                          "a managed certificate is already set for this run");
        }
        m_cert = certificate;
        m_certAdopted = true;
        if (reasonOut) {
            reasonOut->clear();
        }
        return true;
    }

    // Step 3a (first pair only).  Read the managed first-pair bootstrap: the one
    // narrow plaintext `serverinfo` read permitted before a certificate exists.
    // Returns the host app version (for the pairing hash generation) and
    // validates that the host advertises the pinned HttpsPort.  The reply is
    // never retained as host state.  Refused once a certificate is pinned.
    bool fetchPairingBootstrap(QString* hostAppVersionOut, QString* reasonOut = nullptr);

    // Step 3b (optional).  Native PIN exchange against the pinned loopback
    // endpoint.  `pin` is used once and never logged or stored.  On success the
    // returned certificate is held as the ephemeral pin for this run.
    // Returns the native PairState via `pinWrong`.
    bool pairWithPin(const QString& hostAppVersion, const QString& pin, bool* pinWrong,
                     QString* reasonOut = nullptr);
    bool fetchAppList(QList<NvApp>* appsOut, QString* reasonOut = nullptr);
    bool runtimeReady(const ReadyProof& proof, QString* reasonOut = nullptr);
    Session* createSession(NvApp& app, StreamingPreferences* preferences,
                          QString* reasonOut = nullptr);

    // Step 7a.  Strict forward-only renewal from a confirmed lease response.
    // Rejects an equal/lower deadline: use tickLease() for the 1 s watchdog,
    // which treats a repeat as "no news" instead of a failure.
    bool renewLease(qint64 newDeadlineMs, QString* reasonOut = nullptr);

    // Step 7b.  The 1 s watchdog tick, fed the absolute deadline most recently
    // CONFIRMED by Kanade (KanadeSession::leaseDeadlineMonotonicMs()).
    //
    // The confirmed deadline only advances when the server confirms a later
    // lease (roughly every 30 s), while this is called every second, so an
    // unchanged deadline is the NORMAL case and MUST NOT fail the run.
    // LiveLeaseGuard::observe() therefore treats an equal deadline for a live,
    // matching run as a successful no-op while keeping every strict rule
    // (lower deadline, wrong identity, elapsed lease, cap violation, dead
    // guard) fail-closed.
    //
    // Defined inline so the offline fixture exercises this exact production
    // decision without linking NvHTTP/Session.
    bool tickLease(qint64 confirmedDeadlineMs, QString* reasonOut = nullptr)
    {
        if (!m_lease || !m_context) {
            // Plain "no lease held" read, not a death: a gate that needs a
            // lease already refuses through its own state.
            return refuse(reasonOut, NativeReason::LeaseMissing, "no managed lease is held");
        }
        // A tick after the run is already terminal must not resurrect anything.
        if (m_state == State::Failed || m_state == State::Stopped) {
            return refuse(reasonOut,
                          m_lease->deadReason() == NativeReason::Ok ? NativeReason::Stopped
                                                                   : m_lease->deadReason(),
                          "the managed run is already finished");
        }

        NativeResult why;
        if (!m_lease->observe(managedMonotonicNowMs(), confirmedDeadlineMs,
                              m_context->runGeneration(), m_context->sessionId(), &why)) {
            // Expired/revoked, a foreign run, a LOWER deadline, or an over-cap
            // confirmation: terminal and fail closed, exactly as a failed
            // extension was always treated.
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

    void stop();
    void revoke(NativeReason reason);

private:
    bool refuse(QString* reasonOut, NativeReason reason, const char* detail)
    {
        const QString text = QString::fromLatin1(detail);
        if (reasonOut) {
            *reasonOut = text;
        }
        return false;
    }

    void setState(State state, const QString& reason)
    {
        m_state = state;
        if (m_onState) {
            m_onState(state, reason);
        }
    }

    void failNow(NativeReason reason)
    {
        m_failureReason = nativeReasonToString(reason);
        if (m_gate) {
            m_gate->revoke(reason);
        }
        if (m_lease) {
            m_lease->revoke(reason);
        }
        setState(State::Failed, m_failureReason);
    }

    // Refuses when the certificate is absent or when the shared gate/lease is
    // no longer live.  Used by every method that would open a connection.
    bool requireLiveCertificate(QString* reasonOut, const char* detail)
    {
        if (m_cert.isNull()) {
            return refuse(reasonOut, NativeReason::ContextInvalid, detail);
        }
        if (m_lease && !m_lease->isLive(managedMonotonicNowMs())) {
            failNow(m_lease->deadReason() == NativeReason::Ok ? NativeReason::LeaseExpired
                                                              : m_lease->deadReason());
            if (reasonOut) {
                *reasonOut = m_failureReason;
            }
            return false;
        }
        return true;
    }

    State m_state = State::Idle;
    QString m_failureReason;
    StateCallback m_onState;

    std::optional<ManagedEndpointContext> m_context;
    std::shared_ptr<LiveLeaseGuard> m_lease;
    std::shared_ptr<ManagedNativeGate> m_gate;

    QSslCertificate m_cert;
    QString m_hostName;
    bool m_certAdopted = false;
};

} // namespace Kanade

#endif // MANAGEDNATIVECONTROLLER_H
