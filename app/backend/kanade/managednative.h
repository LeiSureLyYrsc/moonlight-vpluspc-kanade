#pragma once

#ifndef MANAGEDNATIVE_H
#define MANAGEDNATIVE_H

#include <QMutex>
#include <QMutexLocker>
#include <QSslCertificate>
#include <QString>

#include <chrono>
#include <memory>
#include <optional>

#include "managedendpoint.h"

// Include this at file scope: the header guard would otherwise hide the
// global policy type from Limelight.h when this header is included first.
#if defined(__has_include)
#  if __has_include(<ManagedPortPolicy.h>)
#    define KANADE_HAS_MANAGED_PORT_POLICY_HEADER 1
#    include <ManagedPortPolicy.h>
#  endif
#endif

// Kanade online-mode managed NATIVE gate (client side).
//
// This is the typed, single-owner gate between a verified managed runtime
// ("ready" proof from the sidecar/host lane) and reuse of the stock native
// objects (NvHTTP, NvPairingManager, Session, moonlight-common-c).
//
// Design constraints (plan 3.2/3.3, continuation prompt):
//
//   * One immutable ManagedEndpointContext per operation.  Everything the
//     native path may dial is derived from that context plus the pinned
//     loopback endpoint below - never from ComputerManager, NvComputer address
//     history, UUID merging, discovery or `activeAddress`.
//   * A SHARED LiveLeaseGuard carries the only deadline the native path
//     honours.  It is a conservative LOCAL MONOTONIC deadline: the owner
//     runtime may extend it forward from its own confirmed lease responses and
//     may revoke it permanently.  Nothing else (peer renewal, socket liveness,
//     UI state, wall clock) can move it, and nothing can extend it after it
//     elapsed or was revoked.
//   * After death (revocation, expiry, stop) the gate is terminal: no further
//     native call is permitted, ever, for that generation.  A new run needs a
//     new context, a new guard and a new gate.
//   * Launch/Resume/Stream stay closed until BOTH a verified `ready` proof is
//     presented AND common-c exposes the pre-send destination validator
//     (`presendValidatorAvailable()`).  Until that hook exists this class fails
//     closed with PresendHookUnavailable; it does not warn-and-continue.
//
// This module performs no I/O, owns no socket, reads no clock itself (every
// caller passes its trusted monotonic instant; managedMonotonicNowMs() is the
// one shared convenient source), and does not include Limelight.h.  It cannot
// make a stream happen; it can only refuse.  Header-only on purpose so the
// managed policy can be consumed without touching the application project
// file; there is no out-of-line state.
namespace Kanade {

// Stable, non-secret failure classification (safe to log verbatim).
enum class NativeReason {
    Ok = 0,

    ContextInvalid,

    // Endpoint / packet policy
    EndpointHostNotPinned,
    EndpointPortNotPinned,
    PacketSizeNotSupported,

    // Gate lifecycle
    NotArmed,
    NotReady,
    AlreadyArmed,
    AlreadyDead,
    Stopping,
    AlreadyStopping,
    Stopped,
    Dead,
    CallNotPermitted,
    PresendHookUnavailable,

    // Lease guard
    LeaseMissing,
    LeaseInvalid,
    LeaseDeadlineInvalid,
    LeaseExpired,
    LeaseRevoked,
    LeaseSessionMismatch,
    LeaseGenerationMismatch,
    LeaseNotExtended,

    // Ready proof
    ReadyProofUnverified,
    ReadyProofSessionMismatch,
    ReadyProofGenerationMismatch,
    ReadyProofTransportMismatch,
    ReadyProofDeadlineInvalid,
    ReadyProofReplay,
    RunGenerationInvalid,

    // Verified runtime binding (listen proof; see RuntimeBinding)
    RuntimeBindingUnverified,
    RuntimeBindingSessionMismatch,
    RuntimeBindingGenerationMismatch,
    RuntimeBindingDeadlineInvalid
};

inline QString nativeReasonToString(NativeReason reason)
{
    switch (reason) {
    case NativeReason::Ok: return QStringLiteral("ok");
    case NativeReason::ContextInvalid: return QStringLiteral("context_invalid");
    case NativeReason::EndpointHostNotPinned: return QStringLiteral("endpoint_host_not_pinned");
    case NativeReason::EndpointPortNotPinned: return QStringLiteral("endpoint_port_not_pinned");
    case NativeReason::PacketSizeNotSupported: return QStringLiteral("packet_size_not_supported");
    case NativeReason::NotArmed: return QStringLiteral("not_armed");
    case NativeReason::NotReady: return QStringLiteral("not_ready");
    case NativeReason::AlreadyArmed: return QStringLiteral("already_armed");
    case NativeReason::AlreadyDead: return QStringLiteral("already_dead");
    case NativeReason::Stopping: return QStringLiteral("stopping");
    case NativeReason::AlreadyStopping: return QStringLiteral("already_stopping");
    case NativeReason::Stopped: return QStringLiteral("stopped");
    case NativeReason::Dead: return QStringLiteral("dead");
    case NativeReason::CallNotPermitted: return QStringLiteral("call_not_permitted");
    case NativeReason::PresendHookUnavailable: return QStringLiteral("presend_hook_unavailable");
    case NativeReason::LeaseMissing: return QStringLiteral("lease_missing");
    case NativeReason::LeaseInvalid: return QStringLiteral("lease_invalid");
    case NativeReason::LeaseDeadlineInvalid: return QStringLiteral("lease_deadline_invalid");
    case NativeReason::LeaseExpired: return QStringLiteral("lease_expired");
    case NativeReason::LeaseRevoked: return QStringLiteral("lease_revoked");
    case NativeReason::LeaseSessionMismatch: return QStringLiteral("lease_session_mismatch");
    case NativeReason::LeaseGenerationMismatch: return QStringLiteral("lease_generation_mismatch");
    case NativeReason::LeaseNotExtended: return QStringLiteral("lease_not_extended");
    case NativeReason::ReadyProofUnverified: return QStringLiteral("ready_proof_unverified");
    case NativeReason::ReadyProofSessionMismatch: return QStringLiteral("ready_proof_session_mismatch");
    case NativeReason::ReadyProofGenerationMismatch: return QStringLiteral("ready_proof_generation_mismatch");
    case NativeReason::ReadyProofTransportMismatch: return QStringLiteral("ready_proof_transport_mismatch");
    case NativeReason::ReadyProofDeadlineInvalid: return QStringLiteral("ready_proof_deadline_invalid");
    case NativeReason::ReadyProofReplay: return QStringLiteral("ready_proof_replay");
    case NativeReason::RunGenerationInvalid: return QStringLiteral("run_generation_invalid");
    case NativeReason::RuntimeBindingUnverified: return QStringLiteral("runtime_binding_unverified");
    case NativeReason::RuntimeBindingSessionMismatch: return QStringLiteral("runtime_binding_session_mismatch");
    case NativeReason::RuntimeBindingGenerationMismatch: return QStringLiteral("runtime_binding_generation_mismatch");
    case NativeReason::RuntimeBindingDeadlineInvalid: return QStringLiteral("runtime_binding_deadline_invalid");
    }
    return QStringLiteral("unknown");
}

struct NativeResult {
    NativeReason reason = NativeReason::Ok;
    QString detail; // fixed, non-secret English text owned by this module

    bool ok() const { return reason == NativeReason::Ok; }
};

// The one shared trusted monotonic source for the managed path (milliseconds).
//
// On Windows this is GetTickCount64(), i.e. the SAME absolute clock origin the
// managed sidecar contract already uses (`KanadeSidecar::start(...,
// absoluteDeadlineMs)` / `renewLease(...)`), so a deadline minted from a sidecar
// authorization or a KanadeSession confirmation can be compared here without
// any conversion.  Elsewhere a fixed steady_clock origin is used.  It is never
// wall-clock time and never moves backwards, so a system-time change cannot
// reopen the gate.
#if defined(Q_OS_WIN)
// Declared here rather than including <windows.h> from a header that must stay
// usable from pure-QtCore targets.  If <windows.h> is already in this TU, its
// declaration is used instead: a second declaration of the same signature with
// a different dllimport spelling is not portable across MSVC modes.
#  ifndef _WINBASE_
extern "C" __declspec(dllimport) unsigned long long __stdcall GetTickCount64(void);
#  endif
#endif

inline qint64 managedMonotonicNowMs()
{
#if defined(Q_OS_WIN)
    return static_cast<qint64>(GetTickCount64());
#else
    using Clock = std::chrono::steady_clock;
    static const Clock::time_point origin = Clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - origin).count();
#endif
}

// ---------------------------------------------------------------------------
// common-c pre-send port policy (owner-settled ABI, final)
// ---------------------------------------------------------------------------
//
// src/ManagedPortPolicy.h:
//   typedef struct _LI_MANAGED_PORT_POLICY {
//       int enable;
//       uint16_t videoPort, controlPort, audioPort;
//       bool (*isLive)(void*);   // non-capturing, noexcept
//       void* context;           // valid from start through LiStopConnection
//   } LI_MANAGED_PORT_POLICY;
//
//   int LiStartConnectionWithPortPolicy(PSERVER_INFORMATION, PSTREAM_CONFIGURATION,
//       PCONNECTION_LISTENER_CALLBACKS, PDECODER_RENDERER_CALLBACKS,
//       PAUDIO_RENDERER_CALLBACKS, void*, int, void*, int,
//       const LI_MANAGED_PORT_POLICY*);
//
// Managed path MUST pass a non-NULL policy; a NULL policy on the managed path is
// rejected by this client before the call.  Ordinary LAN keeps calling plain
// LiStartConnection() only.

// Owner sets this once the callback is part of the built struct.  Both the
// header AND this macro are required; either alone keeps the path closed, and
// nothing here is hardcoded to "true".
#if defined(KANADE_HAS_MANAGED_PORT_POLICY_HEADER) \
    && defined(LI_MANAGED_PORT_POLICY_HAS_PRESEND_CALLBACK)
#  define KANADE_PRESEND_VALIDATOR_AVAILABLE 1
#endif

// Locked media/control UDP group of the managed path (plan 3.2).  The order is
// NOT interchangeable: foundation-sunshine src/stream.h:32-34 defines
//   VIDEO_STREAM_PORT = 9, CONTROL_PORT = 10, AUDIO_STREAM_PORT = 11
// over the 47989 base, i.e. VIDEO=47998, CONTROL=47999, AUDIO=48000.  The
// reviewed common-c patch rejects a policy whose ports do not match, so these
// constants must stay in exactly this mapping.  48001 is never represented, and
// 47990 is a TCP management port, not part of this policy.
constexpr quint16 kManagedVideoUdpPort = 47998;
constexpr quint16 kManagedControlUdpPort = 47999;
constexpr quint16 kManagedAudioUdpPort = 48000;

// State the callback needs.  Declared here (after LiveLeaseGuard below) - the
// bridge and the ABI callback are defined further down, once LiveLeaseGuard and
// LiveLeaseSnapshot are complete, because the callback calls snapshot().
// `context` must stay valid from LiStartConnectionWithPortPolicy() until
// LiStopConnection(): the Session owns it as a member.

// True only when the reviewed common-c patch is really part of this build.
inline bool managedPortPolicyAvailable()
{
#if defined(KANADE_PRESEND_VALIDATOR_AVAILABLE)
    return true;
#else
    return false;
#endif
}

// The exact loopback data-path endpoint the managed native client may use.
// httpPort/httpsPort are the locked defaults (47989/47984); 47990 and 48001
// are never represented here.
struct NativeEndpoint {
    QString host;
    quint16 httpPort = 0;
    quint16 httpsPort = 0;
};

inline NativeEndpoint pinnedManagedEndpoint()
{
    NativeEndpoint endpoint;
    endpoint.host = ManagedEndpointContext::loopbackHost();
    endpoint.httpPort = ManagedEndpointContext::kManagedHttpPort;
    endpoint.httpsPort = ManagedEndpointContext::kManagedHttpsPort;
    return endpoint;
}

inline bool isPinnedManagedEndpoint(const QString& host, quint16 port)
{
    if (host != ManagedEndpointContext::loopbackHost()) {
        return false;
    }
    return port == ManagedEndpointContext::kManagedHttpPort
        || port == ManagedEndpointContext::kManagedHttpsPort;
}

// Managed packet size policy.  The native default (0 == "use 1392") and an
// explicit 1392 are the ONLY accepted values.  A 1024 downgrade is never
// implied, clamped or silently applied: it must stay a decision backed by
// measured evidence and explicit user consent, and today it is simply refused.
constexpr int kManagedPacketSize = 1392;

inline bool checkManagedPacketSize(int packetSize, NativeResult* reason = nullptr)
{
    if (packetSize == 0 || packetSize == kManagedPacketSize) {
        if (reason) {
            reason->reason = NativeReason::Ok;
            reason->detail.clear();
        }
        return true;
    }
    if (reason) {
        reason->reason = NativeReason::PacketSizeNotSupported;
        reason->detail = QStringLiteral(
            "packet size is not the managed default; 1024 requires measured evidence "
            "and explicit consent and is not implied here");
    }
    return false;
}

inline int managedPacketSize()
{
    return kManagedPacketSize;
}

// Snapshot of the shared lease.  `epoch` increases on every accepted extension
// and on revocation, so a caller can detect that the guard moved underneath it.
struct LiveLeaseSnapshot {
    bool live = false;
    qint64 deadlineMs = -1;
    quint64 generation = 0;
    QString sessionId;
    quint64 epoch = 0;
    NativeReason deadReason = NativeReason::Ok;
};

// The single monotonic lease shared by the owner runtime and the native path.
// Thread-safe; every call takes the caller's trusted monotonic instant.
class LiveLeaseGuard {
public:
    // Requires a canonical session id, generation >= 1, a positive cap, and a
    // deadline strictly in the future and no further than capMs away.
    static std::shared_ptr<LiveLeaseGuard> create(const QString& sessionId,
                                                 quint64 runGeneration,
                                                 qint64 deadlineMs,
                                                 qint64 nowMs,
                                                 qint64 capMs = ManagedEndpointContext::kLeaseTtlCapMs,
                                                 NativeResult* reason = nullptr)
    {
        if (!ManagedEndpointContext::isCanonicalUuid4(sessionId)) {
            fail(reason, NativeReason::ContextInvalid,
                 "lease session id is not a canonical uuid4");
            return nullptr;
        }
        if (runGeneration == 0) {
            fail(reason, NativeReason::RunGenerationInvalid, "run generation must be >= 1");
            return nullptr;
        }
        if (nowMs < 0) {
            fail(reason, NativeReason::LeaseInvalid, "trusted monotonic clock is unusable");
            return nullptr;
        }
        if (capMs <= 0) {
            fail(reason, NativeReason::LeaseDeadlineInvalid, "lease cap must be positive");
            return nullptr;
        }
        if (deadlineMs <= nowMs) {
            fail(reason, NativeReason::LeaseExpired,
                 "lease deadline is not strictly in the future");
            return nullptr;
        }
        if (deadlineMs - nowMs > capMs) {
            fail(reason, NativeReason::LeaseDeadlineInvalid,
                 "lease deadline exceeds the locally honoured span");
            return nullptr;
        }

        if (reason) {
            *reason = NativeResult{};
        }
        return std::shared_ptr<LiveLeaseGuard>(
            new LiveLeaseGuard(sessionId, runGeneration, deadlineMs));
    }

    // Origin-independent factory: the caller supplies time REMAINING on its own
    // already-confirmed lease (e.g. KanadeSession::leaseRemainingMs()), not an
    // absolute instant.  This is the preferred path for the controller lane,
    // because it removes any dependence on which monotonic clock produced the
    // original deadline: only the interval is trusted, and it is clamped to the
    // locally honoured cap.  Bounded exactly like create(): remaining must be
    // strictly positive and no greater than capMs.
    static std::shared_ptr<LiveLeaseGuard> createFromRemaining(const QString& sessionId,
                                                              quint64 runGeneration,
                                                              qint64 remainingMs,
                                                              qint64 capMs = ManagedEndpointContext::kLeaseTtlCapMs,
                                                              NativeResult* reason = nullptr)
    {
        if (remainingMs <= 0) {
            fail(reason, NativeReason::LeaseExpired,
                 "confirmed lease has no remaining time");
            return nullptr;
        }
        if (remainingMs > capMs) {
            // Never trust a longer span than the locked server can mint.
            remainingMs = capMs;
        }
        return create(sessionId, runGeneration, managedMonotonicNowMs() + remainingMs,
                      managedMonotonicNowMs(), capMs, reason);
    }

    LiveLeaseSnapshot snapshot(qint64 nowMs) const
    {
        QMutexLocker locker(&m_mutex);

        LiveLeaseSnapshot state;
        state.deadlineMs = m_deadlineMs;
        state.generation = m_generation;
        state.sessionId = m_sessionId;
        state.epoch = m_epoch;
        state.deadReason = m_deadReason;

        if (m_deadReason != NativeReason::Ok) {
            state.live = false;
            return state;
        }
        if (nowMs < 0) {
            state.live = false;
            state.deadReason = NativeReason::LeaseInvalid;
            return state;
        }
        // At the deadline itself the lease is ALREADY gone.
        state.live = nowMs < m_deadlineMs;
        if (!state.live) {
            state.deadReason = NativeReason::LeaseExpired;
        }
        return state;
    }

    bool isLive(qint64 nowMs) const { return snapshot(nowMs).live; }

    // Forward-only extension from a confirmed lease response.  Rejects an
    // expired/already-dead guard, a non-matching session/generation, a
    // deadline that is not strictly later, one already elapsed, or one beyond
    // the cap.  Never shortens a live deadline (a shorter confirmed deadline
    // means the caller should revoke instead).
    bool extend(qint64 nowMs,
                qint64 newDeadlineMs,
                quint64 expectedGeneration,
                const QString& expectedSessionId,
                NativeResult* reason = nullptr)
    {
        QMutexLocker locker(&m_mutex);

        if (m_deadReason != NativeReason::Ok) {
            fail(reason, m_deadReason, "lease is already dead");
            return false;
        }
        if (expectedGeneration == 0 || expectedGeneration != m_generation) {
            fail(reason, NativeReason::LeaseGenerationMismatch,
                 "renewal is from a different run generation");
            return false;
        }
        if (expectedSessionId != m_sessionId) {
            fail(reason, NativeReason::LeaseSessionMismatch,
                 "renewal does not name this session");
            return false;
        }
        if (nowMs < 0) {
            fail(reason, NativeReason::LeaseInvalid, "trusted monotonic clock is unusable");
            return false;
        }
        if (nowMs >= m_deadlineMs) {
            // Latched death: a late confirmation can never revive an elapsed lease.
            m_deadReason = NativeReason::LeaseExpired;
            ++m_epoch;
            fail(reason, NativeReason::LeaseExpired, "lease deadline was already reached");
            return false;
        }
        if (newDeadlineMs <= nowMs) {
            fail(reason, NativeReason::LeaseExpired,
                 "renewed deadline is not strictly in the future");
            return false;
        }
        if (newDeadlineMs - nowMs > ManagedEndpointContext::kLeaseTtlCapMs) {
            fail(reason, NativeReason::LeaseDeadlineInvalid,
                 "renewed deadline exceeds the locally honoured span");
            return false;
        }
        if (newDeadlineMs <= m_deadlineMs) {
            fail(reason, NativeReason::LeaseNotExtended,
                 "renewal did not strictly advance the deadline");
            return false;
        }

        m_deadlineMs = newDeadlineMs;
        ++m_epoch;
        if (reason) {
            *reason = NativeResult{};
        }
        return true;
    }

    // Periodic observation for a watchdog that polls faster than the server
    // confirms.  It differs from extend() in exactly ONE case: a confirmation
    // that EQUALS the deadline already held, on a guard that is still live and
    // for this same run/session, is a successful no-op (nothing moves, epoch
    // unchanged) - on a short cadence that repeat means "no news yet", not a
    // failed renewal.
    //
    // It is not a weaker gate.  Every other case - already dead, foreign run
    // generation/session, unusable clock, elapsed lease, a LOWER deadline, a
    // deadline not strictly in the future, or one beyond the cap - is handed to
    // the SAME strict extend() above, so all of them still fail closed with the
    // identical reasons.
    bool observe(qint64 nowMs,
                 qint64 confirmedDeadlineMs,
                 quint64 expectedGeneration,
                 const QString& expectedSessionId,
                 NativeResult* reason = nullptr)
    {
        // Check the one benign case under the lock, then hand every other case
        // to the strict body (which re-takes the lock and re-checks death, so a
        // revoke landing in between still fails closed).
        {
            QMutexLocker locker(&m_mutex);
            if (confirmedDeadlineMs == m_deadlineMs
                && m_deadReason == NativeReason::Ok
                && expectedGeneration != 0 && expectedGeneration == m_generation
                && expectedSessionId == m_sessionId
                && nowMs >= 0 && nowMs < m_deadlineMs) {
                if (reason) {
                    *reason = NativeResult{};
                }
                return true;
            }
        }
        return extend(nowMs, confirmedDeadlineMs, expectedGeneration, expectedSessionId, reason);
    }

    // Permanent, idempotent death.  Bumps epoch and records the reason once.
    void revoke(NativeReason reason)
    {
        QMutexLocker locker(&m_mutex);
        if (m_deadReason != NativeReason::Ok) {
            return;
        }
        m_deadReason = reason == NativeReason::Ok ? NativeReason::LeaseRevoked : reason;
        ++m_epoch;
    }

    quint64 epoch() const
    {
        QMutexLocker locker(&m_mutex);
        return m_epoch;
    }

    NativeReason deadReason() const
    {
        QMutexLocker locker(&m_mutex);
        return m_deadReason;
    }

private:
    LiveLeaseGuard(const QString& sessionId, quint64 runGeneration, qint64 deadlineMs)
        : m_sessionId(sessionId)
        , m_generation(runGeneration)
        , m_deadlineMs(deadlineMs)
    {
    }

    static void fail(NativeResult* reason, NativeReason value, const char* detail)
    {
        if (reason) {
            reason->reason = value;
            reason->detail = QString::fromLatin1(detail);
        }
    }

    mutable QMutex m_mutex;
    QString m_sessionId;
    quint64 m_generation;
    qint64 m_deadlineMs;
    quint64 m_epoch = 0;
    NativeReason m_deadReason = NativeReason::Ok;
};

// ---------------------------------------------------------------------------
// Port-policy bridge + ABI callback
// ---------------------------------------------------------------------------
// Defined HERE, after LiveLeaseGuard/LiveLeaseSnapshot are complete, because the
// callback calls snapshot().  The marker/types/constants stay earlier so callers
// can wire the policy up without caring about definition order.

// State the callback needs.  The guard is shared with the gate, so a revoke or a
// lease expiry observed anywhere stops every subsequent send immediately.
// `context` must stay valid from LiStartConnectionWithPortPolicy() until
// LiStopConnection(): the Session owns it as a member.
struct ManagedPortPolicyBridge {
    std::shared_ptr<LiveLeaseGuard> lease;
    quint64 runGeneration = 0;
    QString sessionId;
};

// Synchronous ABI callback: true == live (permitted).  Non-capturing and
// noexcept, so it is safe to hand to C code.  Every abnormal case - null
// context, no lease, wrong generation/session, expired/revoked lease - returns
// false, which makes common-c refuse the send rather than attempt it.
inline bool managedPortIsLive(void* context) noexcept
{
    if (context == nullptr) {
        return false;
    }
    const auto* bridge = static_cast<const ManagedPortPolicyBridge*>(context);
    if (!bridge->lease) {
        return false;
    }
    const LiveLeaseSnapshot lease = bridge->lease->snapshot(managedMonotonicNowMs());
    if (!lease.live) {
        return false;
    }
    if (lease.generation != bridge->runGeneration || lease.sessionId != bridge->sessionId) {
        return false;
    }
    return true;
}

// Native operations the managed path may request.  Policy lives in
// ManagedNativeGate::permits(); the enum is deliberately coarse so the
// controller/Session lanes cannot invent extra slots.
enum class NativeCall {
    ServerInfo, // native discovery over the pinned loopback endpoint
    AppList,    // applist
    PairCert,   // native PIN pairing, certificate exchange stage
    Pair,       // native PIN pairing, full exchange
    Launch,     // launch control + common-c start
    Resume,     // resume control + common-c start
    Quit,       // cancel/stop control only
    Stream      // any media/control traffic after LiStartConnection
};

// A verified statement from the managed runtime over the authenticated,
// same-user, same-session IPC channel.  `ipcVerified` may be set ONLY by the
// frame validator that already proved pipe ACL, parent PID and child image;
// there is no "trusted" shortcut and no default value.
//
// Two milestones exist and both are required before any native call:
//   * RuntimeBinding - the runtime has proven it actually OWNS the pinned
//     loopback listeners.  This gates arm(): without it the native client
//     would dial ports that may belong to an unrelated local process.
//   * ReadyProof - the peer transport is ready for this exact session and
//     generation.  This gates launch/resume/stream.
struct RuntimeBinding {
    QString sessionId;
    quint64 runGeneration = 0;
    QString transportId;      // opaque runtime transport tag (not a secret)
    quint64 ipcSequence = 0;  // monotonic sequence of the verified listen frame
    qint64 leaseDeadlineMs = -1;
    bool ipcVerified = false;
};

struct ReadyProof {
    QString sessionId;
    quint64 runGeneration = 0;
    QString transportId;      // opaque runtime transport tag (not a secret)
    quint64 ipcSequence = 0;  // monotonic sequence of the verified ready frame
    qint64 leaseDeadlineMs = -1;
    bool ipcVerified = false;
};

// Typed gate.  One instance per managed run; terminal after death.
// Default-constructed instances are Idle/Dead-safe: every entry point refuses
// until a real, verified binding is supplied.  An invalid/default value never
// enables anything and can never be mistaken for an unmanaged path.
class ManagedNativeGate {
public:
    enum class State {
        Idle,     // nothing bound yet
        Bound,    // verified runtime listen + live lease; discovery/pairing allowed
        Ready,    // verified ready proof accepted; launch/resume allowed if hook exists
        Stopping, // local stop started; only cleanup calls remain
        Dead      // terminal: no further native calls
    };

    ManagedNativeGate() = default;

    // Binds the context, the shared lease and the runtime's verified listener
    // proof.  Requires: a live guard matching the context session/generation,
    // AND a RuntimeBinding whose ipcVerified is true and that names the same
    // session/generation.  `binding.leaseDeadlineMs` may only tighten.
    // Only valid from Idle.  There is no way to bind without the proof.
    NativeResult arm(const ManagedEndpointContext& context,
                     const std::shared_ptr<LiveLeaseGuard>& guard,
                     const RuntimeBinding& binding,
                     qint64 nowMs)
    {
        QMutexLocker locker(&m_mutex);

        if (m_state == State::Dead) {
            return failure(NativeReason::AlreadyDead, "managed native gate is already dead");
        }
        if (m_state != State::Idle) {
            return failure(NativeReason::AlreadyArmed, "managed native gate is already armed");
        }
        if (!guard) {
            return failure(NativeReason::LeaseMissing, "no live lease was supplied");
        }
        if (context.runGeneration() == 0) {
            return failure(NativeReason::RunGenerationInvalid, "run generation must be >= 1");
        }
        if (!binding.ipcVerified) {
            // Nothing is bound and nothing becomes callable: an unverified
            // runtime statement must not open even the discovery slot.
            return failure(NativeReason::RuntimeBindingUnverified,
                           "runtime binding was not verified by the IPC path");
        }
        if (binding.sessionId != context.sessionId()) {
            return failure(NativeReason::RuntimeBindingSessionMismatch,
                           "runtime binding names a different session");
        }
        if (binding.runGeneration == 0 || binding.runGeneration != context.runGeneration()) {
            return failure(NativeReason::RuntimeBindingGenerationMismatch,
                           "runtime binding names a different run generation");
        }
        const LiveLeaseSnapshot lease = guard->snapshot(nowMs);
        if (!lease.live) {
            // A guard that is already dead must never arm a new native path.
            m_state = State::Dead;
            m_deadReason = lease.deadReason == NativeReason::Ok ? NativeReason::LeaseExpired
                                                               : lease.deadReason;
            return failure(m_deadReason, "lease is not live at arm time");
        }
        if (lease.sessionId != context.sessionId()) {
            return failure(NativeReason::LeaseSessionMismatch,
                           "lease names a different session than the context");
        }
        if (lease.generation != context.runGeneration()) {
            return failure(NativeReason::LeaseGenerationMismatch,
                           "lease belongs to a different run generation");
        }
        // The guard must never be more optimistic than the confirmed context,
        // nor than the runtime's own verified statement.
        if (lease.deadlineMs > context.confirmedDeadlineMs()) {
            return failure(NativeReason::LeaseDeadlineInvalid,
                           "lease deadline is beyond the confirmed context deadline");
        }
        if (binding.leaseDeadlineMs > 0 && binding.leaseDeadlineMs > lease.deadlineMs) {
            return failure(NativeReason::RuntimeBindingDeadlineInvalid,
                           "runtime binding deadline would extend the Kanade-confirmed lease");
        }

        m_context = context;
        m_guard = guard;        m_transportId = binding.transportId;
        m_lastIpcSequence = binding.ipcSequence;
        m_hasIpcSequence = true;
        m_state = State::Bound;
        return NativeResult{};
    }

    // Accepts the verified ready proof.  Only from Bound, only with a live
    // lease, only for the same runtime transport that bound, and only with a
    // strictly newer IPC sequence.
    NativeResult markReady(const ReadyProof& proof, qint64 nowMs)
    {
        QMutexLocker locker(&m_mutex);

        if (m_state == State::Dead) {
            return failure(NativeReason::AlreadyDead, "managed native gate is already dead");
        }
        if (m_state != State::Bound) {
            return failure(NativeReason::NotArmed, "ready proof is only accepted from Bound");
        }
        if (!m_guard) {
            m_state = State::Dead;
            m_deadReason = NativeReason::LeaseMissing;
            return failure(NativeReason::LeaseMissing, "no live lease is bound");
        }
        if (!proof.ipcVerified) {
            return failure(NativeReason::ReadyProofUnverified,
                           "ready proof was not verified by the IPC path");
        }
        if (!m_context.has_value()) {
            return failure(NativeReason::NotArmed, "managed native gate has no bound context");
        }
        if (proof.sessionId != m_context->sessionId()) {
            return failure(NativeReason::ReadyProofSessionMismatch,
                           "ready proof names a different session");
        }
        if (proof.runGeneration == 0 || proof.runGeneration != m_context->runGeneration()) {
            return failure(NativeReason::ReadyProofGenerationMismatch,
                           "ready proof names a different run generation");
        }
        if (!proof.transportId.isEmpty() && proof.transportId != m_transportId) {
            return failure(NativeReason::ReadyProofTransportMismatch,
                           "ready proof names a different runtime transport");
        }
        if (m_hasIpcSequence && proof.ipcSequence <= m_lastIpcSequence) {
            return failure(NativeReason::ReadyProofReplay,
                           "ready proof replayed an older sequence");
        }

        const LiveLeaseSnapshot lease = m_guard->snapshot(nowMs);
        if (!lease.live) {
            m_state = State::Dead;
            m_deadReason = lease.deadReason == NativeReason::Ok ? NativeReason::LeaseExpired
                                                               : lease.deadReason;
            return failure(m_deadReason, "lease is not live at ready time");
        }
        // The runtime may only tighten.  A later runtime deadline is a protocol
        // error, not a lease extension: extend() is the only way to move forward.
        if (proof.leaseDeadlineMs > 0 && proof.leaseDeadlineMs > lease.deadlineMs) {
            return failure(NativeReason::ReadyProofDeadlineInvalid,
                           "ready proof deadline would extend the Kanade-confirmed lease");
        }

        m_lastIpcSequence = proof.ipcSequence;
        m_transportId = proof.transportId.isEmpty() ? m_transportId : proof.transportId;
        m_state = State::Ready;
        return NativeResult{};
    }

    // Central policy.  Returns Ok only when the call is allowed right now.
    NativeResult permits(NativeCall call, qint64 nowMs, quint64 runGeneration) const
    {
        QMutexLocker locker(&m_mutex);
        return permitsLocked(call, nowMs, runGeneration);
    }

    // Local stop: from Bound/Ready.  Quit/cleanup remain possible; everything
    // else is refused.  Returns false when a stop cannot start (already dead,
    // or a stop is already in progress).
    bool beginStop(qint64 nowMs, NativeResult* reason = nullptr)
    {
        QMutexLocker locker(&m_mutex);
        Q_UNUSED(nowMs);

        if (m_state == State::Dead) {
            setReason(reason, NativeReason::AlreadyDead, "managed native gate is already dead");
            return false;
        }
        if (m_state == State::Stopping) {
            setReason(reason, NativeReason::AlreadyStopping,
                      "managed native gate is already stopping");
            return false;
        }
        if (m_state == State::Idle) {
            setReason(reason, NativeReason::NotArmed, "managed native gate was never armed");
            return false;
        }

        m_state = State::Stopping;
        if (reason) {
            *reason = NativeResult{};
        }
        return true;
    }

    void finishStop()
    {
        QMutexLocker locker(&m_mutex);
        if (m_state == State::Dead) {
            return;
        }
        m_state = State::Dead;
        m_deadReason = NativeReason::Stopped;
        m_guard.reset();
        m_transportId.clear();
    }

    // Death from any cause (lease expiry, runtime death, IPC loss, user logout,
    // protocol error).  Terminal and idempotent; also kills the shared guard so
    // the runtime's own renewals stop being accepted.
    void revoke(NativeReason reason)
    {
        QMutexLocker locker(&m_mutex);
        if (m_state == State::Dead) {
            return;
        }
        m_state = State::Dead;
        m_deadReason = reason == NativeReason::Ok ? NativeReason::LeaseRevoked : reason;
        if (m_guard) {
            m_guard->revoke(m_deadReason);
        }
        m_transportId.clear();
    }

    State state() const
    {
        QMutexLocker locker(&m_mutex);
        return m_state;
    }

    NativeReason deadReason() const
    {
        QMutexLocker locker(&m_mutex);
        return m_deadReason;
    }

    // True only in Ready with a live lease AND the common-c pre-send hook.
    bool streamingReady(qint64 nowMs) const
    {
        QMutexLocker locker(&m_mutex);
        if (m_state != State::Ready || !m_guard) {
            return false;
        }
        if (!m_guard->isLive(nowMs)) {
            return false;
        }
        return presendValidatorAvailable();
    }

    // The Session lane's last gate before it assembles SERVER_INFORMATION.
    bool canOpenManagedStream(qint64 nowMs) const { return streamingReady(nowMs); }

    QString sessionId() const
    {
        QMutexLocker locker(&m_mutex);
        return m_context.has_value() ? m_context->sessionId() : QString();
    }

    quint64 runGeneration() const
    {
        QMutexLocker locker(&m_mutex);
        return m_context.has_value() ? m_context->runGeneration() : 0;
    }

    QString apiOrigin() const
    {
        QMutexLocker locker(&m_mutex);
        return m_context.has_value() ? m_context->apiOrigin() : QString();
    }

    QString transportId() const
    {
        QMutexLocker locker(&m_mutex);
        return m_transportId;
    }

    // Single source of truth for the common-c pre-send destination validator.
    // True only when the reviewed owner patch is actually in this build
    // (ManagedPortPolicy.h + the owner's callback macro).  Not hardcoded.
    static bool presendValidatorAvailable() { return managedPortPolicyAvailable(); }

private:
    NativeResult permitsLocked(NativeCall call, qint64 nowMs, quint64 runGeneration) const
    {
        if (m_state == State::Dead) {
            return failure(NativeReason::Dead,
                           "managed native gate is dead; no further calls are permitted");
        }
        if (m_state == State::Idle) {
            return failure(NativeReason::NotArmed, "managed native gate is not armed");
        }
        if (!m_context.has_value()) {
            // Bound/Ready without a context is impossible; refuse rather than
            // dereference.
            return failure(NativeReason::NotArmed, "managed native gate has no bound context");
        }
        if (runGeneration == 0) {
            return failure(NativeReason::RunGenerationInvalid, "run generation must be >= 1");
        }
        if (runGeneration != m_context->runGeneration()) {
            return failure(NativeReason::LeaseGenerationMismatch,
                           "caller belongs to a different run generation");
        }
        if (!m_guard || !m_guard->isLive(nowMs)) {
            // Observation only: a const query does not mutate the gate.  The
            // owner is expected to revoke(); every call is refused regardless.
            return failure(m_guard ? NativeReason::LeaseExpired : NativeReason::LeaseMissing,
                           "lease is not live; no contact is permitted");
        }

        switch (call) {
        case NativeCall::Quit:
            if (m_state == State::Stopping) {
                return NativeResult{};
            }
            return (m_state == State::Bound || m_state == State::Ready)
                ? NativeResult{}
                : failure(NativeReason::CallNotPermitted, "quit is not permitted in this state");

        case NativeCall::ServerInfo:
        case NativeCall::AppList:
        case NativeCall::PairCert:
        case NativeCall::Pair:
            return (m_state == State::Bound || m_state == State::Ready)
                ? NativeResult{}
                : failure(NativeReason::CallNotPermitted,
                          "native call is not permitted in this state");

        case NativeCall::Launch:
        case NativeCall::Resume:
        case NativeCall::Stream:
            if (m_state != State::Ready) {
                return failure(NativeReason::NotReady,
                               "launch/resume/stream requires a verified ready proof");
            }
            if (!presendValidatorAvailable()) {
                return failure(NativeReason::PresendHookUnavailable,
                               "common-c pre-send destination validator is unavailable");
            }
            return NativeResult{};
        }
        return failure(NativeReason::CallNotPermitted, "unknown native call");
    }

    static NativeResult failure(NativeReason reason, const char* detail)
    {
        NativeResult result;
        result.reason = reason;
        result.detail = QString::fromLatin1(detail);
        return result;
    }

    static void setReason(NativeResult* out, NativeReason reason, const char* detail)
    {
        if (out) {
            out->reason = reason;
            out->detail = QString::fromLatin1(detail);
        }
    }

    mutable QMutex m_mutex;
    State m_state = State::Idle;
    NativeReason m_deadReason = NativeReason::Ok;
    // Engaged only after a successful arm().  ManagedEndpointContext has no
    // default constructor and must never be default-constructed here.
    std::optional<ManagedEndpointContext> m_context;
    std::shared_ptr<LiveLeaseGuard> m_guard;
    QString m_transportId;
    quint64 m_lastIpcSequence = 0;
    bool m_hasIpcSequence = false;
};

// Everything the Session lane needs to run the managed native path.  All
// members are owned explicitly; nothing here may be merged into
// ComputerManager state, and `serverCert` is EPHEMERAL: it is trusted for this
// run only and must not be presented as a durable native pin until the
// installation-isolation work lands.
struct ManagedNativeStream {
    // Optional for the same reason as the gate: no default constructor exists.
    // A stream bundle without a context is invalid.
    std::optional<ManagedEndpointContext> context;
    NativeEndpoint endpoint;
    std::shared_ptr<LiveLeaseGuard> lease;
    std::shared_ptr<ManagedNativeGate> gate;
    QSslCertificate serverCert; // ephemeral trust for this run only
    QString hostName;           // display name only; never a dial target

    bool valid() const
    {
        return context.has_value() && lease != nullptr && gate != nullptr
            && !serverCert.isNull()
            && endpoint.host == ManagedEndpointContext::loopbackHost()
            && endpoint.httpPort == ManagedEndpointContext::kManagedHttpPort
            && endpoint.httpsPort == ManagedEndpointContext::kManagedHttpsPort;
    }
};

// Explicit managed native stop sequence (documented, not implemented here to
// keep this header free of NvHTTP):
//   1. gate->beginStop(now) must return true (only from Bound/Ready);
//   2. construct NvHTTP from a policy with call = NativeCall::Quit;
//   3. call quitApp() once; its own gate check enforces the single-call rule;
//   4. gate->finishStop() in every path, including exceptions.
// After step 4 the gate is Dead and every later call is refused, so a
// controller-side stop that never reached a live Session follows the exact same
// contract.

// The complete managed policy a NvHTTP instance must carry.  It is attached
// once at construction (managed NvHTTP is single-run and single-origin) and
// makes every request consult the shared gate first.
struct ManagedNativePolicy {
    NativeEndpoint endpoint;
    std::shared_ptr<ManagedNativeGate> gate;
    quint64 runGeneration = 0;
    NativeCall call = NativeCall::ServerInfo;

    // Exact numeric literal loopback and the two pinned control ports.  A
    // hostname ("localhost"), an IPv6 literal, a wildcard bind address or any
    // other port is invalid.  A gate is mandatory: a policy object without a
    // live gate can never authorize a call.
    bool valid() const
    {
        return gate != nullptr && runGeneration >= 1
            && endpoint.host == ManagedEndpointContext::loopbackHost()
            && endpoint.httpPort == ManagedEndpointContext::kManagedHttpPort
            && endpoint.httpsPort == ManagedEndpointContext::kManagedHttpsPort
            && isPinnedManagedEndpoint(endpoint.host, endpoint.httpPort)
            && isPinnedManagedEndpoint(endpoint.host, endpoint.httpsPort);
    }
};

} // namespace Kanade

#endif // MANAGEDNATIVE_H
