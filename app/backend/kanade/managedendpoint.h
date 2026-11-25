#pragma once

#ifndef MANAGEDENDPOINT_H
#define MANAGEDENDPOINT_H

#include <QString>

#include <optional>

// Kanade online-mode managed endpoint context (client side).
//
// Plan sections 3.2 (fixed data path) and 3.3 (managed path isolation): a
// single managed operation must run against ONE immutable context that binds
// the normalized HTTPS API origin, the exact selected identifiers (host,
// grant, session, both participant installations and key versions), the
// confirmed lease deadline, and the current run generation.  Every address
// and URL that a future managed path feeds into NvHTTP / common-c must come
// from this context.
//
// This module is PURE VALIDATION AND VALUE STORAGE:
//
//   * It performs no network I/O, reads no clock, and never instantiates
//     NvHTTP, NvPairingManager, Session, or any other live object.  It cannot
//     open a stream and must never be presented as one.
//   * This value object makes no readiness claim. The live runtime owns
//     sidecar readiness, activation and lease enforcement.
//   * There is deliberately NO access to historical address candidates: no
//     uniqueAddresses()/pinAddress()/UUID-merge input is read or accepted.
//     The only loopback identity this module knows is the exact numeric
//     string "127.0.0.1" on the pinned ports below.
//   * No credential, token, ticket or authorization is created, checked or
//     implied here.  "Validated" means the local value is internally
//     consistent and restricted to the fixed shape; it is NOT an
//     authorization or readiness claim.
//
// Locked-source evidence that shaped the strictness (all read-only):
//   * moonlight-common-c @ 733025a254e6e166a4afb577cbe056c10257f950
//     (gitlink; src/RtspConnection.c blob 6678f7845eace14f67f21c5af6102f699370aaa2):
//       - RTSP encryption is enabled ONLY when the session URL contains the
//         EXACT LOWERCASE spelling "rtspenc://" (strstr, RtspConnection.c:1141).
//         An uppercase or alternate scheme silently yields PLAINTEXT RTSP, so
//         validateRtspUrl() requires the exact lowercase "rtspenc://" prefix
//         and rejects "rtsp://" outright (encryption must never be disabled).
//       - The RTSP TCP peer comes from serverInfo->address (RemoteAddr) with
//         NO pre-send destination guard (RtspConnection.c:428;
//         Connection.c:295); the negotiated audio SETUP port is consumed
//         immediately (RtspConnection.c:1458-1479).  Validation here is
//         therefore strict-by-construction, because the library below does
//         not enforce it.
//       - Connection.c:201-225 derives the RTSP port from the LAST ':' of the
//         session URL and WEAK-DEFAULTS to 48010 when parsing fails.  The
//         managed validator never weak-defaults: a missing or malformed port
//         fails closed.
//   * foundation-sunshine @ 83438ebc1b4c3ba5a57ee91f5bd57c83d0822cdb
//     (read-only baseline; zero business-source changes are made):
//       - src/nvhttp.cpp:286-292 emits rtspenc:// only when the client reports
//         corever >= 1; nvhttp.cpp:795-797 builds sessionUrl0 as
//         scheme + request-local address + ':' + RTSP_SETUP_PORT with no
//         path, userinfo, query or fragment.  validateRtspUrl() matches
//         exactly that shape.
//   * moonlight-qt app/backend/nvaddress.h: DEFAULT_HTTP_PORT 47989,
//     DEFAULT_HTTPS_PORT 47984; foundation src/rtsp.h:31 RTSP_SETUP_PORT=21
//     with the default base port (47989) maps to 48010.  Only this locked
//     default port group is supported (plan 3.2); 47990/48001 are never
//     mapped and the media UDP group belongs to the sidecar lane.
//   * Kanade src/kanade/security/identity.py:156-160,
//     persistence/sessions.py:291-294, domain/pairing.py:173-174: every
//     host/grant/session/installation id is str(uuid.uuid4()) - a canonical
//     36-char lowercase UUID4.  isCanonicalUuid4() enforces that spelling
//     exactly so the context binds the precise selected rows, not a lookalike.
//   * Kanade persistence/sessions.py:2133-2153 session_snapshot(): the
//     session carries host_key_version / client_key_version, and
//     windows_host_session.py:567-581 refuses offers whose key versions or
//     participants differ from the configured ones.  This context applies the
//     same exact binding on the client side.
//
// Error reporting: every validation returns a structured, NON-SECRET reason
// (enum + fixed English detail string).  No input value, credential, URL
// query, or other potentially sensitive material is ever copied into a
// reason.  Reasons may be logged verbatim; user input must not be.
//
// Canonical HTTPS origin contract (aligned with kanadeidentity.h, which scopes
// DPAPI entropy by "canonical HTTPS origin"):
//     https://<host>[:<port>]      with port omitted exactly when it is 443,
//   where <host> is a lowercased DNS reg-name or a strict dotted-quad IPv4
//   literal.  Bracketed IPv6 literals are rejected here for the same reason
//   kanadeidentity.h rejects them: an installation identity can never be
//   scoped to one, so a context bound to it could never authenticate.  No
//   userinfo, path (except a tolerated "/" which is dropped), query or
//   fragment; the scheme spelling "https" is case-insensitive on input and
//   lowercased.
namespace Kanade {

// Structured, non-secret failure classification.  Values are stable and safe
// to log; detail strings are fixed literals chosen by this module only.
enum class ValidationReason {
    Ok = 0,

    // API origin (see validateApiOrigin).
    OriginEmpty,
    OriginNotCanonical,          // whitespace or non-literal spelling
    OriginSchemeNotHttps,
    OriginUserInfoNotAllowed,
    OriginHostInvalid,
    OriginPortInvalid,
    OriginPathNotAllowed,
    OriginQueryNotAllowed,
    OriginFragmentNotAllowed,

    // Exact selected identifiers (see create()).
    HostIdInvalid,
    GrantIdInvalid,
    SessionIdInvalid,
    ClientInstallationIdInvalid,
    HostInstallationIdInvalid,
    ParticipantsNotDistinct,
    KeyVersionInvalid,

    // Pinned loopback endpoints (see validateHttpEndpoint/HttpsEndpoint).
    EndpointHostNotPinnedLoopback,
    EndpointPortNotPinned,

    // Expected RTSP URL (see validateRtspUrl).
    RtspUrlNotCanonical,
    RtspSchemePlaintextNotAllowed, // "rtsp://" would disable RTSP encryption
    RtspSchemeNotAllowed,          // e.g. "rtspru://" or anything unexpected
    RtspUserInfoNotAllowed,
    RtspHostNotPinnedLoopback,
    RtspPortInvalid,
    RtspPortNotPinned,
    RtspPathNotAllowed,
    RtspQueryNotAllowed,
    RtspFragmentNotAllowed,

    // Lease/run gate (see checkLeaseGate()/renewed()).
    LeaseDeadlineInvalid,   // not a bounded future deadline at confirmation
    LeaseClockInvalid,      // caller-supplied monotonic instant unusable
    LeaseExpired,           // deadline already reached (at it == expired)
    LeaseStaleRunGeneration,
    LeaseSessionMismatch,
    RunGenerationInvalid,
    LeaseNotExtended        // renewal did not strictly advance the deadline
};

// Stable, non-secret printable name of a reason (for logs and tests).
QString reasonToString(ValidationReason reason);

// Result of any validation in this module.  detail is a fixed, non-secret
// English string owned by this module; ok() is true exactly when reason is
// Ok (detail is then empty).
struct ValidationResult {
    ValidationReason reason = ValidationReason::Ok;
    QString detail;

    bool ok() const { return reason == ValidationReason::Ok; }
};

// Raw, unvalidated inputs for a managed context.  All fields come from the
// explicit user selection plus the Kanade control plane; nothing here may be
// populated from address history, discovery, or UUID merging.
struct ManagedEndpointSpec {
    QString apiOrigin;                 // user-configured Kanade HTTPS origin
    QString hostId;                    // Kanade host id (canonical UUID4)
    QString grantId;                   // Kanade grant id (canonical UUID4)
    QString sessionId;                 // Kanade session id (canonical UUID4)
    QString clientInstallationId;      // this installation (canonical UUID4)
    QString hostInstallationId;        // host installation (canonical UUID4)
    int clientKeyVersion = 0;          // >= 1
    int hostKeyVersion = 0;            // >= 1
    quint64 runGeneration = 0;         // client run generation, >= 1
    // Last CONFIRMED lease deadline expressed on the caller's trusted
    // MONOTONIC clock in milliseconds (same origin as checkLeaseGate()'s
    // argument).  No wall-clock value is accepted: a system-time change can
    // then never revive an elapsed lease.
    qint64 confirmedDeadlineMs = 0;
};

// Immutable managed endpoint context.  Instances can only be produced by
// create() or renewed(); there are no setters, no default constructor and no
// clock source.  The class performs no I/O and never touches live streaming
// objects.
class ManagedEndpointContext final {
public:
    // Locked default port group (plan 3.2).  Only these values are ever
    // accepted by the loopback endpoint and RTSP URL validators.
    static constexpr quint16 kManagedHttpPort = 47989;  // app/backend/nvaddress.h DEFAULT_HTTP_PORT
    static constexpr quint16 kManagedHttpsPort = 47984; // app/backend/nvaddress.h DEFAULT_HTTPS_PORT
    static constexpr quint16 kManagedRtspPort = 48010;  // foundation rtsp.h:31 + default base

    // Maximum locally honoured lease span.  Kanade LEASE_TTL_SECONDS is 90;
    // a confirmed deadline further away than this was not minted by the
    // locked server and is rejected rather than clamped silently.
    static constexpr qint64 kLeaseTtlCapMs = 90000;

    // Validates every field of spec and, only on success, returns an
    // immutable context.  trustedMonotonicNowMs is the caller's trusted
    // monotonic instant (milliseconds) used ONLY to bound the confirmed
    // deadline: it must be strictly in the future and at most
    // kLeaseTtlCapMs away.  Field order: apiOrigin, hostId, grantId,
    // sessionId, clientInstallationId, hostInstallationId, participants
    // distinct, clientKeyVersion, hostKeyVersion, runGeneration, deadline.
    // On failure returns std::nullopt and fills reason; nothing partial is
    // exposed.
    static std::optional<ManagedEndpointContext> create(const ManagedEndpointSpec& spec,
                                                        qint64 trustedMonotonicNowMs,
                                                        ValidationResult& reason);

    ManagedEndpointContext(const ManagedEndpointContext&) = default;
    ManagedEndpointContext(ManagedEndpointContext&&) = default;
    ManagedEndpointContext& operator=(const ManagedEndpointContext&) = default;
    ManagedEndpointContext& operator=(ManagedEndpointContext&&) = default;

    // --- Immutable accessors -------------------------------------------------
    const QString& apiOrigin() const { return m_apiOrigin; }
    const QString& hostId() const { return m_hostId; }
    const QString& grantId() const { return m_grantId; }
    const QString& sessionId() const { return m_sessionId; }
    const QString& clientInstallationId() const { return m_clientInstallationId; }
    const QString& hostInstallationId() const { return m_hostInstallationId; }
    int clientKeyVersion() const { return m_clientKeyVersion; }
    int hostKeyVersion() const { return m_hostKeyVersion; }
    quint64 runGeneration() const { return m_runGeneration; }

    // Confirmed deadline on the caller's monotonic clock (milliseconds).
    qint64 confirmedDeadlineMs() const { return m_confirmedDeadlineMs; }

    // The only loopback identity this module accepts: exact numeric
    // "127.0.0.1".  "localhost", "::1", "0.0.0.0", compressed IPv4 spellings
    // and any other alias are rejected by every validator below.
    static const QString& loopbackHost();

    // The exact RTSP URL the managed path expects from the host adapter:
    // "rtspenc://127.0.0.1:48010".  This is the same string that satisfies the
    // locked common-c "rtspenc://" encryption gate.
    static const QString& expectedRtspUrl();

    // --- Pure input validators (usable without a context) --------------------

    // Strict port parser: non-empty ASCII digits only, at most 5 characters,
    // no leading zeros, value in 1..65535 with an early-overflow bail.  This
    // prevents the weak defaults and integer overflow that the C library's
    // strtol-based parsing tolerates (Connection.c:201-225 defaults to 48010
    // on ANY failure, including malformed and out-of-range text).  Returns
    // false instead of ever substituting a default.
    static bool parseStrictPort(const QString& text, quint16* out);

    // Canonical Kanade id check: exactly 36 chars, lowercase hex with hyphens
    // at positions 8/13/18/23, UUID version nibble '4' and variant nibble
    // 8/9/a/b (Kanade ids are str(uuid.uuid4()); see module comment).
    static bool isCanonicalUuid4(const QString& id);

    // Validates and canonicalizes a Kanade API origin.  On success returns Ok
    // and, when canonicalOut is non-null, writes the canonical form
    // "https://host[:port]" (port omitted iff 443; see module comment for the
    // full contract).  On failure returns a structured reason and does not
    // write canonicalOut.  No redirect is ever followed: the origin is an
    // exact connection target, and any HTTP redirect handling in the API
    // client must fail closed on cross-origin moves (plan 3.4) - this module
    // simply binds the exact literal origin.
    static ValidationResult validateApiOrigin(const QString& text, QString* canonicalOut);

    // Managed loopback HTTPS/HTTP endpoint check: host must be the exact
    // numeric loopback and port exactly the pinned value.  These are the only
    // NvHTTP endpoints a managed operation may target; historical LAN
    // candidates are never consulted.
    static ValidationResult validateHttpEndpoint(const QString& host, quint16 port);
    static ValidationResult validateHttpsEndpoint(const QString& host, quint16 port);

    // Strict expected RTSP URL check.  Accepts exactly one shape:
    //     rtspenc://127.0.0.1:48010
    // i.e. lowercase "rtspenc" (the only spelling that enables RTSP
    // encryption in the locked common-c; RtspConnection.c:1141), exact
    // numeric loopback, exact port 48010, and no userinfo, path, query,
    // fragment (not even a trailing '/'), whitespace or redirect.  Plaintext
    // "rtsp://" is rejected with RtspSchemePlaintextNotAllowed because
    // accepting it would disable RTSP encryption.  A missing or malformed
    // port is RtspPortNotPinned / RtspPortInvalid - this validator never
    // weak-defaults the way Connection.c:201-225 does.
    static ValidationResult validateRtspUrl(const QString& urlText);

    // --- Lease / run gate -----------------------------------------------------

    // Fail-closed lease gate for an EXPLICIT caller-supplied monotonic instant:
    //   * currentRunGeneration must be >= 1 and equal to the context's run
    //     generation (a context from an older or newer run must not serve:
    //     reconnection, refresh or clock jumps never resurrect a stale run);
    //   * trustedMonotonicNowMs must be a non-negative instant supplied by the
    //     caller's trusted monotonic clock, strictly earlier than the context
    //     deadline.  At the deadline itself the lease is ALREADY expired
    //     ("never later than the last confirmed lease deadline", plan 3.1.4).
    // No wall clock and no implicit "now" is consulted here, so a system-time
    // change (including moving the clock backward) cannot reopen the gate.
    ValidationResult checkLeaseGate(qint64 trustedMonotonicNowMs,
                                    quint64 currentRunGeneration) const;

    // Produces a refreshed immutable context with a strictly later deadline.
    // Fail-closed: the renewal must name THIS session id and THIS run
    // generation, the same trusted monotonic clock must bound the new
    // deadline (future, at most kLeaseTtlCapMs away), the EXISTING deadline
    // must still be strictly in the future (an expired context cannot be
    // revived by a late confirmation), and the new deadline must be STRICTLY
    // greater than this context's deadline - so a delayed, replayed or
    // out-of-order confirmation can never move the gate.  Anything else
    // returns std::nullopt and fills reason; the original context is never
    // modified (immutability).
    std::optional<ManagedEndpointContext> renewed(qint64 newDeadlineMs,
                                                  qint64 trustedMonotonicNowMs,
                                                  const QString& expectedSessionId,
                                                  quint64 expectedRunGeneration,
                                                  ValidationResult& reason) const;

private:
    ManagedEndpointContext(const QString& apiOrigin,
                           const QString& hostId,
                           const QString& grantId,
                           const QString& sessionId,
                           const QString& clientInstallationId,
                           const QString& hostInstallationId,
                           int clientKeyVersion,
                           int hostKeyVersion,
                           quint64 runGeneration,
                           qint64 confirmedDeadlineMs);

    QString m_apiOrigin;
    QString m_hostId;
    QString m_grantId;
    QString m_sessionId;
    QString m_clientInstallationId;
    QString m_hostInstallationId;
    int m_clientKeyVersion = 0;
    int m_hostKeyVersion = 0;
    quint64 m_runGeneration = 0;
    qint64 m_confirmedDeadlineMs = 0;
};

} // namespace Kanade

#endif // MANAGEDENDPOINT_H
