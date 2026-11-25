#pragma once

#ifndef KANADERUNTIMECONFIG_H
#define KANADERUNTIMECONFIG_H

#include <QByteArray>
#include <QList>
#include <QString>

// Managed online runtime configuration (client side, non-secret manifest).
//
// This is the ONE place that decides which sidecar executable may run, which
// fixed peer identity it may serve, the exact Kanade origin, and the outer
// transport endpoints.  It is deliberately a *file* loaded once at startup by
// the embedding application, never caller input from QML, the network, the
// device directory or a session snapshot:
//
//   * QML only ever names a grant id (and host id) it already displays from
//     GET /v1/devices.  That row carries NO key, version or endpoint.
//   * The host installation id, host key version, host public key, the client
//     installation id, the client key version and the QUIC endpoints all come
//     from this file, and every session snapshot is checked against them.
//   * The file contains NO credential: no token, no ticket, no password, no
//     installation seed, no private key.  The client seed stays in the DPAPI
//     store / process memory.
//
// Shape (version 1; every object is closed, unknown keys are refused):
//
//   {
//     "version": 1,
//     "api_origin": "https://kanade.example",           // exact, canonical
//     "client": {
//       "installation_id": "<uuid4>",
//       "key_version": 1
//     },
//     "sidecar": {
//       "executable_path": "D:/.../kanade-sidecar.exe",
//       "executable_sha256": "<64 lowercase hex>"
//     },
//     "peer": {
//       "host_id": "<uuid4>",
//       "host_installation_id": "<uuid4>",
//       "host_key_version": 1,
//       "host_public_key": "<canonical standard base64 of 32 raw bytes>",
//       "host_app_version": "<digits and dots, e.g. 7.1.431.-1>",
//       "quic": "192.0.2.10:50000"                        // outer peer endpoint
//     },
//     "local": {
//       "quic": "192.0.2.11:50000"                        // outer local endpoint
//     },
//     "handshake_timeout_ms": 15000
//   }
//
// The outer QUIC endpoints are NOT GameStream ports: 47989/47984/48010 and
// UDP 47998/47999/48000, plus management 47990 and 48001, are refused there.
// The GameStream port group is a code constant (kManagedTcpPorts /
// kManagedUdpPorts) because it is fixed by the contract; only the outer
// transport addresses vary by deployment.
//
// Both outer endpoints must be numeric IPv4 literals on the approved lab
// interface: never loopback (a UDP socket bound to 127.0.0.1 cannot reach
// another machine), never a hostname, never a wildcard, and never the same
// address on both ends.  GameStream keeps talking to 127.0.0.1 on the locked
// six-port group; that loopback binding belongs to the sidecar, not to this
// manifest.
//
// Packet size: there is no user-configurable MTU.  The engine performs bounded
// internal fragmentation that preserves the 1392-byte managed packet size, and
// a 1024-byte fallback is never implied.
namespace Kanade {

// Locked GameStream port group of the managed path (plan 3.2).  Management
// 47990 and the extra UDP port 48001 must never appear; comparison is exact
// set equality, not a minimum.
constexpr quint16 kManagedTcpPorts[3] = { 47989, 47984, 48010 };
constexpr quint16 kManagedUdpPorts[3] = { 47998, 47999, 48000 };

//: Ports that may never be used as the OUTER transport endpoints.
constexpr quint16 kForbiddenOuterPorts[] = { 47989, 47984, 48010, 47998, 47999,
                                             48000, 47990, 48001 };

constexpr int kManagedMinHandshakeMs = 1000;
constexpr int kManagedMaxHandshakeMs = 60000;

//: Longest accepted configuration file; a small fixed bound so the parser can
//: not be used as a memory amplifier.
constexpr qint64 kManagedMaxConfigBytes = 64 * 1024;

enum class ManagedRuntimeError {
    Ok = 0,
    RootNotAbsolute,
    RootNotOnApprovedDrive,
    RootNotFound,
    RootIsReparse,
    ConfigPathNotAbsolute,
    ConfigOutsideRoot,
    ConfigNotRegularFile,
    ConfigTooLarge,
    ConfigReadFailed,
    ConfigParseError,
    ConfigVersionUnsupported,
    ConfigUnknownField,
    ConfigMissingField,
    ConfigTypeMismatch,
    OriginInvalid,
    ClientInstallationIdInvalid,
    ClientKeyVersionInvalid,
    ExecutablePathNotAbsolute,
    ExecutableOutsideRoot,
    ExecutableNotFound,
    ExecutableIsReparse,
    ExecutableHashInvalid,
    PeerHostIdInvalid,
    PeerInstallationIdInvalid,
    PeerKeyVersionInvalid,
    PeerPublicKeyInvalid,
    PeerHostAppVersionInvalid,
    PeerEndpointInvalid,
    LocalEndpointInvalid,
    EndpointsNotDistinct,
    TimeoutInvalid
};

struct ManagedRuntimeValidation {
    ManagedRuntimeError error = ManagedRuntimeError::Ok;
    QString detail; // fixed, non-secret English detail owned by this module

    bool ok() const { return error == ManagedRuntimeError::Ok; }
};

//: Stable, non-secret printable reason (safe for logs; never contains user
//: input, a path or an identifier).
QString managedRuntimeErrorReason(ManagedRuntimeError error);

//: Canonical numeric IPv4 endpoint used for the outer transport.
struct ManagedQuicEndpoint {
    QString ipv4;   // strict dotted quad, no leading zeros
    quint16 port = 0;

    QString toString() const { return ipv4 + QLatin1Char(':') + QString::number(port); }
};

struct ManagedRuntimeConfig {
    QString approvedRoot;            // absolute, existing, non-reparse directory on D:
    QString configFilePath;          // absolute regular file inside approvedRoot
    QString apiOrigin;               // canonical "https://host[:port]"
    QString clientInstallationId;    // canonical UUID4, pinned
    int clientKeyVersion = 0;        // >= 1, pinned

    QString sidecarExecutablePath;   // absolute regular file inside approvedRoot
    QString sidecarExecutableSha256; // 64 lowercase hex

    QString hostId;             // canonical UUID4
    QString hostInstallationId; // canonical UUID4
    int hostKeyVersion = 0;     // >= 1
    QByteArray hostPublicKey;   // canonical standard base64 decoding to 32 bytes
    // Pinned GameStream host app version used for the native PIN exchange.
    // Taken from the operator manifest so a QML page can never choose it.
    QString hostAppVersion;

    ManagedQuicEndpoint peerQuic;  // outer peer endpoint (lab IPv4, never loopback)
    ManagedQuicEndpoint localQuic; // outer local endpoint (lab IPv4, never loopback)

    int handshakeTimeoutMs = 0; // kManagedMinHandshakeMs..kManagedMaxHandshakeMs
};

// Loads and fully validates the configuration.  On failure `out` is untouched
// and `why` carries a fixed reason.  No network access, no process launch, no
// filesystem write.  Every path is opened with FILE_FLAG_OPEN_REPARSE_POINT and
// re-checked on the handle, so a junction swap between check and read cannot
// redirect the read.
bool loadManagedRuntimeConfig(const QString& approvedRoot, const QString& configFilePath,
                              ManagedRuntimeConfig& out, ManagedRuntimeValidation& why);

// Validates an already-parsed configuration (used by the loader and tests).
bool validateManagedRuntimeConfig(const ManagedRuntimeConfig& config,
                                  ManagedRuntimeValidation& why);

// Strict helpers, also used by the sidecar frame validator.
bool isCanonicalSha256Hex(const QString& text);
bool isFixedIpv4Literal(const QString& text, bool allowLoopback);
// Exact set equality against one locked GameStream group (TCP or UDP).
bool isExactPortGroup(const quint16* ports, const quint16 (&expected)[3]);
bool isCanonicalEd25519PublicKey(const QByteArray& base64Text);
// Strict canonical UUID4 (lowercase, version nibble 4, variant 8..b).
bool isCanonicalUuid4Text(const QString& text);
// Canonical bare HTTPS origin ("https://host[:port]", no path/query/fragment,
// port omitted iff 443).  On success writes the canonical spelling.
bool canonicalHttpsOrigin(const QString& text, QString* canonicalOut);
// "<ipv4>:<port>" with a strict dotted quad and a decimal port 1..65535.
bool parseNumericEndpoint(const QString& text, ManagedQuicEndpoint& out);
bool isForbiddenOuterPort(quint16 port);

// --- Pinned launch helper (used by KanadeSidecar) ---------------------------
//
// Opens the executable through the SAME pinned object graph the manifest was
// validated with, verifies its SHA-256 from that handle, and hands back the open
// file handle plus every pinned ancestor directory handle.  The caller must keep
// them open across CreateProcess/QProcess::started and release them with
// closePinnedLaunchHandles(); that is what closes the hash->launch TOCTOU window.
//
// Returns false with a fixed (non-secret) reason on any refusal.  `ossl-free`.
bool openPinnedLaunchTarget(const QString& approvedRoot, const QString& executablePath,
                            const QString& expectedSha256, void*& fileHandleOut,
                            QList<void*>& pinnedHandleOut, QString& reason);
void closePinnedLaunchHandles(void* fileHandle, QList<void*>& pinnedHandles);

} // namespace Kanade

#endif // KANADERUNTIMECONFIG_H
