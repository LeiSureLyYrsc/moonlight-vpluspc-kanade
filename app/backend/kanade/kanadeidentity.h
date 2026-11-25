#pragma once

#ifndef KANADEIDENTITY_H
#define KANADEIDENTITY_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QUrl>

// Kanade online-mode installation identity (client role).
//
// This module is the client-side counterpart of Kanade
// src/kanade/security/identity.py.  It implements, with the OpenSSL already
// linked by Moonlight (no new dependencies):
//
//   * Ed25519 installation key generation and proof signing
//     (enrollment and device-login canonical messages, byte-exact with
//     enrollment_message()/device_login_message()).
//   * Windows current-user DPAPI (CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN)
//     protection of the private seed, with entropy scoped by canonical HTTPS
//     origin, user ID, role ("client"), installation ID and key version.
//   * Atomic persistence under a caller-approved root with a strict
//     current-user (+ SYSTEM) ACL and reparse-point rejection.  The root and
//     the store file are pinned by handle; every read, replace and delete is
//     handle-relative and re-verifies the object's identity, type and DACL.
//
// Wire-format notes (must match the server exactly):
//   * public_key / proof on the wire are the CANONICAL spelling produced by
//     the server: standard base64 WITH padding (see canonicalize_public_key()
//     and sign_message() in security/identity.py).  The server accepts
//     url-safe spellings on input, but the canonical message it signs embeds
//     the standard padded form, so this module stores and emits exactly that.
//   * Canonical messages are deterministic JSON: sorted keys, compact
//     separators, UTF-8, no trailing newline.  They are rebuilt locally and
//     compared byte-exact against Challenge.canonical_message before signing;
//     a mismatch fails closed (empty proof), so the client never signs
//     arbitrary server-supplied text.
//   * This module is client-role only: a challenge echoing role "host" is
//     rejected.  Labels are not used: any non-null "label" echo is rejected
//     and the enrollment message always carries "label":null.
//   * Origins must be a bare HTTPS origin: host (ACE-normalized, IPv6
//     literals rejected), optional non-default port; path, query, fragment,
//     userinfo and explicit :0 are rejected.
//   * challenge_id / installation_id must be canonical lowercase UUID
//     strings, nonce must be 43 unpadded base64url characters, expires_at a
//     positive Unix timestamp no later than 2100-01-01.
//
// Security boundaries:
//   * Access/refresh tokens, passwords, pair codes and tickets are NOT handled
//     here and must stay memory-only (plan section 3.4).
//   * Non-Windows builds fail closed: every IdentityStore operation reports
//     Unsupported/false (and the module refuses to build without OpenSSL).
//     There is deliberately no plaintext fallback.
//   * Windows desktop builds compile the store by default.  Defining
//     KANADE_DISABLE_WIN32_IDENTITY compiles it out again (it then reports
//     Unsupported); that switch exists for platform-port/packaging reasons,
//     not as a permissive mode, and never enables a weaker store.
//   * Secrets are never logged by this module.
namespace Kanade {

// An Ed25519 installation identity.  privateKey/publicKey are canonical
// standard-base64 (padded) encodings of the raw 32-byte seed and public key.
// installationId is empty while registration is still pending (the identity
// is persisted before POST /installations so a lost response can be retried
// idempotently with the same key).
struct InstallationIdentity {
    QByteArray privateKey;
    QByteArray publicKey;
    QString installationId;
    int keyVersion = 1;
};

// Generates a fresh Ed25519 identity (installationId empty, keyVersion 1).
// On RNG/OpenSSL failure every field is empty; callers MUST treat an empty
// privateKey as failure and must not persist or use the result.
InstallationIdentity generateIdentity();

// Signs an enrollment challenge (POST /installations/challenge response).
//
// The canonical message is rebuilt locally from challenge fields plus the
// caller-supplied userId, identity.keyVersion and identity.publicKey, then
// compared byte-exact with challenge["canonical_message"].  Any echoed
// public_key/key_version must match the identity; labels are rejected.
//
// Returns the standard-base64 (padded) Ed25519 proof exactly as expected by
// the server's b64decode(), or an empty QByteArray on any validation,
// comparison or crypto failure.  Never signs on mismatch.
QByteArray signRegistration(const QUrl& origin,
                            const QString& userId,
                            const InstallationIdentity& identity,
                            const QJsonObject& challenge);

// Signs a device-login challenge (POST /auth/device-challenge response).
// Same fail-closed semantics as signRegistration().  Requires a canonical
// UUID identity.installationId (the challenge response does not carry it;
// an echoed installation_id, if present, must match).
QByteArray signDeviceToken(const QUrl& origin,
                           const QString& userId,
                           const InstallationIdentity& identity,
                           const QJsonObject& challenge);

// DPAPI-backed persistence of installation identities, one file per
// (canonical HTTPS origin, user ID, role "client") under an approved root.
class IdentityStore {
public:
    // Distinguishes "no identity yet" (safe to generate one) from "identity
    // exists but could not be loaded" (must NOT silently generate a new key:
    // fail closed and surface the error).
    enum class LoadResult {
        Ok,          // identity loaded and keypair verified
        NotFound,    // no stored identity for this origin/user (safe to create)
        Unsupported, // non-Windows platform: persistence unavailable
        Error        // corrupt, tampered, ACL/reparse/DPAPI/keypair failure
    };

    // True only when this build carries a store that can persist secrets
    // safely (Windows desktop, not compiled out).  Callers may use it to
    // report an unavailable feature without fabricating a successful login;
    // a false value never means "use a weaker store".
    static bool platformSupported();

    // approvedRoot must be an absolute path inside the caller-approved tree
    // (plan: approved D-drive tree only), on a fixed local volume and outside
    // the Windows directory.  It is created on demand by save().  Any
    // junction/reparse point in the resolved path fails closed.
    explicit IdentityStore(QString approvedRoot);

    // Full-result load.  *out is only modified when Ok is returned.
    LoadResult loadResult(const QUrl& origin, const QString& userId, InstallationIdentity& out);

    // Convenience wrapper: true only when loadResult() == Ok.
    bool load(const QUrl& origin, const QString& userId, InstallationIdentity& out);

    // Validates the identity (32-byte seed, keypair consistency, key version),
    // DPAPI-protects the seed and atomically replaces the store file with a
    // current-user-only ACL.  Also used to persist the pending key before
    // registration and to re-save with the assigned installationId afterwards.
    bool save(const QUrl& origin, const QString& userId, const InstallationIdentity& identity);

    // Removes the local material for this origin/user ("forget this
    // installation").  Idempotent: a missing file is success.  This is purely
    // local; remote revocation is a separate explicit action.
    bool forget(const QUrl& origin, const QString& userId);

private:
    QString m_approvedRoot;
};

#ifdef KANADE_IDENTITY_TEST_HOOKS
// Introspection for the Windows storage test target
// (tests/kanade_identity_win32).  Compiled only when that target defines
// KANADE_IDENTITY_TEST_HOOKS.  These expose no way to weaken the store's
// behaviour and no way to read a seed: the only mutating helper
// (widenDaclToEveryone) plants a WIDER DACL so the negative tests can prove the
// store refuses it, and it is never reachable from a product build.
namespace IdentityTestHooks {
// True when the object at path is a real (non-reparse) object of the expected
// type whose DACL is exactly current-user + SYSTEM, protected.
bool aclIsPrivate(const QString& path, bool directory);
// True when the object at path is a real (non-reparse) object of that type.
bool objectIsPlain(const QString& path, bool directory);
// Hard link count of a file, or -1 when it cannot be opened/inspected.
int linkCount(const QString& path);
// Store file name for a scope, or empty when the scope is invalid.
QString fileNameForScope(const QUrl& origin, const QString& userId);
// True when the approved-root rules accept this path (absolute drive path on a
// fixed local non-system volume, outside the Windows directory, not a mounted
// folder or reparse point).
bool rootIsAccepted(const QString& approvedRoot);
// Test-only: apply an inheritable Everyone/owner/SYSTEM DACL to the object.
bool widenDaclToEveryone(const QString& path, bool directory);
} // namespace IdentityTestHooks
#endif // KANADE_IDENTITY_TEST_HOOKS

} // namespace Kanade

#endif // KANADEIDENTITY_H
