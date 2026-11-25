#include "kanadeidentity.h"

#include <QCryptographicHash>
#include <QDir>
#include <QJsonDocument>
#include <QRandomGenerator>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>
#endif

// Canonical signed payload domain constants.  These MUST stay byte-identical
// to Kanade src/kanade/security/identity.py.
static const char* const kAudience = "kanade";
static const char* const kEnrollmentType = "kanade.installation.enrollment";
static const char* const kDeviceLoginType = "kanade.device.login";
static const char* const kRole = "client";
static const int kMessageVersion = 1;
static const int kKeyVersionMin = 1;
static const int kKeyVersionMax = 2147483647; // server schema bound
static const int kMaxUserIdLen = 256;
static const int kMaxInstallationIdLen = 64;
static const qint64 kMaxEnvelopeBytes = 16 * 1024;
// Challenge expiry must be a positive Unix timestamp; 4102444800 is
// 2100-01-01T00:00:00Z, far beyond any legitimate challenge TTL (120 s).
static const qint64 kMaxExpiresAt = 4102444800LL;

namespace {

// ------------------------------------------------------------------------ //
// Canonical base64 (standard alphabet, padded) matching security/identity.py
// b64decode/b64encode.  Decoding tolerates url-safe spellings, missing
// padding and whitespace; the canonical spelling is what is stored/compared.
// ------------------------------------------------------------------------ //

QByteArray strictB64Decode(const QByteArray& text)
{
    QByteArray compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        compact.append(c == '-' ? '+' : (c == '_' ? '/' : c));
    }
    if (compact.isEmpty() || (compact.size() % 4) == 1) {
        return QByteArray();
    }
    // Validate the alphabet and padding ourselves: QByteArray::fromBase64
    // silently truncates at the first invalid character even with
    // AbortOnBase64DecodingErrors, which would accept corrupt keys.
    bool seenPadding = false;
    int paddingCount = 0;
    for (char c : compact) {
        const bool inAlphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (c == '=') {
            seenPadding = true;
            if (++paddingCount > 2) {
                return QByteArray();
            }
        }
        else if (!inAlphabet || seenPadding) {
            return QByteArray();
        }
    }
    const int padding = (4 - (compact.size() % 4)) % 4;
    for (int i = 0; i < padding; ++i) {
        compact.append('=');
    }
    return QByteArray::fromBase64(compact, QByteArray::Base64Encoding);
}

QByteArray canonicalB64(const QByteArray& text)
{
    return strictB64Decode(text).toBase64();
}

// ------------------------------------------------------------------------ //
// Canonical JSON writer.  Hand-built (not QJsonDocument) so the output is
// guaranteed to match Python json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False): sorted keys, no whitespace, short escapes for the six
// control characters, \u00xx for other <0x20, non-ASCII passed through as
// UTF-8.  Keys here are already listed in sorted order.
// ------------------------------------------------------------------------ //

void appendJsonString(QString& out, const QString& value)
{
    out += QLatin1Char('"');
    for (const QChar c : value) {
        switch (c.unicode()) {
        case '"': out += QStringLiteral("\\\""); break;
        case '\\': out += QStringLiteral("\\\\"); break;
        case '\b': out += QStringLiteral("\\b"); break;
        case '\f': out += QStringLiteral("\\f"); break;
        case '\n': out += QStringLiteral("\\n"); break;
        case '\r': out += QStringLiteral("\\r"); break;
        case '\t': out += QStringLiteral("\\t"); break;
        default:
            if (c.unicode() < 0x20) {
                out += QStringLiteral("\\u%1").arg(static_cast<uint>(c.unicode()), 4, 16, QLatin1Char('0'));
            }
            else {
                out += c;
            }
        }
    }
    out += QLatin1Char('"');
}

// ------------------------------------------------------------------------ //
// Ed25519 via OpenSSL EVP (already linked by Moonlight; no new dependency).
// ------------------------------------------------------------------------ //

QByteArray ed25519SeedFromIdentity(const Kanade::InstallationIdentity& identity, bool* ok)
{
    *ok = false;
    QByteArray seed = strictB64Decode(identity.privateKey);
    if (seed.size() != 32) {
        return QByteArray();
    }
    *ok = true;
    return seed;
}

// Derives the canonical public key from the 32-byte seed.  Returns empty for
// anything that is not exactly 32 bytes: passing a short buffer to OpenSSL with
// a hardcoded length would be an out-of-bounds read.
QByteArray ed25519DerivePublic(const QByteArray& seed)
{
    QByteArray result;
    if (seed.size() != 32) {
        return result;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(seed.constData()), 32);
    if (pkey == nullptr) {
        return result;
    }
    unsigned char raw[32];
    size_t rawLen = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &rawLen) == 1 && rawLen == 32) {
        result = QByteArray(reinterpret_cast<const char*>(raw), 32);
    }
    EVP_PKEY_free(pkey);
    return result;
}

// True when identity.privateKey is a 32-byte seed whose derived public key
// exactly matches identity.publicKey (canonical spellings).
bool identityKeypairConsistent(const Kanade::InstallationIdentity& identity)
{
    bool ok = false;
    const QByteArray seed = ed25519SeedFromIdentity(identity, &ok);
    if (!ok) {
        return false;
    }
    return canonicalB64(identity.publicKey) == ed25519DerivePublic(seed).toBase64();
}

QByteArray ed25519Sign(const QByteArray& seed, const QByteArray& message)
{
    QByteArray signature;
    if (seed.size() != 32 || message.isEmpty()) {
        return signature; // never hand a short/odd buffer to OpenSSL
    }
    EVP_PKEY* pkey = nullptr;
    EVP_MD_CTX* ctx = nullptr;
    pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(seed.constData()), 32);
    if (pkey != nullptr) {
        ctx = EVP_MD_CTX_new();
        if (ctx != nullptr &&
            EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
            size_t sigLen = 64;
            signature.resize(static_cast<int>(sigLen));
            if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(signature.data()),
                               &sigLen, reinterpret_cast<const unsigned char*>(message.constData()),
                               static_cast<size_t>(message.size())) != 1) {
                signature.clear();
            }
            else {
                signature.resize(static_cast<int>(sigLen));
            }
        }
    }
    if (ctx != nullptr) {
        EVP_MD_CTX_free(ctx);
    }
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    return signature;
}

// ------------------------------------------------------------------------ //
// Shared signable-message construction (cross-platform, no crypto).
// ------------------------------------------------------------------------ //

bool canonicalOrigin(const QUrl& url, QString& out)
{
    if (!url.isValid() || url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0) {
        return false;
    }
    if (!url.userInfo().isEmpty() || !url.query().isEmpty() || !url.fragment().isEmpty()) {
        return false;
    }
    const QString path = url.path();
    if (!path.isEmpty() && path != QStringLiteral("/")) {
        return false; // only a bare origin scopes an identity
    }
    const QString host = url.host();
    if (host.isEmpty() || host.contains(QLatin1Char(':'))) {
        return false; // IPv6 literals are rejected consistently
    }
    const int rawPort = url.port();
    if (rawPort == 0 || rawPort > 65535) {
        return false;
    }
    const QString ace = QString::fromLatin1(QUrl::toAce(host)).toLower();
    if (ace.isEmpty()) {
        return false;
    }
    out = QStringLiteral("https://") + ace;
    if (rawPort != -1 && rawPort != 443) {
        out += QStringLiteral(":%1").arg(rawPort);
    }
    return true;
}

bool validScopedInput(const QString& userId)
{
    return !userId.isEmpty() && userId.size() <= kMaxUserIdLen;
}

bool validKeyVersion(int keyVersion)
{
    return keyVersion >= kKeyVersionMin && keyVersion <= kKeyVersionMax;
}

// Reads a required string field; present and of JSON string type.  Empty
// strings are accepted (a pending identity has an empty installation_id).
bool jsonStringField(const QJsonObject& object, const char* key, QString& out)
{
    const QJsonValue value = object.value(QLatin1String(key));
    if (!value.isString()) {
        return false;
    }
    out = value.toString();
    return true;
}

// Reads a required non-empty string field.
bool jsonNonEmptyStringField(const QJsonObject& object, const char* key, QString& out)
{
    return jsonStringField(object, key, out) && !out.isEmpty();
}

// Reads a required integer field that arrived as a JSON number.  JSON numbers
// are doubles; require an exact integer in a sane range.
bool jsonIntegerField(const QJsonObject& object, const char* key, qint64& out)
{
    const QJsonValue value = object.value(QLatin1String(key));
    if (!value.isDouble()) {
        return false;
    }
    const double d = value.toDouble();
    if (d < -9007199254740992.0 || d > 9007199254740992.0) {
        return false;
    }
    const qint64 i = static_cast<qint64>(d);
    if (static_cast<double>(i) != d) {
        return false;
    }
    out = i;
    return true;
}

// This client only ever acts in the "client" installation role.  A challenge
// echoing any other role (e.g. "host") must never be signed here.
bool validRole(const QString& role)
{
    return role == QStringLiteral("client");
}

// Server identifiers are lowercase uuid4 strings (security/identity.py new_id).
bool isCanonicalUuid(const QString& value)
{
    if (value.size() != 36) {
        return false;
    }
    for (int i = 0; i < 36; ++i) {
        const QChar c = value.at(i);
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != QLatin1Char('-')) {
                return false;
            }
        }
        else if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                   (c >= QLatin1Char('a') && c <= QLatin1Char('f')))) {
            return false;
        }
    }
    return true;
}

// generate_nonce() is 32 random bytes as unpadded base64url: 43 chars.
bool isCanonicalNonce(const QString& value)
{
    if (value.size() != 43) {
        return false;
    }
    for (const QChar c : value) {
        const bool ok = (c >= QLatin1Char('A') && c <= QLatin1Char('Z')) ||
                        (c >= QLatin1Char('a') && c <= QLatin1Char('z')) ||
                        (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                        c == QLatin1Char('-') || c == QLatin1Char('_');
        if (!ok) {
            return false;
        }
    }
    return true;
}

// If the challenge echoes a purpose, it must match what this function signs.
bool purposeMatches(const QJsonObject& challenge, const char* expected)
{
    const QJsonValue value = challenge.value(QStringLiteral("purpose"));
    if (value.isUndefined() || value.isNull()) {
        return true; // older/leaner server responses: rebuild+compare is the gate
    }
    return value.isString() && value.toString() == QLatin1String(expected);
}

// Rebuilds the enrollment canonical message (sorted keys, compact, UTF-8).
// Returns false without modifying out on any field problem.
bool buildEnrollmentMessage(const QString& userId,
                            const Kanade::InstallationIdentity& identity,
                            const QJsonObject& challenge,
                            QString& out)
{
    QString challengeId, nonce, role;
    qint64 expiresAt = 0;
    if (!jsonNonEmptyStringField(challenge, "challenge_id", challengeId) ||
        !isCanonicalUuid(challengeId) ||
        !jsonNonEmptyStringField(challenge, "nonce", nonce) || !isCanonicalNonce(nonce) ||
        !jsonIntegerField(challenge, "expires_at", expiresAt) || expiresAt <= 0 ||
        expiresAt > kMaxExpiresAt ||
        !jsonNonEmptyStringField(challenge, "role", role) || !validRole(role) ||
        !validKeyVersion(identity.keyVersion) ||
        !validScopedInput(userId) ||
        !identityKeypairConsistent(identity)) {
        return false;
    }

    // The public key we sign over must be the canonical spelling of OUR key;
    // the server canonicalizes its own copy, so it must match byte-exact.
    QString publicKey = QString::fromLatin1(canonicalB64(identity.publicKey));
    const QJsonValue serverPublicKey = challenge.value(QStringLiteral("public_key"));
    if (!serverPublicKey.isUndefined() && !serverPublicKey.isNull()) {
        if (!serverPublicKey.isString()) {
            return false;
        }
        if (canonicalB64(serverPublicKey.toString().toLatin1()) != publicKey.toLatin1()) {
            return false;
        }
    }

    // Optional key_version echo must agree with the identity being enrolled.
    const QJsonValue keyVersionEcho = challenge.value(QStringLiteral("key_version"));
    if (!keyVersionEcho.isUndefined() && !keyVersionEcho.isNull()) {
        qint64 echoed = 0;
        if (!jsonIntegerField(challenge, "key_version", echoed) ||
            echoed != identity.keyVersion) {
            return false;
        }
    }

    // Labels are not used by this client: never sign one implicitly.  The
    // canonical message therefore always carries "label":null.
    const QJsonValue labelValue = challenge.value(QStringLiteral("label"));
    if (!labelValue.isUndefined() && !labelValue.isNull()) {
        return false;
    }

    out.clear();
    out += QStringLiteral("{\"aud\":");
    appendJsonString(out, QString::fromLatin1(kAudience));
    out += QStringLiteral(",\"challenge_id\":");
    appendJsonString(out, challengeId);
    out += QStringLiteral(",\"expires_at\":");
    out += QString::number(expiresAt);
    out += QStringLiteral(",\"key_version\":");
    out += QString::number(identity.keyVersion);
    out += QStringLiteral(",\"label\":null");
    out += QStringLiteral(",\"nonce\":");
    appendJsonString(out, nonce);
    out += QStringLiteral(",\"public_key\":");
    appendJsonString(out, publicKey);
    out += QStringLiteral(",\"role\":");
    appendJsonString(out, role);
    out += QStringLiteral(",\"type\":");
    appendJsonString(out, QString::fromLatin1(kEnrollmentType));
    out += QStringLiteral(",\"user_id\":");
    appendJsonString(out, userId);
    out += QStringLiteral(",\"v\":");
    out += QString::number(kMessageVersion);
    out += QLatin1Char('}');
    return true;
}

// Rebuilds the device-login canonical message.
bool buildDeviceLoginMessage(const QString& userId,
                             const Kanade::InstallationIdentity& identity,
                             const QJsonObject& challenge,
                             QString& out)
{
    QString challengeId, nonce, role;
    qint64 expiresAt = 0;
    if (!jsonNonEmptyStringField(challenge, "challenge_id", challengeId) ||
        !isCanonicalUuid(challengeId) ||
        !jsonNonEmptyStringField(challenge, "nonce", nonce) || !isCanonicalNonce(nonce) ||
        !jsonIntegerField(challenge, "expires_at", expiresAt) || expiresAt <= 0 ||
        expiresAt > kMaxExpiresAt ||
        !jsonNonEmptyStringField(challenge, "role", role) || !validRole(role) ||
        !validScopedInput(userId) || !isCanonicalUuid(identity.installationId) ||
        !identityKeypairConsistent(identity)) {
        return false;
    }

    // Optional installation_id echo must match the identity being used.
    const QJsonValue installationEcho = challenge.value(QStringLiteral("installation_id"));
    if (!installationEcho.isUndefined() && !installationEcho.isNull()) {
        if (!installationEcho.isString() ||
            installationEcho.toString() != identity.installationId) {
            return false;
        }
    }

    out.clear();
    out += QStringLiteral("{\"aud\":");
    appendJsonString(out, QString::fromLatin1(kAudience));
    out += QStringLiteral(",\"challenge_id\":");
    appendJsonString(out, challengeId);
    out += QStringLiteral(",\"expires_at\":");
    out += QString::number(expiresAt);
    out += QStringLiteral(",\"installation_id\":");
    appendJsonString(out, identity.installationId);
    out += QStringLiteral(",\"nonce\":");
    appendJsonString(out, nonce);
    out += QStringLiteral(",\"role\":");
    appendJsonString(out, role);
    out += QStringLiteral(",\"type\":");
    appendJsonString(out, QString::fromLatin1(kDeviceLoginType));
    out += QStringLiteral(",\"user_id\":");
    appendJsonString(out, userId);
    out += QStringLiteral(",\"v\":");
    out += QString::number(kMessageVersion);
    out += QLatin1Char('}');
    return true;
}

// Common fail-closed signer: rebuild, byte-exact compare, sign.
QByteArray signChallenge(const QString& userId,
                         const Kanade::InstallationIdentity& identity,
                         const QJsonObject& challenge,
                         bool (*builder)(const QString&, const Kanade::InstallationIdentity&,
                                         const QJsonObject&, QString&),
                         const char* purpose)
{
    if (!purposeMatches(challenge, purpose)) {
        return QByteArray();
    }
    QString rebuilt;
    if (!builder(userId, identity, challenge, rebuilt)) {
        return QByteArray();
    }
    const QJsonValue canonical = challenge.value(QStringLiteral("canonical_message"));
    if (!canonical.isString() || canonical.toString() != rebuilt) {
        return QByteArray(); // never sign anything we could not rebuild exactly
    }
    bool ok = false;
    const QByteArray seed = ed25519SeedFromIdentity(identity, &ok);
    if (!ok) {
        return QByteArray();
    }
    // The wire proof is the canonical standard-base64 (padded) spelling of the
    // raw 64-byte signature, exactly what sign_message() returns server-side.
    return ed25519Sign(seed, rebuilt.toUtf8()).toBase64();
}

} // namespace

namespace Kanade {

InstallationIdentity generateIdentity()
{
    InstallationIdentity identity;
    EVP_PKEY_CTX* keygenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (keygenCtx == nullptr ||
        EVP_PKEY_keygen_init(keygenCtx) != 1 ||
        EVP_PKEY_keygen(keygenCtx, &pkey) != 1) {
        EVP_PKEY_CTX_free(keygenCtx);
        return identity; // empty privateKey == failure
    }
    EVP_PKEY_CTX_free(keygenCtx);

    unsigned char seed[32];
    size_t seedLen = sizeof(seed);
    unsigned char publicKey[32];
    size_t publicKeyLen = sizeof(publicKey);
    if (EVP_PKEY_get_raw_private_key(pkey, seed, &seedLen) == 1 && seedLen == 32 &&
        EVP_PKEY_get_raw_public_key(pkey, publicKey, &publicKeyLen) == 1 && publicKeyLen == 32) {
        identity.privateKey = QByteArray(reinterpret_cast<const char*>(seed), 32).toBase64();
        identity.publicKey = QByteArray(reinterpret_cast<const char*>(publicKey), 32).toBase64();
        identity.installationId.clear();
        identity.keyVersion = 1;
    }
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(publicKey, sizeof(publicKey));
    EVP_PKEY_free(pkey);
    return identity;
}

QByteArray signRegistration(const QUrl& origin,
                            const QString& userId,
                            const InstallationIdentity& identity,
                            const QJsonObject& challenge)
{
    QString originCanon;
    if (!canonicalOrigin(origin, originCanon)) {
        return QByteArray(); // enrollment is only ever bound to an HTTPS origin
    }
    return signChallenge(userId, identity, challenge, &buildEnrollmentMessage, "enrollment");
}

QByteArray signDeviceToken(const QUrl& origin,
                           const QString& userId,
                           const InstallationIdentity& identity,
                           const QJsonObject& challenge)
{
    QString originCanon;
    if (!canonicalOrigin(origin, originCanon)) {
        return QByteArray();
    }
    return signChallenge(userId, identity, challenge, &buildDeviceLoginMessage, "device_login");
}

// --------------------------------------------------------------------------- //
// IdentityStore: Windows DPAPI persistence.
//
// Compiled by default for Windows desktop builds.  A build that must not carry
// the store can define KANADE_DISABLE_WIN32_IDENTITY; the class then reports
// Unsupported and every operation fails closed.  There is no plaintext
// fallback in either configuration.
//
// Race resistance (plan 3.4).  Every operation pins the approved root with a
// HANDLE and proves that the opened object is the requested directory by
// comparing the normalized final path AND the volume/file id; afterwards all
// I/O is performed relative to that pinned object:
//   * children are opened with FILE_FLAG_OPEN_REPARSE_POINT, so a junction or
//     symlink is inspected, never traversed, and any reparse tag fails closed;
//   * the opened child's parent directory identity must equal the pinned
//     root's file id, so a swapped path component cannot redirect the I/O;
//   * reads consume the very handle that was verified (never re-opened by
//     path);
//   * the atomic replace is SetFileInformationByHandle(FileRenameInfo) with
//     RootDirectory = the pinned root handle and a bare file name;
//   * forget() deletes through FileDispositionInfo on a verified handle.
//
// The private DACL (current user + SYSTEM, inheritance blocked) is supplied at
// creation time, so the file never exists with a wider ACL even briefly, and
// is re-verified through the handle on every open.  A missing or unprotected
// DACL, an inherited or foreign ACE, an unexpected owner, a reparse tag, a
// foreign parent directory id or a non-fixed volume all fail closed.
//
// DPAPI is current-user scope (never CRYPTPROTECT_LOCAL_MACHINE).  The sealed
// plaintext is self-describing and is cross-checked against the requested
// origin/user/installation/key version after decryption, on top of the
// scope-bound entropy, so a blob copied to another scope can never be used.
// --------------------------------------------------------------------------- //

IdentityStore::IdentityStore(QString approvedRoot)
    : m_approvedRoot(std::move(approvedRoot))
{
}

#if defined(Q_OS_WIN) && !defined(Q_OS_WINRT) && !defined(KANADE_DISABLE_WIN32_IDENTITY)

// Invariant (plan 3.4).  There is no Win32 API that creates a file relative to
// a directory handle, so safety comes from PINNING EVERY COMPONENT:
//
//   1. The path is resolved top-down from the volume root.  Each component is
//      opened with CreateFile (FILE_FLAG_OPEN_REPARSE_POINT, BACKUP_SEMANTICS)
//      and HELD for the whole operation with share = READ|WRITE and NO
//      FILE_SHARE_DELETE.  Per CreateFileW's documented semantics, delete
//      access "allows both delete and rename operations" and is refused unless
//      existing handles granted FILE_SHARE_DELETE, so no pinned component can
//      be renamed, replaced or deleted by anyone while the operation runs.
//   2. Sharing is enforced per object, not against descendants, so pinning a
//      directory still allows creating/renaming/deleting entries inside it.
//      No DELETE access is requested on pinned directories, so this process's
//      own concurrent operations (which also grant READ|WRITE) coexist with no
//      extra lock.
//   3. Each opened component must be a real directory (no reparse tag) and must
//      be strictly under the previously pinned component's own final path.
//      Because the parent is pinned without delete sharing it cannot have been
//      renamed, so that prefix relation proves the child really lives inside
//      the pinned object rather than in a substituted look-alike tree.
//   4. Rights are minimal per component: the volume root and intermediate
//      directories get traverse/list/read-attribute/read-control/synchronize
//      only (a normal user has no FILE_ADD_FILE on a drive root), and only the
//      approved-root leaf additionally gets FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY
//      (it is ours, with a private DACL, so those are always granted).
//   5. Only the leaf is created with the private DACL, supplied in
//      CreateDirectoryW's SECURITY_ATTRIBUTES, so it never exists with a wider
//      ACL.  There is NO post-open ACL rewrite anywhere: an existing leaf that
//      is not already private, or whose owner is untrusted, is REFUSED.
//   6. The root must be on a fixed local volume whose volume GUID differs from
//      the volume that hosts Windows (compared by GUID, not by drive letter),
//      outside the Windows directory, and not under a mounted folder.
//   7. Files are created with CREATE_NEW and the private DACL supplied at
//      creation; the atomic replace is handle-relative (FileRenameInfo with
//      RootDirectory = the pinned leaf handle and a bare file name).
//   8. No failure path mutates by path.  The rename result is verified by
//      comparing the file id associated with the name against the id held on
//      the still-open write handle; a mismatch disposes of that handle's object
//      only, never whatever the name now denotes.
//   9. Objects with more than one hard link are rejected on read, replace and
//      delete, so a planted hard link cannot make the store mutate an
//      unrelated file.

namespace {

constexpr int kMaxSealedBlobBytes = 64 * 1024;
const char kSealedPayloadMagic[] = "kanade-moonlight-qt/installation-seed/v1";

// Rights for a pinned directory.  None of these is DELETE, so the pin itself
// never requires FILE_SHARE_DELETE from us, and its share mask (below) is what
// blocks rename/replace/delete of the pinned object by anyone else.
constexpr DWORD kPinMinimumAccess =
    FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
// Intermediates additionally need listing so their contents can be inspected.
constexpr DWORD kPinIntermediateAccess = kPinMinimumAccess | FILE_LIST_DIRECTORY;
// The approved-root leaf is ours: it also allows creating the store file and
// resolving a rename target relative to the handle.
constexpr DWORD kPinLeafAccess =
    kPinIntermediateAccess | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;

// No FILE_SHARE_DELETE: blocks rename/replace/delete of the pinned object.
// Read-only pins on ancestors deny in-place reparse writes as well as rename.
// The private leaf uses compatible write sharing for store operations only.
constexpr DWORD kPinAncestorShare = FILE_SHARE_READ;
constexpr DWORD kPinLeafShare = FILE_SHARE_READ | FILE_SHARE_WRITE;

struct FileIdentity {
    quint64 volume = 0;
    quint64 index = 0;

    bool operator==(const FileIdentity& other) const
    {
        return volume == other.volume && index == other.index;
    }
};

class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : m_handle(handle) {}
    ~ScopedHandle() { reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle)
    {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept
    {
        if (this != &other) {
            reset(other.m_handle);
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const { return m_handle; }
    bool valid() const { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }

    void reset(HANDLE handle = INVALID_HANDLE_VALUE)
    {
        if (valid()) {
            CloseHandle(m_handle);
        }
        m_handle = handle;
    }

private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
};

QString nativePath(const QString& path)
{
    return QDir::toNativeSeparators(path);
}

const wchar_t* wide(const QString& path)
{
    return reinterpret_cast<const wchar_t*>(path.utf16());
}

// Compares two "\\?\"-prefixed final paths, ignoring one trailing separator.
bool sameWinPath(const QString& left, const QString& right)
{
    auto strip = [](QString value) {
        if (value.size() > 4 && value.endsWith(QLatin1Char('\\')) &&
            value.at(value.size() - 2) != QLatin1Char(':')) {
            value.chop(1);
        }
        return value;
    };
    return strip(left).compare(strip(right), Qt::CaseInsensitive) == 0;
}

// True when `childFinal` is a DIRECT child of `parentFinal`.  Both are
// "\\?\"-prefixed normalized final paths.  The parent is pinned without delete
// sharing, so it cannot have been renamed; a direct-child prefix relation with
// the parent's own final path therefore proves containment in that object.
bool isDirectChildFinalPath(const QString& childFinal, const QString& parentFinal)
{
    QString prefix = parentFinal;
    if (!prefix.endsWith(QLatin1Char('\\'))) {
        prefix += QLatin1Char('\\');
    }
    if (childFinal.size() <= prefix.size()) {
        return false;
    }
    if (childFinal.compare(0, prefix.size(), prefix, Qt::CaseInsensitive) != 0) {
        return false;
    }
    const QString rest = childFinal.mid(prefix.size());
    return !rest.isEmpty() && !rest.contains(QLatin1Char('\\')) &&
           rest != QStringLiteral(".") && rest != QStringLiteral("..");
}

// The current process token's user SID, valid while this object lives.
class TokenUserSid {
public:
    TokenUserSid()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return;
        }
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 0) {
            // LocalAlloc is suitably aligned for TOKEN_USER; a QByteArray is not
            // guaranteed to be.
            m_buffer = LocalAlloc(LMEM_FIXED, needed);
            DWORD written = 0;
            if (m_buffer != nullptr &&
                GetTokenInformation(token, TokenUser, m_buffer, needed, &written)) {
                m_sid = reinterpret_cast<PTOKEN_USER>(m_buffer)->User.Sid;
            }
        }
        CloseHandle(token);
    }

    ~TokenUserSid()
    {
        if (m_buffer != nullptr) {
            LocalFree(m_buffer);
        }
    }

    TokenUserSid(const TokenUserSid&) = delete;
    TokenUserSid& operator=(const TokenUserSid&) = delete;

    PSID sid() const { return m_sid; }
    bool valid() const { return m_sid != nullptr; }

private:
    HLOCAL m_buffer = nullptr;
    PSID m_sid = nullptr;
};

PSID allocateWellKnownSid(WELL_KNOWN_SID_TYPE type)
{
    DWORD size = SECURITY_MAX_SID_SIZE;
    auto* sid = static_cast<PSID>(LocalAlloc(LMEM_FIXED, size));
    if (sid == nullptr) {
        return nullptr;
    }
    if (!CreateWellKnownSid(type, nullptr, sid, &size)) {
        LocalFree(sid);
        return nullptr;
    }
    return sid;
}

bool ownerIsTrusted(PSID owner, PSID userSid, PSID systemSid)
{
    if (owner == nullptr || userSid == nullptr || systemSid == nullptr) {
        return false;
    }
    if (EqualSid(owner, userSid) || EqualSid(owner, systemSid)) {
        return true;
    }
    // An elevated process creates objects owned by BUILTIN\Administrators.
    // Ownership governs chown/chmod only; the DACL check is the security
    // boundary, so accepting it here cannot widen who may read the seed.
    PSID administrators = allocateWellKnownSid(WinBuiltinAdministratorsSid);
    const bool trusted = administrators != nullptr && EqualSid(owner, administrators);
    if (administrators != nullptr) {
        LocalFree(administrators);
    }
    return trusted;
}

// The one DACL this module ever writes: Full Control for the current user and
// SYSTEM, no inheritance.  Always supplied AT CREATION and never applied
// afterwards.
class PrivateDacl {
public:
    PrivateDacl() = default;
    ~PrivateDacl()
    {
        if (m_acl != nullptr) {
            LocalFree(m_acl);
        }
        if (m_systemSid != nullptr) {
            LocalFree(m_systemSid);
        }
    }

    PrivateDacl(const PrivateDacl&) = delete;
    PrivateDacl& operator=(const PrivateDacl&) = delete;

    bool build(PSID userSid)
    {
        if (userSid == nullptr) {
            return false;
        }
        m_systemSid = allocateWellKnownSid(WinLocalSystemSid);
        if (m_systemSid == nullptr) {
            return false;
        }
        EXPLICIT_ACCESS_W entries[2] = {};
        entries[0].grfAccessPermissions = GENERIC_ALL;
        entries[0].grfAccessMode = SET_ACCESS;
        entries[0].grfInheritance = NO_INHERITANCE;
        entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        entries[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(userSid);
        entries[1].grfAccessPermissions = GENERIC_ALL;
        entries[1].grfAccessMode = SET_ACCESS;
        entries[1].grfInheritance = NO_INHERITANCE;
        entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        entries[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(m_systemSid);
        return SetEntriesInAclW(2, entries, nullptr, &m_acl) == ERROR_SUCCESS && m_acl != nullptr;
    }

    bool prepareCreate(SECURITY_ATTRIBUTES& attributes)
    {
        if (m_acl == nullptr) {
            return false;
        }
        if (!InitializeSecurityDescriptor(&m_descriptor, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorDacl(&m_descriptor, TRUE, m_acl, FALSE)) {
            return false;
        }
        // Best effort: the DACL is already exact and grants nothing
        // inheritable, so the verified check after creation is authoritative.
        SetSecurityDescriptorControl(&m_descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        attributes.lpSecurityDescriptor = &m_descriptor;
        attributes.bInheritHandle = FALSE;
        return true;
    }

private:
    PACL m_acl = nullptr;
    PSID m_systemSid = nullptr;
    SECURITY_DESCRIPTOR m_descriptor = {};
};

bool pathIsReparsePoint(const QString& path)
{
    const DWORD attributes = GetFileAttributesW(wide(nativePath(path)));
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// Cheap path-based pre-filter only.  The authoritative check is the pinned
// component chain; this rejects obviously bad input before any handle is taken.
bool pathContainsReparsePoint(const QString& absolutePath)
{
    const QString clean = QDir::cleanPath(absolutePath);
    const QStringList parts = clean.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    QString prefix;
    for (int index = 0; index < parts.size(); ++index) {
        if (prefix.isEmpty()) {
            prefix = parts[index];
            if (prefix.endsWith(QLatin1Char(':'))) {
                prefix += QLatin1Char('/'); // drive root, not drive-relative
            }
        }
        else {
            prefix += QLatin1Char('/') + parts[index];
        }
        if (pathIsReparsePoint(prefix)) {
            return true;
        }
    }
    return false;
}

// Volume GUID (not a drive letter) for an existing directory path, or empty.
QString volumeGuid(const QString& directory)
{
    QString path = nativePath(directory);
    if (!path.endsWith(QLatin1Char('\\'))) {
        path += QLatin1Char('\\');
    }
    wchar_t name[MAX_PATH] = {};
    if (!GetVolumeNameForVolumeMountPointW(wide(path), name, MAX_PATH)) {
        return QString();
    }
    return QString::fromWCharArray(name).toUpper();
}

// "C:\" for the volume that hosts Windows.
QString systemVolumeRootPath()
{
    wchar_t directory[MAX_PATH] = {};
    if (GetSystemDirectoryW(directory, MAX_PATH) == 0) {
        return QString();
    }
    return QString::fromWCharArray(directory, 3);
}

// True when every existing component resolves to the drive root itself, i.e. no
// component is a mounted folder / volume mount point.  Walks up to the deepest
// existing component so it works for a root that save() is about to create.
bool volumeMountIsDriveRoot(const QString& absolutePath, const QString& volume)
{
    QString probe = absolutePath;
    wchar_t mountPoint[MAX_PATH] = {};
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (GetVolumePathNameW(wide(probe), mountPoint, MAX_PATH) != FALSE) {
            return sameWinPath(QString::fromWCharArray(mountPoint), volume);
        }
        const int separator = probe.lastIndexOf(QLatin1Char('/'));
        if (separator <= 2) {
            return false;
        }
        probe = probe.left(separator);
    }
    return false;
}

// Root rules enforced by the store itself:
//   * absolute, drive-letter path (no UNC, no device path);
//   * fixed local volume (DRIVE_FIXED, so no network/removable/ramdisk);
//   * the volume GUID must DIFFER from the volume hosting Windows, so the OS
//     volume is refused by identity rather than by a hardcoded drive letter;
//   * not inside the Windows directory;
//   * no component is a mounted folder / volume mount point.
//
// Production additionally restricts the tree to the approved D-drive location;
// that choice is the caller's (see kanadecontroller identityRoot()).  The store
// enforces the properties above for whatever root it is handed.
bool approvedLocalRoot(const QString& approvedRoot, QString& out)
{
    if (approvedRoot.isEmpty() || !QDir::isAbsolutePath(approvedRoot)) {
        return false;
    }
    const QString clean = QDir::cleanPath(approvedRoot);
    if (clean.startsWith(QStringLiteral("//")) || clean.size() <= 3 ||
        clean.at(1) != QLatin1Char(':') || clean.at(2) != QLatin1Char('/')) {
        return false;
    }
    const QString volume = nativePath(clean.left(2) + QStringLiteral("/"));
    if (GetDriveTypeW(wide(volume)) != DRIVE_FIXED) {
        return false;
    }

    const QString systemRoot = systemVolumeRootPath();
    if (systemRoot.isEmpty()) {
        return false;
    }
    const QString systemGuid = volumeGuid(systemRoot);
    const QString candidateGuid = volumeGuid(clean);
    if (systemGuid.isEmpty() || candidateGuid.isEmpty() || systemGuid == candidateGuid) {
        return false; // never the volume that hosts Windows
    }

    wchar_t windowsDirectory[MAX_PATH] = {};
    if (GetWindowsDirectoryW(windowsDirectory, MAX_PATH) == 0) {
        return false;
    }
    const QString windowsPath = QDir::cleanPath(QString::fromWCharArray(windowsDirectory));
    if (clean.compare(windowsPath, Qt::CaseInsensitive) == 0 ||
        clean.startsWith(windowsPath + QLatin1Char('/'), Qt::CaseInsensitive)) {
        return false;
    }
    if (!volumeMountIsDriveRoot(clean, volume)) {
        return false;
    }
    out = clean;
    return true;
}

QString finalPathOf(HANDLE handle)
{
    std::vector<wchar_t> buffer(512, L'\0');
    for (int attempt = 0; attempt < 4; ++attempt) {
        const DWORD written = GetFinalPathNameByHandleW(
            handle, buffer.data(), static_cast<DWORD>(buffer.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (written == 0) {
            return QString();
        }
        if (written < buffer.size()) {
            return QString::fromWCharArray(buffer.data(), static_cast<int>(written));
        }
        buffer.assign(static_cast<size_t>(written) + 1, L'\0');
    }
    return QString();
}

QString expectedFinalPath(const QString& absolutePath)
{
    QString normalized = nativePath(absolutePath);
    while (normalized.size() > 3 && normalized.endsWith(QLatin1Char('\\')) &&
           normalized.at(normalized.size() - 2) != QLatin1Char(':')) {
        normalized.chop(1);
    }
    return QStringLiteral("\\\\?\\") + normalized;
}

bool fileIdentityOf(HANDLE handle, FileIdentity& out)
{
    // Volume serial + file index, both read from the handle (never the path).
    // ReFS ids may exceed what is expressible here, but both sides of every
    // comparison use the same API, so equality still proves "same object" and
    // any mismatch only fails closed.
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(handle, &info)) {
        return false;
    }
    out.volume = static_cast<quint64>(info.dwVolumeSerialNumber);
    out.index = (static_cast<quint64>(info.nFileIndexHigh) << 32) |
                static_cast<quint64>(info.nFileIndexLow);
    return true;
}

// Handle-based reparse check: the object itself is inspected, never traversed.
bool plainObject(HANDLE handle)
{
    FILE_ATTRIBUTE_TAG_INFO info = {};
    return GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) != FALSE &&
           (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && info.ReparseTag == 0;
}

bool isDirectoryHandle(HANDLE handle)
{
    BY_HANDLE_FILE_INFORMATION info = {};
    return GetFileInformationByHandle(handle, &info) != FALSE &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// A second hard link means the object is reachable from somewhere this module
// never created; refuse to read, replace or delete it.
bool hasSingleLink(HANDLE handle)
{
    FILE_STANDARD_INFO info = {};
    return GetFileInformationByHandleEx(handle, FileStandardInfo, &info, sizeof(info)) != FALSE &&
           info.NumberOfLinks == 1;
}

// True only when the object's DACL is PRESENT, PROTECTED (inheritance blocked)
// and contains access-ALLOWED ACEs for the current user and SYSTEM exclusively,
// with the owner being the user, SYSTEM or Administrators.  Any other trustee,
// any inherited ACE, a missing or unprotected DACL, or a foreign owner fails.
bool aclIsPrivateHandle(HANDLE handle)
{
    TokenUserSid user;
    if (!user.valid()) {
        return false;
    }
    PSID systemSid = allocateWellKnownSid(WinLocalSystemSid);
    if (systemSid == nullptr) {
        return false;
    }

    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    bool ok = false;

    if (GetSecurityInfo(handle, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                        &dacl, nullptr, &descriptor) == ERROR_SUCCESS &&
        descriptor != nullptr && dacl != nullptr &&
        ownerIsTrusted(owner, user.sid(), systemSid)) {
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        ok = GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
             (control & SE_DACL_PRESENT) != 0 && (control & SE_DACL_PROTECTED) != 0;
        bool seenUser = false;
        for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
            LPVOID ace = nullptr;
            if (!GetAce(dacl, i, &ace) || ace == nullptr) {
                ok = false;
                break;
            }
            const auto* header = static_cast<const ACE_HEADER*>(ace);
            // Only plain allow ACEs are ever written; deny/object/audit/
            // callback ACEs and inherited ACEs are unexpected here.
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
                (header->AceFlags & INHERITED_ACE) != 0) {
                ok = false;
                break;
            }
            const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
            PSID trustee = const_cast<PSID>(static_cast<const void*>(&allowed->SidStart));
            if (EqualSid(trustee, user.sid())) {
                seenUser = true;
            }
            else if (!EqualSid(trustee, systemSid)) {
                ok = false;
            }
        }
        ok = ok && seenUser;
    }

    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    LocalFree(systemSid);
    return ok;
}

bool deleteOpenedObject(HANDLE object)
{
    FILE_DISPOSITION_INFO info = {};
    info.DeleteFile = TRUE;
    return SetFileInformationByHandle(object, FileDispositionInfo, &info, sizeof(info)) != FALSE;
}

enum class RootState { Ok, Missing, Rejected };
enum class StepState { Ok, Missing, Rejected };

// One pinned directory in the resolved chain.
struct PinnedDirectory {
    ScopedHandle handle;
    FileIdentity identity;
    QString path;      // native path used to reach it
    QString finalPath; // "\\?\"-normalized final path from the handle
};

// The whole chain from the volume root down to the approved root.  Lifetime =
// one store operation; every component stays pinned until destruction.
class PinnedChain {
public:
    RootState open(const QString& approvedRoot, bool createIfMissing)
    {
        QString absolute;
        if (!approvedLocalRoot(approvedRoot, absolute)) {
            return RootState::Rejected;
        }
        if (pathContainsReparsePoint(absolute)) {
            return RootState::Rejected;
        }

        const QStringList parts = absolute.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        if (parts.size() < 2) {
            return RootState::Rejected; // a bare volume root is not a store root
        }

        // The volume root must already exist; pin it first so the tree below
        // cannot be swapped while it is being walked.
        if (!append(parts[0] + QStringLiteral("/"), /*access=*/kPinMinimumAccess,
                    kPinAncestorShare,
                    /*parent=*/nullptr)) {
            return RootState::Rejected;
        }

        for (int i = 1; i < parts.size(); ++i) {
            const bool leaf = (i == parts.size() - 1);
            QString path = m_components.back().path;
            if (!path.endsWith(QLatin1Char('\\'))) {
                path += QLatin1Char('\\');
            }
            path += parts[i];
            const DWORD access = leaf ? kPinLeafAccess : kPinIntermediateAccess;
            const StepState step = appendWithCreate(path, access, leaf, createIfMissing);
            if (step == StepState::Missing) {
                return RootState::Missing;
            }
            if (step == StepState::Rejected) {
                return RootState::Rejected;
            }
        }
        return RootState::Ok;
    }

    // The approved root itself (the last pinned component).
    const PinnedDirectory& root() const { return m_components.back(); }

private:
    StepState appendWithCreate(const QString& path, DWORD access, bool leaf,
                               bool createIfMissing)
    {
        const DWORD attributes = GetFileAttributesW(wide(nativePath(path)));
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                return StepState::Rejected;
            }
            if (!createIfMissing) {
                return StepState::Missing;
            }
            if (leaf) {
                // The private DACL exists from the first byte of the directory.
                TokenUserSid user;
                PrivateDacl dacl;
                SECURITY_ATTRIBUTES security = {};
                if (!user.valid() || !dacl.build(user.sid()) ||
                    !dacl.prepareCreate(security)) {
                    return StepState::Rejected;
                }
                if (!CreateDirectoryW(wide(nativePath(path)), &security) &&
                    GetLastError() != ERROR_ALREADY_EXISTS) {
                    return StepState::Rejected;
                }
            }
            else if (!CreateDirectoryW(wide(nativePath(path)), nullptr) &&
                     GetLastError() != ERROR_ALREADY_EXISTS) {
                return StepState::Rejected;
            }
            // Fall through to the verified open.  If another writer won the
            // race, the open sees THEIR object and the checks in append()
            // refuse it unless it is exactly what this module would accept.
        }
        if (!append(path, access, leaf ? kPinLeafShare : kPinAncestorShare, &m_components.back())) {
            return StepState::Rejected;
        }
        // Only the leaf must be private.  NEVER rewritten here: an existing
        // leaf with a wider DACL or a foreign owner is refused outright.
        if (leaf && !aclIsPrivateHandle(m_components.back().handle.get())) {
            m_components.pop_back();
            return StepState::Rejected;
        }
        return StepState::Ok;
    }

    bool append(const QString& path, DWORD access, DWORD share, const PinnedDirectory* parent)
    {
        PinnedDirectory component;
        component.path = nativePath(path);
        component.handle.reset(CreateFileW(wide(component.path), access, share,
                                           nullptr, OPEN_EXISTING,
                                           FILE_FLAG_BACKUP_SEMANTICS |
                                               FILE_FLAG_OPEN_REPARSE_POINT,
                                           nullptr));
        if (!component.handle.valid()) {
            return false;
        }
        if (!plainObject(component.handle.get()) || !isDirectoryHandle(component.handle.get())) {
            return false;
        }
        if (!fileIdentityOf(component.handle.get(), component.identity)) {
            return false;
        }
        component.finalPath = finalPathOf(component.handle.get());
        if (component.finalPath.isEmpty()) {
            return false;
        }
        if (parent == nullptr) {
            // Volume root: the final path must be exactly the requested root.
            if (!sameWinPath(component.finalPath, expectedFinalPath(component.path))) {
                return false;
            }
        }
        else if (!isDirectChildFinalPath(component.finalPath, parent->finalPath)) {
            // Not a direct child of the pinned parent: the path was redirected,
            // substituted, or resolved through a component we do not trust.
            return false;
        }
        m_components.push_back(std::move(component));
        return true;
    }

    std::vector<PinnedDirectory> m_components;
};
QString childPath(const PinnedDirectory& root, const QString& fileName)
{
    QString base = root.finalPath;
    if (!base.endsWith(QLatin1Char('\\'))) {
        base += QLatin1Char('\\');
    }
    return nativePath(base + fileName);
}

// Atomic, handle-relative replace: the destination name is resolved against the
// pinned leaf handle, so a path swap cannot redirect the write.
bool renameWithinRoot(HANDLE source, HANDLE rootDirectory, const QString& fileName)
{
    const SIZE_T nameBytes = static_cast<SIZE_T>(fileName.size()) * sizeof(wchar_t);
    const SIZE_T total = offsetof(FILE_RENAME_INFO, FileName) + nameBytes + sizeof(wchar_t);
    // FILE_RENAME_INFO declares ReplaceIfExists through a union whose spelling
    // differs across SDK/compiler modes; in every layout it is the first DWORD,
    // followed by RootDirectory and FileNameLength.
    std::vector<unsigned char> buffer(static_cast<size_t>(total), 0);
    const DWORD replaceIfExists = TRUE;
    std::memcpy(buffer.data(), &replaceIfExists, sizeof(replaceIfExists));
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    info->RootDirectory = rootDirectory;
    info->FileNameLength = static_cast<DWORD>(nameBytes);
    info->FileName[0] = L'\0';
    if (!fileName.isEmpty()) {
        // Written through the raw buffer: assigning info->FileName directly
        // would alias the DWORD punning above.
        std::memcpy(buffer.data() + offsetof(FILE_RENAME_INFO, FileName), fileName.utf16(),
                    static_cast<size_t>(nameBytes));
    }
    return SetFileInformationByHandle(source, FileRenameInfo, buffer.data(),
                                      static_cast<DWORD>(buffer.size())) != FALSE;
}

enum class ChildState { Ok, Missing, Error };

ChildState readIdentityFile(const PinnedDirectory& root, const QString& fileName, QByteArray& out)
{
    ScopedHandle child(CreateFileW(wide(childPath(root, fileName)),
                                   GENERIC_READ | READ_CONTROL | SYNCHRONIZE |
                                       FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                   nullptr));
    if (!child.valid()) {
        const DWORD error = GetLastError();
        return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ? ChildState::Missing
                                                                               : ChildState::Error;
    }
    if (!plainObject(child.get()) || !hasSingleLink(child.get()) ||
        !aclIsPrivateHandle(child.get())) {
        return ChildState::Error;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(child.get(), &size) || size.QuadPart <= 0 ||
        size.QuadPart > kMaxEnvelopeBytes) {
        return ChildState::Error;
    }
    out.resize(static_cast<int>(size.QuadPart));
    int offset = 0;
    while (offset < out.size()) {
        DWORD received = 0;
        if (!ReadFile(child.get(), out.data() + offset,
                      static_cast<DWORD>(out.size() - offset), &received, nullptr) ||
            received == 0) {
            out.clear();
            return ChildState::Error;
        }
        offset += static_cast<int>(received);
    }
    return ChildState::Ok;
}

bool deleteIdentityFile(const PinnedDirectory& root, const QString& fileName, bool& missing)
{
    missing = false;
    ScopedHandle child(CreateFileW(wide(childPath(root, fileName)),
                                   DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                   nullptr));
    if (!child.valid()) {
        const DWORD error = GetLastError();
        missing = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
        return false;
    }
    // Never delete an object whose type, link count or DACL cannot be verified.
    // Deletion is then performed on this verified handle.
    if (!plainObject(child.get()) || !hasSingleLink(child.get()) ||
        !aclIsPrivateHandle(child.get())) {
        return false;
    }
    return deleteOpenedObject(child.get());
}

// Verifies that `fileName` in the pinned root now denotes exactly the object
// held on `written`.  Performs no path-based mutation.
//
// Nothing here opens the file: the write handle still holds it, and a second
// open could conflict.  The pinned root directory is enumerated instead;
// FILE_ID_BOTH_DIR_INFO reports the 64-bit file reference the filesystem
// associates with each name, which is the same value BY_HANDLE_FILE_INFORMATION
// returns for the write handle.  Equality proves the name still denotes our
// object; a mismatch means the name was swapped.
bool nameDenotesWrittenObject(const PinnedDirectory& root, const QString& fileName, HANDLE written)
{
    FileIdentity writtenIdentity;
    if (!fileIdentityOf(written, writtenIdentity)) {
        return false;
    }

    // Enumerate through the already-pinned root handle: it was opened with
    // FILE_LIST_DIRECTORY, so no new open of the directory is needed and the
    // listing is guaranteed to be of the pinned object.
    // FILE_ID_BOTH_DIR_INFO must be 8-byte aligned; a vector of quint64 is.
    constexpr size_t kWords = (64 * 1024) / sizeof(quint64);
    std::vector<quint64> storage(kWords, 0);
    auto* buffer = reinterpret_cast<unsigned char*>(storage.data());
    const DWORD bytes = static_cast<DWORD>(storage.size() * sizeof(quint64));
    if (!GetFileInformationByHandleEx(root.handle.get(), FileIdBothDirectoryRestartInfo, buffer,
                                      bytes)) {
        return false;
    }
    for (const unsigned char* cursor = buffer;;) {
        const auto* entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(cursor);
        const QString entryName = QString::fromWCharArray(
            entry->FileName, static_cast<int>(entry->FileNameLength / sizeof(wchar_t)));
        if (entryName.compare(fileName, Qt::CaseInsensitive) == 0) {
            return static_cast<quint64>(entry->FileId.QuadPart) == writtenIdentity.index;
        }
        if (entry->NextEntryOffset == 0) {
            break;
        }
        cursor += entry->NextEntryOffset;
    }
    return false;
}

bool replaceIdentityFile(const PinnedDirectory& root, const QString& fileName,
                         const QByteArray& data)
{
    if (fileName.isEmpty() || fileName.contains(QLatin1Char('/')) ||
        fileName.contains(QLatin1Char('\\')) || data.isEmpty()) {
        return false;
    }

    // Refuse a destination that is already a reparse point or hard-linked
    // elsewhere: that is tampering, not a file we should replace.
    {
        ScopedHandle existing(CreateFileW(wide(childPath(root, fileName)), FILE_READ_ATTRIBUTES,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                          nullptr));
        if (existing.valid()) {
            if (!plainObject(existing.get()) || !hasSingleLink(existing.get())) {
                return false;
            }
        }
        else {
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                return false;
            }
        }
    }

    QByteArray suffix;
    for (int i = 0; i < 4; ++i) {
        suffix += QByteArray::number(static_cast<qulonglong>(QRandomGenerator::global()->generate()),
                                     16)
                      .rightJustified(8, QLatin1Char('0'));
    }
    const QString tempName = fileName + QStringLiteral(".tmp-") + QString::fromLatin1(suffix);

    TokenUserSid user;
    PrivateDacl dacl;
    SECURITY_ATTRIBUTES attributes = {};
    if (!user.valid() || !dacl.build(user.sid()) || !dacl.prepareCreate(attributes)) {
        return false;
    }

    // CREATE_NEW + FILE_SHARE_READ: the temp name cannot be squatted (CREATE_NEW)
    // or unlinked underneath the rename (no FILE_SHARE_DELETE), yet concurrent
    // readers can still open it.  The private DACL exists from the first byte.
    ScopedHandle temp(CreateFileW(wide(childPath(root, tempName)),
                                  GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE |
                                      SYNCHRONIZE,
                                  FILE_SHARE_READ, &attributes, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!temp.valid()) {
        return false;
    }

    bool ok = plainObject(temp.get()) && hasSingleLink(temp.get()) &&
              aclIsPrivateHandle(temp.get());
    DWORD written = 0;
    if (ok) {
        ok = WriteFile(temp.get(), data.constData(), static_cast<DWORD>(data.size()), &written,
                       nullptr) != FALSE &&
             written == static_cast<DWORD>(data.size()) && FlushFileBuffers(temp.get()) != FALSE;
    }
    if (ok) {
        ok = renameWithinRoot(temp.get(), root.handle.get(), fileName);
    }
    if (!ok) {
        // Handle-based cleanup of our own partial ciphertext; the name is never
        // touched by path.
        if (temp.valid()) {
            deleteOpenedObject(temp.get());
        }
        return false;
    }

    // temp still refers to the renamed object.  Verify the name denotes exactly
    // it; on any mismatch dispose of the object we hold, never whatever the
    // name now denotes.
    if (!nameDenotesWrittenObject(root, fileName, temp.get())) {
        deleteOpenedObject(temp.get());
        return false;
    }
    return true;
}

// DPAPI entropy scoped by canonical origin / user / role / installation /
// key version, mirroring plan section 3.4 storage isolation.
QByteArray entropyFor(const QString& origin, const QString& userId, const QString& installationId,
                      int keyVersion)
{
    return QStringLiteral("kanade-moonlight-qt/installation-identity/v1\n%1\n%2\n%3\n%4\n%5")
        .arg(origin, userId, QString::fromLatin1(kRole), installationId)
        .arg(keyVersion)
        .toUtf8();
}

QString fileNameFor(const QString& origin, const QString& userId)
{
    const QByteArray digest = QCryptographicHash::hash(
        QStringLiteral("kanade-moonlight-qt/identity-file/v1\n%1\n%2\n%3")
            .arg(origin, userId, QString::fromLatin1(kRole))
            .toUtf8(),
        QCryptographicHash::Sha256);
    return QStringLiteral("identity-%1.json").arg(QString::fromLatin1(digest.toHex()));
}

// Self-describing sealed plaintext: the scope fields are repeated inside the
// DPAPI blob and verified after decryption.  A blob can therefore never be
// accepted under a different origin/user/installation/key version even if a
// future change passed the wrong entropy.
QByteArray buildSealedPayload(const QString& origin, const QString& userId,
                              const Kanade::InstallationIdentity& identity, const QByteArray& seed)
{
    QJsonObject object;
    object.insert(QStringLiteral("origin"), origin);
    object.insert(QStringLiteral("user_id"), userId);
    object.insert(QStringLiteral("role"), QString::fromLatin1(kRole));
    object.insert(QStringLiteral("installation_id"), identity.installationId);
    object.insert(QStringLiteral("key_version"), identity.keyVersion);
    object.insert(QStringLiteral("seed"), QString::fromLatin1(seed.toBase64()));

    QByteArray payload(kSealedPayloadMagic);
    payload += '\n';
    payload += QJsonDocument(object).toJson(QJsonDocument::Compact);
    return payload;
}

bool parseSealedPayload(const QByteArray& payload, const QString& origin, const QString& userId,
                        const QString& installationId, int keyVersion, QByteArray& seed)
{
    const QByteArray magic = QByteArray(kSealedPayloadMagic) + '\n';
    if (!payload.startsWith(magic) || payload.size() > kMaxSealedBlobBytes) {
        return false;
    }
    QJsonParseError parseError = {};
    const QJsonDocument document = QJsonDocument::fromJson(payload.mid(magic.size()), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return false;
    }
    const QJsonObject object = document.object();
    QString payloadOrigin, payloadUser, payloadRole, payloadInstallation, payloadSeed;
    qint64 payloadKeyVersion = 0;
    if (!jsonStringField(object, "origin", payloadOrigin) || payloadOrigin != origin ||
        !jsonStringField(object, "user_id", payloadUser) || payloadUser != userId ||
        !jsonStringField(object, "role", payloadRole) ||
        payloadRole != QString::fromLatin1(kRole) ||
        !jsonStringField(object, "installation_id", payloadInstallation) ||
        payloadInstallation != installationId ||
        !jsonIntegerField(object, "key_version", payloadKeyVersion) ||
        payloadKeyVersion != keyVersion ||
        !jsonStringField(object, "seed", payloadSeed)) {
        return false;
    }
    seed = strictB64Decode(payloadSeed.toLatin1());
    return seed.size() == 32;
}

bool dpapiProtect(const QByteArray& plain, const QByteArray& entropy, QByteArray& out)
{
    if (plain.isEmpty() || plain.size() > kMaxSealedBlobBytes || entropy.isEmpty()) {
        return false;
    }
    DATA_BLOB in = { static_cast<DWORD>(plain.size()),
                     reinterpret_cast<BYTE*>(const_cast<char*>(plain.constData())) };
    DATA_BLOB ent = { static_cast<DWORD>(entropy.size()),
                      reinterpret_cast<BYTE*>(const_cast<char*>(entropy.constData())) };
    DATA_BLOB result = {};
    // Current-user scope only: no CRYPTPROTECT_LOCAL_MACHINE, no UI prompts.
    if (!CryptProtectData(&in, L"Kanade Moonlight installation identity", &ent, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &result)) {
        return false;
    }
    out = QByteArray(reinterpret_cast<const char*>(result.pbData),
                     static_cast<int>(result.cbData));
    SecureZeroMemory(result.pbData, result.cbData);
    LocalFree(result.pbData);
    return !out.isEmpty();
}

bool dpapiUnprotect(const QByteArray& blob, const QByteArray& entropy, QByteArray& out)
{
    if (blob.isEmpty() || blob.size() > kMaxSealedBlobBytes || entropy.isEmpty()) {
        return false;
    }
    DATA_BLOB in = { static_cast<DWORD>(blob.size()),
                     reinterpret_cast<BYTE*>(const_cast<char*>(blob.constData())) };
    DATA_BLOB ent = { static_cast<DWORD>(entropy.size()),
                      reinterpret_cast<BYTE*>(const_cast<char*>(entropy.constData())) };
    DATA_BLOB result = {};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                            &result)) {
        return false;
    }
    out = QByteArray(reinterpret_cast<const char*>(result.pbData),
                     static_cast<int>(result.cbData));
    SecureZeroMemory(result.pbData, result.cbData);
    LocalFree(result.pbData);
    return !out.isEmpty();
}

bool validateInputs(const QUrl& origin, const QString& userId, QString& originCanon)
{
    return canonicalOrigin(origin, originCanon) && validScopedInput(userId);
}

} // namespace

bool IdentityStore::platformSupported()
{
    return true;
}

IdentityStore::LoadResult IdentityStore::loadResult(const QUrl& origin, const QString& userId,
                                                    InstallationIdentity& out)
{
    QString originCanon;
    if (!validateInputs(origin, userId, originCanon)) {
        return LoadResult::Error;
    }

    // A missing root means nothing was ever stored here.  A root that exists but
    // is a reparse point, lives on a refused volume or carries a non-private
    // DACL is a failure, NOT "missing": treating it as missing could cause a new
    // identity to be generated over tampered or readable storage.
    PinnedChain chain;
    switch (chain.open(m_approvedRoot, /*createIfMissing=*/false)) {
    case RootState::Missing:
        return LoadResult::NotFound;
    case RootState::Rejected:
        return LoadResult::Error;
    case RootState::Ok:
        break;
    }

    QByteArray raw;
    const ChildState state = readIdentityFile(chain.root(), fileNameFor(originCanon, userId), raw);
    if (state == ChildState::Missing) {
        return LoadResult::NotFound;
    }
    if (state == ChildState::Error) {
        return LoadResult::Error;
    }

    QJsonParseError parseError = {};
    const QJsonDocument document = QJsonDocument::fromJson(raw, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return LoadResult::Error;
    }
    const QJsonObject envelope = document.object();

    // Envelope integrity: scoped metadata must match what we would have written;
    // installation_id and key_version double as DPAPI entropy inputs, so
    // tampering with them also makes the blob fail to decrypt.
    QString envelopeOrigin, envelopeUser, envelopeRole, installationId, publicKey;
    qint64 envelopeVersion = 0, keyVersion = 0;
    if (!jsonStringField(envelope, "origin", envelopeOrigin) || envelopeOrigin != originCanon ||
        !jsonStringField(envelope, "user_id", envelopeUser) || envelopeUser != userId ||
        !jsonStringField(envelope, "role", envelopeRole) ||
        envelopeRole != QString::fromLatin1(kRole) ||
        !jsonIntegerField(envelope, "v", envelopeVersion) || envelopeVersion != 1 ||
        !jsonStringField(envelope, "installation_id", installationId) ||
        installationId.size() > kMaxInstallationIdLen ||
        !jsonIntegerField(envelope, "key_version", keyVersion) ||
        !validKeyVersion(static_cast<int>(keyVersion)) ||
        !jsonStringField(envelope, "public_key", publicKey)) {
        return LoadResult::Error;
    }
    const QJsonValue protectedKey = envelope.value(QStringLiteral("protected_key"));
    if (!protectedKey.isString()) {
        return LoadResult::Error;
    }
    const QByteArray blob = strictB64Decode(protectedKey.toString().toLatin1());
    if (blob.isEmpty()) {
        return LoadResult::Error;
    }

    QByteArray payload;
    if (!dpapiUnprotect(blob,
                        entropyFor(originCanon, userId, installationId,
                                   static_cast<int>(keyVersion)),
                        payload)) {
        return LoadResult::Error;
    }
    QByteArray seed;
    const bool sealedOk = parseSealedPayload(payload, originCanon, userId, installationId,
                                             static_cast<int>(keyVersion), seed);
    OPENSSL_cleanse(payload.data(), static_cast<size_t>(payload.size()));
    if (!sealedOk) {
        OPENSSL_cleanse(seed.data(), static_cast<size_t>(seed.size()));
        return LoadResult::Error;
    }

    // The decrypted material must be a 32-byte Ed25519 seed that derives the
    // public key recorded in the envelope; anything else is corruption.
    const QByteArray derivedPublic = ed25519DerivePublic(seed);
    const bool intact = seed.size() == 32 && !derivedPublic.isEmpty() &&
                        canonicalB64(publicKey.toLatin1()) == derivedPublic.toBase64();
    if (!intact) {
        OPENSSL_cleanse(seed.data(), static_cast<size_t>(seed.size()));
        return LoadResult::Error;
    }

    InstallationIdentity loaded;
    loaded.privateKey = seed.toBase64();
    loaded.publicKey = derivedPublic.toBase64();
    loaded.installationId = installationId;
    loaded.keyVersion = static_cast<int>(keyVersion);
    OPENSSL_cleanse(seed.data(), static_cast<size_t>(seed.size()));
    out = loaded;
    return LoadResult::Ok;
}

bool IdentityStore::load(const QUrl& origin, const QString& userId, InstallationIdentity& out)
{
    return loadResult(origin, userId, out) == LoadResult::Ok;
}

bool IdentityStore::save(const QUrl& origin, const QString& userId,
                         const InstallationIdentity& identity)
{
    QString originCanon;
    if (!validateInputs(origin, userId, originCanon) ||
        (!identity.installationId.isEmpty() && !isCanonicalUuid(identity.installationId)) ||
        !validKeyVersion(identity.keyVersion) || !identityKeypairConsistent(identity)) {
        return false;
    }
    bool ok = false;
    QByteArray seed = ed25519SeedFromIdentity(identity, &ok);
    if (!ok) {
        return false;
    }

    PinnedChain chain;
    if (chain.open(m_approvedRoot, /*createIfMissing=*/true) != RootState::Ok) {
        OPENSSL_cleanse(seed.data(), static_cast<size_t>(seed.size()));
        return false;
    }

    QByteArray payload = buildSealedPayload(originCanon, userId, identity, seed);
    OPENSSL_cleanse(seed.data(), static_cast<size_t>(seed.size()));

    QByteArray blob;
    const bool protectedOk =
        dpapiProtect(payload,
                     entropyFor(originCanon, userId, identity.installationId, identity.keyVersion),
                     blob);
    OPENSSL_cleanse(payload.data(), static_cast<size_t>(payload.size()));
    if (!protectedOk || blob.isEmpty()) {
        return false;
    }

    QJsonObject envelope;
    envelope.insert(QStringLiteral("v"), 1);
    envelope.insert(QStringLiteral("origin"), originCanon);
    envelope.insert(QStringLiteral("user_id"), userId);
    envelope.insert(QStringLiteral("role"), QString::fromLatin1(kRole));
    envelope.insert(QStringLiteral("installation_id"), identity.installationId);
    envelope.insert(QStringLiteral("key_version"), identity.keyVersion);
    envelope.insert(QStringLiteral("public_key"),
                    QString::fromLatin1(canonicalB64(identity.publicKey)));
    envelope.insert(QStringLiteral("protected_key"),
                    QString::fromLatin1(blob.toBase64().constData()));
    return replaceIdentityFile(chain.root(), fileNameFor(originCanon, userId),
                               QJsonDocument(envelope).toJson(QJsonDocument::Compact));
}

bool IdentityStore::forget(const QUrl& origin, const QString& userId)
{
    QString originCanon;
    if (!validateInputs(origin, userId, originCanon)) {
        return false;
    }

    PinnedChain chain;
    switch (chain.open(m_approvedRoot, /*createIfMissing=*/false)) {
    case RootState::Missing:
        return true; // nothing stored
    case RootState::Rejected:
        return false;
    case RootState::Ok:
        break;
    }

    bool missing = false;
    const bool deleted = deleteIdentityFile(chain.root(), fileNameFor(originCanon, userId), missing);
    return deleted || missing;
}

#ifdef KANADE_IDENTITY_TEST_HOOKS
// Introspection for tests/kanade_identity_win32.  Never compiled into a product
// build; enabled only by that target's .pro file.
namespace {

bool inspectHandle(const QString& path, bool directory, DWORD access, ScopedHandle& out)
{
    out.reset(CreateFileW(wide(nativePath(path)), access,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                          OPEN_EXISTING,
                          FILE_FLAG_OPEN_REPARSE_POINT |
                              (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
                          nullptr));
    return out.valid();
}

} // namespace

bool IdentityTestHooks::aclIsPrivate(const QString& path, bool directory)
{
    ScopedHandle handle;
    return inspectHandle(path, directory, FILE_READ_ATTRIBUTES | READ_CONTROL, handle) &&
           aclIsPrivateHandle(handle.get());
}

bool IdentityTestHooks::objectIsPlain(const QString& path, bool directory)
{
    ScopedHandle handle;
    return inspectHandle(path, directory, FILE_READ_ATTRIBUTES, handle) &&
           plainObject(handle.get()) && (isDirectoryHandle(handle.get()) == directory);
}

int IdentityTestHooks::linkCount(const QString& path)
{
    ScopedHandle handle;
    if (!inspectHandle(path, /*directory=*/false, FILE_READ_ATTRIBUTES, handle)) {
        return -1;
    }
    FILE_STANDARD_INFO info = {};
    if (!GetFileInformationByHandleEx(handle.get(), FileStandardInfo, &info, sizeof(info))) {
        return -1;
    }
    return static_cast<int>(info.NumberOfLinks);
}

QString IdentityTestHooks::fileNameForScope(const QUrl& origin, const QString& userId)
{
    QString originCanon;
    if (!canonicalOrigin(origin, originCanon) || !validScopedInput(userId)) {
        return QString();
    }
    return fileNameFor(originCanon, userId);
}

bool IdentityTestHooks::rootIsAccepted(const QString& approvedRoot)
{
    QString ignored;
    return approvedLocalRoot(approvedRoot, ignored);
}

bool IdentityTestHooks::widenDaclToEveryone(const QString& path, bool directory)
{
    // Test-only: plant a permissive DACL so the negative cases can prove the
    // store refuses it.  This never runs in a product build, and the product
    // store never has a code path that does this.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    // Everyone/Owner/SYSTEM full control.  ACE flags are left empty so these
    // are EFFECTIVE on the object itself (an inherit-only ACE would grant
    // nothing and make the negative test vacuous).
    const QString sddl = QStringLiteral("D:AI(A;;FA;;;WD)(A;;FA;;;OW)(A;;FA;;;SY)");
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            reinterpret_cast<LPCWSTR>(sddl.utf16()), SDDL_REVISION_1, &descriptor, nullptr)) {
        return false;
    }
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    const bool parsed =
        GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) != FALSE && present &&
        dacl != nullptr;
    bool applied = false;
    if (parsed) {
        ScopedHandle handle;
        if (inspectHandle(path, directory, WRITE_DAC | READ_CONTROL, handle)) {
            applied = SetSecurityInfo(handle.get(), SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION |
                                          UNPROTECTED_DACL_SECURITY_INFORMATION,
                                      nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
        }
    }
    LocalFree(descriptor);
    return applied;
}

#endif // KANADE_IDENTITY_TEST_HOOKS
#else // store compiled out: non-Windows, WinRT, or KANADE_DISABLE_WIN32_IDENTITY

bool IdentityStore::platformSupported()
{
    return false;
}

// Fail closed: persistence is unavailable whenever the private-DACL proof is
// not compiled in (non-Windows, WinRT, or an explicit opt-out).  DPAPI has no
// cross-platform equivalent and plan 3.4 forbids a plaintext fallback, so
// every operation reports Unsupported/false rather than settling for a weaker
// store.
IdentityStore::LoadResult IdentityStore::loadResult(const QUrl& origin, const QString& userId,
                                                    InstallationIdentity& out)
{
    Q_UNUSED(origin)
    Q_UNUSED(userId)
    Q_UNUSED(out)
    return LoadResult::Unsupported;
}

bool IdentityStore::load(const QUrl& origin, const QString& userId, InstallationIdentity& out)
{
    Q_UNUSED(origin)
    Q_UNUSED(userId)
    Q_UNUSED(out)
    return false;
}

bool IdentityStore::save(const QUrl& origin, const QString& userId,
                         const InstallationIdentity& identity)
{
    Q_UNUSED(origin)
    Q_UNUSED(userId)
    Q_UNUSED(identity)
    return false;
}

bool IdentityStore::forget(const QUrl& origin, const QString& userId)
{
    Q_UNUSED(origin)
    Q_UNUSED(userId)
    return false;
}

#endif // Windows desktop store / compiled-out fallback

} // namespace Kanade
