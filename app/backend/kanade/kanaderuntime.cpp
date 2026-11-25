#include "kanaderuntime.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QList>
#include <QSet>
#include <QStringList>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#endif

// Loader/validator for the managed online runtime manifest.  See
// kanaderuntime.h for the file contract and the security argument.
//
// Trust anchor: a PATH STRING proves nothing on Windows.  An intermediate
// junction, a `subst` alias, a mapped network drive, a reparse point or an
// alternate data stream can redirect a path between "we checked it" and "we
// opened it".  So every object this file trusts is opened through
// openPinnedChain(), which:
//
//   1. opens the approved root directory WITHOUT FILE_SHARE_DELETE and reads its
//      FINAL path and volume serial FROM THE HANDLE (GetFinalPathNameByHandleW),
//      refusing a UNC/device namespace and any root whose final path is not the
//      approved drive letter (this is what defeats `subst D: C:\x`);
//   2. walks from the target's parent up to the root, opening EVERY component
//      without delete share, rejecting any reparse point and any component on a
//      different volume serial;
//   3. opens the target file itself without write/delete share, rejecting a
//      reparse point, a directory, a foreign volume or an extra ':' (ADS);
//   4. keeps all handles open across the read/hash/launch decision.
//
// The manifest bytes, the executable SHA-256 and every QProcess argument therefore
// come from one pinned object graph, not from whatever the path currently means.

namespace Kanade {

namespace {

// The product's approved data tree.  No C: fallback, no roaming location.
const QLatin1String kApprovedDriveLetter("d:");

const QString kVersionKey = QStringLiteral("version");
const QString kOriginKey = QStringLiteral("api_origin");
const QString kClientKey = QStringLiteral("client");
const QString kSidecarKey = QStringLiteral("sidecar");
const QString kPeerKey = QStringLiteral("peer");
const QString kLocalKey = QStringLiteral("local");
const QString kTimeoutKey = QStringLiteral("handshake_timeout_ms");

const QString kInstallationIdKey = QStringLiteral("installation_id");
const QString kKeyVersionKey = QStringLiteral("key_version");

const QString kExecutablePathKey = QStringLiteral("executable_path");
const QString kExecutableShaKey = QStringLiteral("executable_sha256");

const QString kHostIdKey = QStringLiteral("host_id");
const QString kHostInstallationKey = QStringLiteral("host_installation_id");
const QString kHostKeyVersionKey = QStringLiteral("host_key_version");
const QString kHostPublicKeyKey = QStringLiteral("host_public_key");
const QString kHostAppVersionKey = QStringLiteral("host_app_version");
const QString kQuicKey = QStringLiteral("quic");

bool fail(ManagedRuntimeValidation& why, ManagedRuntimeError error)
{
    why.error = error;
    why.detail = managedRuntimeErrorReason(error);
    return false;
}

bool requireExactKeys(const QJsonObject& object, const QStringList& keys,
                      ManagedRuntimeValidation& why)
{
    for (const QString& key : keys) {
        if (!object.contains(key)) {
            return fail(why, ManagedRuntimeError::ConfigMissingField);
        }
    }
    if (object.size() != keys.size()) {
        return fail(why, ManagedRuntimeError::ConfigUnknownField);
    }
    return true;
}

bool isAbsolutePath(const QString& path)
{
    return !path.isEmpty() && QDir::isAbsolutePath(path);
}

QString normalizedForCompare(const QString& path)
{
    QString cleaned = QDir::cleanPath(QDir::fromNativeSeparators(path));
    if (cleaned.endsWith(QLatin1Char('/'))) {
        cleaned.chop(1);
    }
    return cleaned.toLower();
}

bool isInsideRoot(const QString& root, const QString& path)
{
    const QString normalizedRoot = normalizedForCompare(root);
    const QString normalizedPath = normalizedForCompare(path);
    if (normalizedPath == normalizedRoot) {
        return true;
    }
    return normalizedPath.startsWith(normalizedRoot + QLatin1Char('/'));
}

bool isLowerHex(const QString& text, int length)
{
    if (text.size() != length) {
        return false;
    }
    for (const QChar c : text) {
        const ushort u = c.unicode();
        const bool lower = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f');
        if (!lower) {
            return false;
        }
    }
    return true;
}

bool isDottedQuad(const QString& text, bool allowLoopback, bool& loopbackOut)
{
    loopbackOut = false;
    const QStringList parts = text.split(QLatin1Char('.'));
    if (parts.size() != 4) {
        return false;
    }
    int octets[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 4; ++i) {
        const QString part = parts.at(i);
        if (part.isEmpty() || part.size() > 3) {
            return false;
        }
        if (part.size() > 1 && part.startsWith(QLatin1Char('0'))) {
            return false; // ambiguous leading zeros are never a valid literal
        }
        int value = 0;
        for (const QChar c : part) {
            if (c < QLatin1Char('0') || c > QLatin1Char('9')) {
                return false;
            }
            value = value * 10 + (c.unicode() - '0');
        }
        if (value > 255) {
            return false;
        }
        octets[i] = value;
    }
    if (octets[0] == 0) {
        return false; // "this network" is never a peer
    }
    if (octets[0] == 127) {
        loopbackOut = true;
        if (!allowLoopback || octets[1] != 0 || octets[2] != 0 || octets[3] != 1) {
            return false; // only the exact 127.0.0.1 loopback is ever valid
        }
        return true;
    }
    if (octets[0] >= 224) {
        return false; // multicast, reserved, broadcast
    }
    if (octets[0] == 169 && octets[1] == 254) {
        return false; // link-local is never a configured peer
    }
    return true;
}

// Host part of a canonical origin: lowercase DNS reg-name or strict IPv4.
bool isOriginHost(const QString& host)
{
    if (host.isEmpty() || host.size() > 253 || host.contains(QLatin1Char(':'))) {
        return false; // IPv6 literals are rejected: an identity can never be scoped to one
    }
    bool loopback = false;
    if (isDottedQuad(host, /*allowLoopback=*/true, loopback)) {
        return true;
    }
    if (host == QLatin1String("localhost")) {
        return false; // never a service origin
    }
    const QStringList labels = host.split(QLatin1Char('.'));
    for (const QString& label : labels) {
        if (label.isEmpty() || label.size() > 63) {
            return false;
        }
        if (label.startsWith(QLatin1Char('-'))) {
            return false;
        }
        for (const QChar c : label) {
            const ushort u = c.unicode();
            const bool ok = (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9')
                || c == QLatin1Char('-');
            if (!ok) {
                return false;
            }
        }
    }
    return true;
}

bool strictB64Decode32(const QByteArray& text, QByteArray& raw)
{
    // Canonical standard base64 WITH padding of exactly 32 bytes: 44 chars,
    // tail '='.  Anything else is a different spelling of (at best) the same
    // key and is refused.
    if (text.size() != 44 || !text.endsWith('=')) {
        return false;
    }
    for (int i = 0; i < text.size(); ++i) {
        const char c = text.at(i);
        const bool alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '+' || c == '/';
        const bool padding = (c == '=' && i == 43);
        if (!alphabet && !padding) {
            return false;
        }
    }
    const QByteArray decoded = QByteArray::fromBase64(
        text, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.size() != 32) {
        return false;
    }
    if (decoded.toBase64() != text) {
        return false;
    }
    raw = decoded;
    return true;
}

// ---------------------------------------------------------------------------
// Pinned object graph (Windows)
// ---------------------------------------------------------------------------

struct PinnedObject {
    void* handle = nullptr;
    QString finalPath;
    DWORD volumeSerial = 0;
    quint64 fileIndex = 0;
    bool isDirectory = false;

    bool valid() const { return handle != nullptr; }
};

void closePinned(PinnedObject& object)
{
#ifdef Q_OS_WIN
    if (object.handle != nullptr) {
        CloseHandle(static_cast<HANDLE>(object.handle));
        object.handle = nullptr;
    }
#endif
}

#ifdef Q_OS_WIN

// Opens one object without delete share, rejects any reparse point, and reads
// its identity FROM THE HANDLE (final path, volume serial, file index).  The
// final path must be a local DOS volume path: UNC, \Device\ and \??\Volume
// namespaces and any alternate data stream are refused outright.
bool openPinnedObject(const QString& path, bool expectDirectory, PinnedObject& out)
{
    const QString native = QDir::toNativeSeparators(path);
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE; // deliberately NO FILE_SHARE_DELETE
    HANDLE handle = CreateFileW(
        reinterpret_cast<const wchar_t*>(native.utf16()),
        expectDirectory ? FILE_READ_ATTRIBUTES : GENERIC_READ, share, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (expectDirectory ? FILE_FLAG_BACKUP_SEMANTICS
                                                       : FILE_FLAG_SEQUENTIAL_SCAN),
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    FILE_ATTRIBUTE_TAG_INFO tag = {};
    BY_HANDLE_FILE_INFORMATION basic = {};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))
        || !GetFileInformationByHandle(handle, &basic)
        || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || tag.ReparseTag != 0) {
        CloseHandle(handle);
        return false;
    }
    const bool isDirectory = (basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (isDirectory != expectDirectory) {
        CloseHandle(handle);
        return false;
    }

    wchar_t buffer[MAX_PATH * 4] = {};
    const DWORD length =
        GetFinalPathNameByHandleW(handle, buffer, DWORD(sizeof(buffer) / sizeof(buffer[0])),
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= sizeof(buffer) / sizeof(buffer[0])) {
        CloseHandle(handle);
        return false;
    }
    QString finalPath = QString::fromWCharArray(buffer, int(length));
    if (finalPath.startsWith(QLatin1String("\\\\?\\"))) {
        finalPath = finalPath.mid(4); // strip the extended prefix, keep the volume path
    }
    if (finalPath.startsWith(QLatin1String("UNC\\"))
        || finalPath.startsWith(QLatin1String("\\Device\\"))
        || finalPath.startsWith(QLatin1String("Volume{")) || finalPath.contains(QLatin1Char('?'))) {
        CloseHandle(handle);
        return false; // remote/device/volume namespace, or an extended spelling we do not accept
    }
    // Exactly one ':' at index 1 (the volume letter).  A second ':' means an
    // alternate data stream.
    if (finalPath.indexOf(QLatin1Char(':')) != 1
        || finalPath.indexOf(QLatin1Char(':'), 2) != -1) {
        CloseHandle(handle);
        return false;
    }

    out.handle = handle;
    out.finalPath = QDir::cleanPath(QDir::fromNativeSeparators(finalPath));
    out.volumeSerial = basic.dwVolumeSerialNumber;
    out.fileIndex = (quint64(basic.nFileIndexHigh) << 32) | quint64(basic.nFileIndexLow);
    out.isDirectory = isDirectory;
    return true;
}

// A pinned path: the root directory, every intermediate directory down to the
// target's parent, and the target itself.  All handles are held without delete
// share until closeChain(), so no component can be renamed or re-pointed while
// the caller reads, hashes or launches the target.
struct PinnedChain {
    QList<PinnedObject> directories; // root first, then each ancestor
    PinnedObject target;

    void close()
    {
        closePinned(target);
        for (PinnedObject& directory : directories) {
            closePinned(directory);
        }
        directories.clear();
    }

    ~PinnedChain() { close(); }
};

// Opens `path` (a file or a directory) under `approvedRoot`.
//
// Every component is opened without delete share and must report the SAME volume
// serial as the root handle, so a junction/subst/mapped drive cannot smuggle a
// different tree in.  The walk must actually reach the root's own file index;
// "we never found the root" is a refusal, not a pass.
bool openPinnedChain(const QString& approvedRoot, const QString& path, bool targetIsDirectory,
                     PinnedChain& chain)
{
    PinnedObject root;
    if (!openPinnedObject(approvedRoot, /*expectDirectory=*/true, root)) {
        return false;
    }
    chain.directories.append(root);
    const DWORD rootVolume = root.volumeSerial;

    // The root's FINAL path must still be on the approved drive letter.  This is
    // what rejects `subst D: C:\elsewhere` and a mapped network drive: both
    // resolve to a different final path than the one the operator pinned.
    if (!normalizedForCompare(root.finalPath).startsWith(kApprovedDriveLetter + QLatin1Char('/'))) {
        return false;
    }

    const QString targetDirectory = targetIsDirectory ? QDir::cleanPath(QDir::fromNativeSeparators(path))
                                                      : QFileInfo(path).absolutePath();
    QString directory = QDir::cleanPath(QDir::fromNativeSeparators(targetDirectory));
    bool reachedRoot = false;
    for (int guard = 0; guard < 64; ++guard) {
        if (directory.compare(QDir::cleanPath(QDir::fromNativeSeparators(approvedRoot)),
                              Qt::CaseInsensitive)
            == 0) {
            reachedRoot = true;
            break;
        }
        PinnedObject component;
        if (!openPinnedObject(directory, /*expectDirectory=*/true, component)) {
            return false;
        }
        if (component.volumeSerial != rootVolume) {
            closePinned(component);
            return false;
        }
        chain.directories.append(component);
        const QString parent = QFileInfo(directory).absolutePath();
        if (parent.isEmpty() || parent == directory) {
            break;
        }
        directory = parent;
    }
    if (!reachedRoot) {
        return false; // the target is not under the approved root
    }

    if (!openPinnedObject(path, targetIsDirectory, chain.target)) {
        return false;
    }
    if (chain.target.volumeSerial != rootVolume) {
        return false;
    }
    return true;
}

bool readHandle(void* rawHandle, QByteArray& out, qint64 maxBytes)
{
    HANDLE handle = static_cast<HANDLE>(rawHandle);
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN)) {
        return false;
    }
    out.clear();
    QByteArray buffer(16 * 1024, Qt::Uninitialized);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(handle, buffer.data(), DWORD(buffer.size()), &read, nullptr)) {
            out.clear();
            return false;
        }
        if (read == 0) {
            return true;
        }
        if (out.size() + int(read) > maxBytes) {
            out.clear();
            return false;
        }
        out.append(buffer.constData(), int(read));
    }
}

bool hashHandle(void* rawHandle, QByteArray& hexOut)
{
    HANDLE handle = static_cast<HANDLE>(rawHandle);
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN)) {
        return false;
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    QByteArray buffer(64 * 1024, Qt::Uninitialized);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(handle, buffer.data(), DWORD(buffer.size()), &read, nullptr)) {
            return false;
        }
        if (read == 0) {
            break;
        }
        hash.addData(buffer.constData(), int(read));
    }
    hexOut = hash.result().toHex();
    return true;
}

#else

bool openPinnedObject(const QString&, bool, PinnedObject&) { return false; }
bool openPinnedChain(const QString&, const QString&, bool, PinnedChain&) { return false; }
bool readHandle(void*, QByteArray&, qint64) { return false; }
bool hashHandle(void*, QByteArray&) { return false; }

#endif

bool readBoundedFile(const QString& approvedRoot, const QString& path, QByteArray& out,
                     ManagedRuntimeValidation& why)
{
    PinnedChain chain;
    if (!openPinnedChain(approvedRoot, path, /*targetIsDirectory=*/false, chain)) {
        return fail(why, ManagedRuntimeError::ConfigReadFailed);
    }
    QByteArray bytes;
    if (!readHandle(chain.target.handle, bytes, kManagedMaxConfigBytes)) {
        return fail(why, bytes.isEmpty() && chain.target.valid()
                             ? ManagedRuntimeError::ConfigTooLarge
                             : ManagedRuntimeError::ConfigReadFailed);
    }
    if (bytes.isEmpty()) {
        return fail(why, ManagedRuntimeError::ConfigReadFailed);
    }
    out = bytes;
    return true;
}

bool fileMatchesSha256(const QString& approvedRoot, const QString& path,
                       const QString& expectedHex, ManagedRuntimeValidation& why,
                       ManagedRuntimeError mismatchError){
    PinnedChain chain;
    if (!openPinnedChain(approvedRoot, path, /*targetIsDirectory=*/false, chain)) {
        return fail(why, mismatchError);
    }
    QByteArray digest;
    if (!hashHandle(chain.target.handle, digest)) {
        return fail(why, ManagedRuntimeError::ConfigReadFailed);
    }
    if (QString::fromLatin1(digest) != expectedHex) {
        return fail(why, mismatchError);
    }
    return true;
}

// --- Public pinned launch helper --------------------------------------------

} // namespace

bool openPinnedLaunchTarget(const QString& approvedRoot, const QString& executablePath,
                            const QString& expectedSha256, void*& fileHandleOut,
                            QList<void*>& pinnedHandleOut, QString& reason)
{
    fileHandleOut = nullptr;
    pinnedHandleOut.clear();
#ifdef Q_OS_WIN
    // The chain must outlive this call WITHOUT closing the handles we hand out,
    // so it is heap-allocated, its handles are detached, and it is destroyed
    // while empty.  The caller releases them via closePinnedLaunchHandles().
    auto* chain = new PinnedChain();
    if (!openPinnedChain(approvedRoot, executablePath, /*targetIsDirectory=*/false, *chain)) {
        delete chain;
        reason = QStringLiteral("executable_unverified");
        return false;
    }
    QByteArray digest;
    if (!hashHandle(chain->target.handle, digest)
        || QString::fromLatin1(digest) != expectedSha256) {
        delete chain;
        reason = QStringLiteral("executable_unverified");
        return false;
    }
    for (const PinnedObject& directory : qAsConst(chain->directories)) {
        pinnedHandleOut.append(directory.handle);
    }
    fileHandleOut = chain->target.handle;
    chain->target.handle = nullptr;
    for (PinnedObject& directory : chain->directories) {
        directory.handle = nullptr;
    }
    delete chain;
    return true;
#else
    Q_UNUSED(approvedRoot);
    Q_UNUSED(executablePath);
    Q_UNUSED(expectedSha256);
    reason = QStringLiteral("unsupported");
    return false;
#endif
}

void closePinnedLaunchHandles(void* fileHandle, QList<void*>& pinnedHandles)
{
#ifdef Q_OS_WIN
    if (fileHandle != nullptr) {
        CloseHandle(static_cast<HANDLE>(fileHandle));
    }
    for (void* handle : qAsConst(pinnedHandles)) {
        if (handle != nullptr) {
            CloseHandle(static_cast<HANDLE>(handle));
        }
    }
#else
    Q_UNUSED(fileHandle);
#endif
    pinnedHandles.clear();
}

namespace {

bool parsePortValue(const QJsonValue& value, quint16& out)
{
    if (!value.isDouble()) {
        return false;
    }
    const double number = value.toDouble();
    if (number < 1 || number > 65535
        || static_cast<double>(static_cast<quint16>(number)) != number) {
        return false;
    }
    out = static_cast<quint16>(number);
    return true;
}


} // namespace

QString managedRuntimeErrorReason(ManagedRuntimeError error)
{
    switch (error) {
    case ManagedRuntimeError::Ok:
        return QStringLiteral("ok");
    case ManagedRuntimeError::RootNotAbsolute:
        return QStringLiteral("root_not_absolute");
    case ManagedRuntimeError::RootNotOnApprovedDrive:
        return QStringLiteral("root_not_on_approved_drive");
    case ManagedRuntimeError::RootNotFound:
        return QStringLiteral("root_not_found");
    case ManagedRuntimeError::RootIsReparse:
        return QStringLiteral("root_is_reparse");
    case ManagedRuntimeError::ConfigPathNotAbsolute:
        return QStringLiteral("config_path_not_absolute");
    case ManagedRuntimeError::ConfigOutsideRoot:
        return QStringLiteral("config_outside_root");
    case ManagedRuntimeError::ConfigNotRegularFile:
        return QStringLiteral("config_not_regular_file");
    case ManagedRuntimeError::ConfigTooLarge:
        return QStringLiteral("config_too_large");
    case ManagedRuntimeError::ConfigReadFailed:
        return QStringLiteral("config_read_failed");
    case ManagedRuntimeError::ConfigParseError:
        return QStringLiteral("config_parse_error");
    case ManagedRuntimeError::ConfigVersionUnsupported:
        return QStringLiteral("config_version_unsupported");
    case ManagedRuntimeError::ConfigUnknownField:
        return QStringLiteral("config_unknown_field");
    case ManagedRuntimeError::ConfigMissingField:
        return QStringLiteral("config_missing_field");
    case ManagedRuntimeError::ConfigTypeMismatch:
        return QStringLiteral("config_type_mismatch");
    case ManagedRuntimeError::OriginInvalid:
        return QStringLiteral("origin_invalid");
    case ManagedRuntimeError::ClientInstallationIdInvalid:
        return QStringLiteral("client_installation_id_invalid");
    case ManagedRuntimeError::ClientKeyVersionInvalid:
        return QStringLiteral("client_key_version_invalid");
    case ManagedRuntimeError::ExecutablePathNotAbsolute:
        return QStringLiteral("executable_path_not_absolute");
    case ManagedRuntimeError::ExecutableOutsideRoot:
        return QStringLiteral("executable_outside_root");
    case ManagedRuntimeError::ExecutableNotFound:
        return QStringLiteral("executable_not_found");
    case ManagedRuntimeError::ExecutableIsReparse:
        return QStringLiteral("executable_is_reparse");
    case ManagedRuntimeError::ExecutableHashInvalid:
        return QStringLiteral("executable_hash_invalid");
    case ManagedRuntimeError::PeerHostIdInvalid:
        return QStringLiteral("peer_host_id_invalid");
    case ManagedRuntimeError::PeerInstallationIdInvalid:
        return QStringLiteral("peer_installation_id_invalid");
    case ManagedRuntimeError::PeerKeyVersionInvalid:
        return QStringLiteral("peer_key_version_invalid");
    case ManagedRuntimeError::PeerPublicKeyInvalid:
        return QStringLiteral("peer_public_key_invalid");
    case ManagedRuntimeError::PeerHostAppVersionInvalid:
        return QStringLiteral("peer_host_app_version_invalid");
    case ManagedRuntimeError::PeerEndpointInvalid:
        return QStringLiteral("peer_endpoint_invalid");
    case ManagedRuntimeError::LocalEndpointInvalid:
        return QStringLiteral("local_endpoint_invalid");
    case ManagedRuntimeError::EndpointsNotDistinct:
        return QStringLiteral("endpoints_not_distinct");
    case ManagedRuntimeError::TimeoutInvalid:
        return QStringLiteral("timeout_invalid");
    }
    return QStringLiteral("unknown");
}

bool isCanonicalSha256Hex(const QString& text)
{
    return isLowerHex(text, 64);
}

bool isCanonicalUuid4Text(const QString& text)
{
    if (text.size() != 36) {
        return false;
    }
    for (int i = 0; i < 36; ++i) {
        const QChar c = text.at(i);
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != QLatin1Char('-')) {
                return false;
            }
            continue;
        }
        const ushort u = c.unicode();
        const bool hex = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f');
        if (!hex) {
            return false;
        }
    }
    if (text.at(14) != QLatin1Char('4')) {
        return false;
    }
    const QChar variant = text.at(19);
    return variant == QLatin1Char('8') || variant == QLatin1Char('9')
        || variant == QLatin1Char('a') || variant == QLatin1Char('b');
}

bool isFixedIpv4Literal(const QString& text, bool allowLoopback)
{
    bool loopback = false;
    return isDottedQuad(text, allowLoopback, loopback);
}

bool isExactPortGroup(const quint16* ports, const quint16 (&expected)[3])
{
    if (ports == nullptr) {
        return false;
    }
    QSet<quint16> seen;
    for (int i = 0; i < 3; ++i) {
        seen.insert(ports[i]);
    }
    if (seen.size() != 3) {
        return false; // a duplicate is a missing port in disguise
    }
    for (int i = 0; i < 3; ++i) {
        if (!seen.contains(expected[i])) {
            return false;
        }
    }
    return true;
}

bool isCanonicalEd25519PublicKey(const QByteArray& base64Text)
{
    QByteArray raw;
    return strictB64Decode32(base64Text, raw);
}

bool canonicalHttpsOrigin(const QString& text, QString* canonicalOut)
{
    if (text.isEmpty() || text.size() > 300) {
        return false;
    }
    if (text.trimmed() != text) {
        return false; // surrounding whitespace is never silently normalized
    }
    const QString lower = text.toLower();
    if (!lower.startsWith(QLatin1String("https://"))) {
        return false;
    }
    const QString authority = text.mid(8);
    if (authority.isEmpty() || authority.contains(QLatin1Char('/'))
        || authority.contains(QLatin1Char('?')) || authority.contains(QLatin1Char('#'))
        || authority.contains(QLatin1Char('@')) || authority.contains(QLatin1Char(' '))) {
        return false;
    }
    QString host = authority;
    int port = 443;
    const int colon = authority.lastIndexOf(QLatin1Char(':'));
    if (colon >= 0) {
        host = authority.left(colon);
        const QString portText = authority.mid(colon + 1);
        if (portText.isEmpty() || portText.size() > 5) {
            return false;
        }
        for (const QChar c : portText) {
            if (c < QLatin1Char('0') || c > QLatin1Char('9')) {
                return false;
            }
        }
        bool ok = false;
        port = portText.toInt(&ok);
        if (!ok || port < 1 || port > 65535) {
            return false;
        }
        if (portText.size() > 1 && portText.startsWith(QLatin1Char('0'))) {
            return false;
        }
    }
    if (host != host.toLower() || !isOriginHost(host)) {
        return false;
    }
    QString canonical = QStringLiteral("https://") + host;
    if (port != 443) {
        canonical += QLatin1Char(':') + QString::number(port);
    }
    if (canonicalOut != nullptr) {
        *canonicalOut = canonical;
    }
    return true;
}

bool parseNumericEndpoint(const QString& text, ManagedQuicEndpoint& out)
{
    const int colon = text.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0 || colon == text.size() - 1) {
        return false;
    }
    // A second colon would be an IPv6 spelling; those are refused outright.
    if (text.left(colon).contains(QLatin1Char(':'))) {
        return false;
    }
    const QString host = text.left(colon);
    const QString portText = text.mid(colon + 1);
    if (portText.isEmpty() || portText.size() > 5) {
        return false;
    }
    if (portText.size() > 1 && portText.startsWith(QLatin1Char('0'))) {
        return false;
    }
    for (const QChar c : portText) {
        if (c < QLatin1Char('0') || c > QLatin1Char('9')) {
            return false;
        }
    }
    bool ok = false;
    const int port = portText.toInt(&ok);
    if (!ok || port < 1 || port > 65535) {
        return false;
    }
    bool loopback = false;
    if (!isDottedQuad(host, /*allowLoopback=*/true, loopback)) {
        return false;
    }
    out.ipv4 = host;
    out.port = static_cast<quint16>(port);
    return true;
}

bool isForbiddenOuterPort(quint16 port)
{
    for (const quint16 forbidden : kForbiddenOuterPorts) {
        if (port == forbidden) {
            return true;
        }
    }
    return false;
}

bool validateManagedRuntimeConfig(const ManagedRuntimeConfig& config,
                                  ManagedRuntimeValidation& why)
{
    why = ManagedRuntimeValidation();

    if (!isAbsolutePath(config.approvedRoot)) {
        return fail(why, ManagedRuntimeError::RootNotAbsolute);
    }
    if (!normalizedForCompare(config.approvedRoot).startsWith(kApprovedDriveLetter
                                                              + QLatin1Char('/'))) {
        return fail(why, ManagedRuntimeError::RootNotOnApprovedDrive);
    }
    if (!isAbsolutePath(config.configFilePath)) {
        return fail(why, ManagedRuntimeError::ConfigPathNotAbsolute);
    }
    if (!isInsideRoot(config.approvedRoot, config.configFilePath)) {
        return fail(why, ManagedRuntimeError::ConfigOutsideRoot);
    }
    if (!isAbsolutePath(config.sidecarExecutablePath)) {
        return fail(why, ManagedRuntimeError::ExecutablePathNotAbsolute);
    }
    if (!isInsideRoot(config.approvedRoot, config.sidecarExecutablePath)) {
        return fail(why, ManagedRuntimeError::ExecutableOutsideRoot);
    }
    if (!isCanonicalSha256Hex(config.sidecarExecutableSha256)) {
        return fail(why, ManagedRuntimeError::ExecutableHashInvalid);
    }

    // Reachability and provenance, both through the pinned chain.  The root check
    // comes first because everything else is relative to it.
    PinnedChain rootChain;
    if (!openPinnedChain(config.approvedRoot, config.approvedRoot,
                         /*targetIsDirectory=*/true, rootChain)) {
        return fail(why, ManagedRuntimeError::RootNotFound);
    }
    rootChain.close();

    {
        PinnedChain configChain;
        if (!openPinnedChain(config.approvedRoot, config.configFilePath,
                             /*targetIsDirectory=*/false, configChain)) {
            return fail(why, ManagedRuntimeError::ConfigNotRegularFile);
        }
    }
    if (!fileMatchesSha256(config.approvedRoot, config.sidecarExecutablePath,
                           config.sidecarExecutableSha256, why,
                           ManagedRuntimeError::ExecutableHashInvalid)) {
        return false;
    }

    QString canonicalOrigin;
    if (!canonicalHttpsOrigin(config.apiOrigin, &canonicalOrigin)
        || canonicalOrigin != config.apiOrigin) {
        return fail(why, ManagedRuntimeError::OriginInvalid);
    }
    if (!isCanonicalUuid4Text(config.clientInstallationId)) {
        return fail(why, ManagedRuntimeError::ClientInstallationIdInvalid);
    }
    if (config.clientKeyVersion < 1 || config.clientKeyVersion > 2147483647) {
        return fail(why, ManagedRuntimeError::ClientKeyVersionInvalid);
    }
    if (!isCanonicalUuid4Text(config.hostId)) {
        return fail(why, ManagedRuntimeError::PeerHostIdInvalid);
    }
    if (!isCanonicalUuid4Text(config.hostInstallationId)
        || config.hostInstallationId == config.clientInstallationId) {
        return fail(why, ManagedRuntimeError::PeerInstallationIdInvalid);
    }
    if (config.hostKeyVersion < 1 || config.hostKeyVersion > 2147483647) {
        return fail(why, ManagedRuntimeError::PeerKeyVersionInvalid);
    }
    // The native PIN exchange names a host GameStream application version.  It is
    // pinned by the operator manifest (never QML) and must be a bounded numeric
    // token (digits, dots and inner '-', as Sunshine uses e.g. "7.1.431.-1"), so
    // it can never inject a header, a path or a control character.
    if (config.hostAppVersion.isEmpty() || config.hostAppVersion.size() > 32) {
        return fail(why, ManagedRuntimeError::PeerHostAppVersionInvalid);
    }
    if (config.hostAppVersion.at(0) < QLatin1Char('0')
        || config.hostAppVersion.at(0) > QLatin1Char('9')) {
        return fail(why, ManagedRuntimeError::PeerHostAppVersionInvalid);
    }
    for (const QChar c : config.hostAppVersion) {
        if ((c < QLatin1Char('0') || c > QLatin1Char('9')) && c != QLatin1Char('.')
            && c != QLatin1Char('-')) {
            return fail(why, ManagedRuntimeError::PeerHostAppVersionInvalid);
        }
    }
    if (!isCanonicalEd25519PublicKey(config.hostPublicKey)) {
        return fail(why, ManagedRuntimeError::PeerPublicKeyInvalid);
    }

    // The OUTER transport endpoints are not GameStream targets.  Both must be
    // numeric IPv4 literals on the approved lab interface: a UDP socket bound to
    // 127.0.0.1 can never reach another machine, and the Go side rejects a mixed
    // loopback/non-loopback pair.  GameStream itself stays on 127.0.0.1 (that is
    // the sidecar's own business, not representable here).
    bool peerLoopback = false;
    if (!isDottedQuad(config.peerQuic.ipv4, /*allowLoopback=*/false, peerLoopback)
        || peerLoopback || config.peerQuic.port == 0
        || isForbiddenOuterPort(config.peerQuic.port)) {
        return fail(why, ManagedRuntimeError::PeerEndpointInvalid);
    }
    bool localLoopback = false;
    if (!isDottedQuad(config.localQuic.ipv4, /*allowLoopback=*/false, localLoopback)
        || localLoopback || config.localQuic.port == 0
        || isForbiddenOuterPort(config.localQuic.port)) {
        return fail(why, ManagedRuntimeError::LocalEndpointInvalid);
    }
    if (config.peerQuic.toString() == config.localQuic.toString()) {
        return fail(why, ManagedRuntimeError::EndpointsNotDistinct);
    }
    // Both are IPv4 by construction, so "same family" holds; the two ends must
    // still be different hosts (two ends of one tunnel are never one address).
    if (config.peerQuic.ipv4 == config.localQuic.ipv4) {
        return fail(why, ManagedRuntimeError::EndpointsNotDistinct);
    }

    if (config.handshakeTimeoutMs < kManagedMinHandshakeMs
        || config.handshakeTimeoutMs > kManagedMaxHandshakeMs) {
        return fail(why, ManagedRuntimeError::TimeoutInvalid);
    }
    return true;
}

bool loadManagedRuntimeConfig(const QString& approvedRoot, const QString& configFilePath,
                              ManagedRuntimeConfig& out, ManagedRuntimeValidation& why)
{
    why = ManagedRuntimeValidation();

    ManagedRuntimeConfig config;
    config.approvedRoot = QDir::cleanPath(QDir::fromNativeSeparators(approvedRoot));
    config.configFilePath = QDir::cleanPath(QDir::fromNativeSeparators(configFilePath));

    if (!isAbsolutePath(config.approvedRoot)) {
        return fail(why, ManagedRuntimeError::RootNotAbsolute);
    }
    if (!isAbsolutePath(config.configFilePath)) {
        return fail(why, ManagedRuntimeError::ConfigPathNotAbsolute);
    }
    if (!isInsideRoot(config.approvedRoot, config.configFilePath)) {
        return fail(why, ManagedRuntimeError::ConfigOutsideRoot);
    }

    QByteArray bytes;
    if (!readBoundedFile(config.approvedRoot, config.configFilePath, bytes, why)) {
        return false;
    }

    QJsonParseError parseError = {};
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return fail(why, ManagedRuntimeError::ConfigParseError);
    }
    const QJsonObject root = document.object();

    if (!requireExactKeys(root,
                          { kVersionKey, kOriginKey, kClientKey, kSidecarKey, kPeerKey,
                            kLocalKey, kTimeoutKey },
                          why)) {
        return false;
    }
    const QJsonValue versionValue = root.value(kVersionKey);
    if (!versionValue.isDouble() || versionValue.toDouble() != 1.0) {
        return fail(why, ManagedRuntimeError::ConfigVersionUnsupported);
    }
    if (!root.value(kOriginKey).isString() || !root.value(kClientKey).isObject()
        || !root.value(kSidecarKey).isObject() || !root.value(kPeerKey).isObject()
        || !root.value(kLocalKey).isObject()) {
        return fail(why, ManagedRuntimeError::ConfigTypeMismatch);
    }
    const QJsonObject client = root.value(kClientKey).toObject();
    const QJsonObject sidecar = root.value(kSidecarKey).toObject();
    const QJsonObject peer = root.value(kPeerKey).toObject();
    const QJsonObject local = root.value(kLocalKey).toObject();

    if (!requireExactKeys(client, { kInstallationIdKey, kKeyVersionKey }, why)
        || !requireExactKeys(sidecar, { kExecutablePathKey, kExecutableShaKey }, why)
        || !requireExactKeys(peer,
                             { kHostIdKey, kHostInstallationKey, kHostKeyVersionKey,
                               kHostPublicKeyKey, kHostAppVersionKey, kQuicKey },
                             why)
        || !requireExactKeys(local, { kQuicKey }, why)) {
        return false;
    }

    if (!client.value(kInstallationIdKey).isString()
        || !sidecar.value(kExecutablePathKey).isString()
        || !sidecar.value(kExecutableShaKey).isString()
        || !peer.value(kHostIdKey).isString()
        || !peer.value(kHostInstallationKey).isString()
        || !peer.value(kHostPublicKeyKey).isString()
        || !peer.value(kHostAppVersionKey).isString()
        || !peer.value(kQuicKey).isString() || !local.value(kQuicKey).isString()) {
        return fail(why, ManagedRuntimeError::ConfigTypeMismatch);
    }
    const QJsonValue clientKeyVersion = client.value(kKeyVersionKey);
    const QJsonValue hostKeyVersion = peer.value(kHostKeyVersionKey);
    const QJsonValue timeout = root.value(kTimeoutKey);
    if (!clientKeyVersion.isDouble() || !hostKeyVersion.isDouble() || !timeout.isDouble()) {
        return fail(why, ManagedRuntimeError::ConfigTypeMismatch);
    }
    const auto integral = [](const QJsonValue& value) {
        const double number = value.toDouble();
        return number >= 0 && double(qint64(number)) == number;
    };
    if (!integral(clientKeyVersion) || !integral(hostKeyVersion) || !integral(timeout)) {
        return fail(why, ManagedRuntimeError::ConfigTypeMismatch);
    }

    config.apiOrigin = root.value(kOriginKey).toString();
    config.clientInstallationId = client.value(kInstallationIdKey).toString();
    config.clientKeyVersion = static_cast<int>(clientKeyVersion.toDouble());
    config.sidecarExecutablePath = QDir::cleanPath(
        QDir::fromNativeSeparators(sidecar.value(kExecutablePathKey).toString()));
    config.sidecarExecutableSha256 = sidecar.value(kExecutableShaKey).toString();
    config.hostId = peer.value(kHostIdKey).toString();
    config.hostInstallationId = peer.value(kHostInstallationKey).toString();
    config.hostKeyVersion = static_cast<int>(hostKeyVersion.toDouble());
    config.hostPublicKey = peer.value(kHostPublicKeyKey).toString().toLatin1();
    config.hostAppVersion = peer.value(kHostAppVersionKey).toString();
    config.handshakeTimeoutMs = static_cast<int>(timeout.toDouble());

    if (!parseNumericEndpoint(peer.value(kQuicKey).toString(), config.peerQuic)) {
        return fail(why, ManagedRuntimeError::PeerEndpointInvalid);
    }
    if (!parseNumericEndpoint(local.value(kQuicKey).toString(), config.localQuic)) {
        return fail(why, ManagedRuntimeError::LocalEndpointInvalid);
    }

    if (!validateManagedRuntimeConfig(config, why)) {
        return false;
    }
    out = config;
    return true;
}

} // namespace Kanade
