#include "kanadesidecar.h"

#include "kanaderuntime.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMutex>
#include <QMutexLocker>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QStringList>
#include <QThread>
#include <QtEndian>

#include <atomic>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#endif

#if defined(Q_OS_WIN) && defined(__has_include)
#if __has_include(<openssl/evp.h>)
#define KANADE_SIDECAR_HAVE_OPENSSL 1
#include <openssl/evp.h>
#endif
#endif

// See kanadesidecar.h for the threat model.  Everything blocking lives on one
// dedicated worker thread, so a hung or hostile sidecar can never block the GUI
// thread; the owner only posts commands and receives queued signals.

namespace Kanade {

namespace {

const char kTypeKey[] = "type";
const char kVersionKey[] = "version";
const char kSessionIdKey[] = "session_id";
const char kRunIdKey[] = "run_id";
const char kExporterKey[] = "exporter";
const char kDeadlineKey[] = "deadline_ms";
const char kRoleKey[] = "role";
const char kLocalKey[] = "local";
const char kPeerKey[] = "peer";
const char kLocalSeedKey[] = "local_seed";
const char kPeerKeyKey[] = "peer_key";

const QString kTypeStart = QStringLiteral("start");
const QString kTypeAuthorize = QStringLiteral("authorize");
const QString kTypeRenew = QStringLiteral("renew");
const QString kTypeStop = QStringLiteral("stop");
const QString kTypePrepared = QStringLiteral("prepared");
const QString kTypeChannel = QStringLiteral("channel");
const QString kTypeReady = QStringLiteral("ready");

constexpr qint64 kWorkerSliceMs = 50;

bool keySetIsExactly(const QJsonObject& object, const QStringList& keys)
{
    if (object.size() != keys.size()) {
        return false;
    }
    for (const QString& key : keys) {
        if (!object.contains(key)) {
            return false;
        }
    }
    return true;
}

enum class Inbound { Prepared, Channel, Ready, Invalid };

// Server -> client message classification: exact key set per type.  There is
// deliberately no `error` message: the Go side has none, so a refusal is either
// a closed pipe or an unknown/unexpected message, both of which are protocol
// violations handled identically (fail closed, no fabricated state).
Inbound classifyInbound(const QJsonObject& message, QByteArray& exporter)
{
    const QJsonValue typeValue = message.value(QLatin1String(kTypeKey));
    if (!typeValue.isString()) {
        return Inbound::Invalid;
    }
    const QString type = typeValue.toString();
    const QStringList base = { QLatin1String(kVersionKey), QLatin1String(kSessionIdKey),
                               QLatin1String(kRunIdKey), QLatin1String(kTypeKey) };

    if (type == kTypePrepared || type == kTypeReady) {
        if (!keySetIsExactly(message, base)) {
            return Inbound::Invalid;
        }
        return type == kTypePrepared ? Inbound::Prepared : Inbound::Ready;
    }
    if (type == kTypeChannel) {
        QStringList keys = base;
        keys.append(QLatin1String(kExporterKey));
        if (!keySetIsExactly(message, keys)) {
            return Inbound::Invalid;
        }
        const QJsonValue value = message.value(QLatin1String(kExporterKey));
        if (!value.isString()) {
            return Inbound::Invalid;
        }
        const QByteArray text = value.toString().toLatin1();
        const QByteArray raw = QByteArray::fromBase64(
            text, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
        if (raw.size() != 32 || raw.toBase64() != text) {
            return Inbound::Invalid;
        }
        exporter = raw;
        return Inbound::Channel;
    }
    return Inbound::Invalid;
}

// Exact envelope: version 1, canonical lowercase UUID4 session/run ids that
// equal this attempt's.  An uppercase spelling is refused.
bool envelopeMatches(const QJsonObject& message, const QString& sessionId, const QString& runId)
{
    const QJsonValue version = message.value(QLatin1String(kVersionKey));
    if (!version.isDouble() || version.toDouble() != double(kSidecarProtocolVersion)) {
        return false;
    }
    const QJsonValue session = message.value(QLatin1String(kSessionIdKey));
    const QJsonValue run = message.value(QLatin1String(kRunIdKey));
    if (!session.isString() || !run.isString()) {
        return false;
    }
    const QString sessionText = session.toString();
    if (sessionText != sessionId || !isCanonicalUuid4Text(sessionText)) {
        return false;
    }
    const QString runText = run.toString();
    return runText == runId && isCanonicalUuid4Text(runText);
}

#ifdef Q_OS_WIN

struct ProcessIdentity {
    QString imagePath;
    quint64 creationTime = 0;
};

bool queryProcessIdentity(DWORD pid, ProcessIdentity& out)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        return false;
    }
    wchar_t buffer[MAX_PATH * 4] = {};
    DWORD size = DWORD(sizeof(buffer) / sizeof(buffer[0]));
    bool ok = QueryFullProcessImageNameW(process, 0, buffer, &size) != FALSE;
    if (ok) {
        out.imagePath = QDir::cleanPath(QString::fromWCharArray(buffer, int(size)));
        FILETIME creation = {}, exit = {}, kernel = {}, user = {};
        if (GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
            ULARGE_INTEGER value = {};
            value.LowPart = creation.dwLowDateTime;
            value.HighPart = creation.dwHighDateTime;
            out.creationTime = value.QuadPart;
        } else {
            ok = false;
        }
    }
    CloseHandle(process);
    return ok;
}

DWORD pipeServerPid(HANDLE pipe)
{
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) {
        return 0;
    }
    return DWORD(pid);
}

#endif // Q_OS_WIN

struct PipeChannel {
    void* pipe = nullptr;
    void* ioEvent = nullptr;
    void* stopEvent = nullptr;

    ~PipeChannel() { close(); }

    bool connected() const { return pipe != nullptr; }

    void close()
    {
#ifdef Q_OS_WIN
        if (pipe != nullptr) {
            CloseHandle(static_cast<HANDLE>(pipe));
            pipe = nullptr;
        }
        if (ioEvent != nullptr) {
            CloseHandle(static_cast<HANDLE>(ioEvent));
            ioEvent = nullptr;
        }
#endif
    }

    bool connectTo(const QString& pipeName, qint64 deadlineMs, QString& reason)
    {
#ifdef Q_OS_WIN
        const QString native = QStringLiteral("\\\\.\\pipe\\") + pipeName;
        const std::wstring wide(reinterpret_cast<const wchar_t*>(native.utf16()));
        for (;;) {
            const qint64 remaining = deadlineMs - qint64(GetTickCount64());
            if (remaining <= 0) {
                reason = QStringLiteral("pipe_timeout");
                return false;
            }
            HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            if (handle != INVALID_HANDLE_VALUE) {
                pipe = handle;
                ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (ioEvent == nullptr) {
                    reason = QStringLiteral("pipe_event_failed");
                    return false;
                }
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(handle, &mode, nullptr, nullptr);
                return true;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) {
                reason = QStringLiteral("pipe_open_failed");
                return false;
            }
            WaitNamedPipeW(wide.c_str(), DWORD(qMin<qint64>(remaining, kWorkerSliceMs)));
        }
#else
        Q_UNUSED(pipeName);
        Q_UNUSED(deadlineMs);
        reason = QStringLiteral("unsupported");
        return false;
#endif
    }

    // Writes the whole buffer.  One OVERLAPPED is issued per write and stays
    // alive until that write completes, so a wait slice can never overlap a
    // second I/O on the same handle with a dead OVERLAPPED.
    bool writeAll(const QByteArray& bytes, qint64 deadlineMs)
    {
#ifdef Q_OS_WIN
        HANDLE handle = static_cast<HANDLE>(pipe);
        int offset = 0;
        while (offset < bytes.size()) {
            const qint64 remaining = deadlineMs - qint64(GetTickCount64());
            if (remaining <= 0) {
                return false;
            }
            ResetEvent(static_cast<HANDLE>(ioEvent));
            OVERLAPPED overlapped = {};
            overlapped.hEvent = static_cast<HANDLE>(ioEvent);
            DWORD written = 0;
            const BOOL started = WriteFile(handle, bytes.constData() + offset,
                                          DWORD(bytes.size() - offset), &written, &overlapped);
            if (!started && GetLastError() != ERROR_IO_PENDING) {
                return false;
            }
            if (started) {
                offset += int(written);
                continue;
            }
            // Pending: wait for THIS operation only.
            HANDLE waits[2] = { static_cast<HANDLE>(ioEvent), static_cast<HANDLE>(stopEvent) };
            for (;;) {
                const qint64 left = deadlineMs - qint64(GetTickCount64());
                if (left <= 0) {
                    CancelIoEx(handle, &overlapped);
                    return false;
                }
                const DWORD wait = WaitForMultipleObjects(
                    2, waits, FALSE, DWORD(qMin<qint64>(left, kWorkerSliceMs)));
                if (wait == WAIT_OBJECT_0 + 1) {
                    CancelIoEx(handle, &overlapped);
                    return false; // stop requested
                }
                if (wait == WAIT_OBJECT_0) {
                    break;
                }
                if (wait != WAIT_TIMEOUT) {
                    CancelIoEx(handle, &overlapped);
                    return false;
                }
                // Slice expired; the operation is still the SAME one.
            }
            DWORD transferred = 0;
            if (!GetOverlappedResult(handle, &overlapped, &transferred, FALSE)) {
                return false;
            }
            offset += int(transferred);
        }
        return true;
#else
        Q_UNUSED(bytes);
        Q_UNUSED(deadlineMs);
        return false;
#endif
    }

    // Reads one chunk.  `closed` reports peer close.  A deadline expiry returns
    // true with an empty chunk so the caller can service queued commands; the
    // single pending read is cancelled, never duplicated.
    bool readSome(QByteArray& out, qint64 deadlineMs, bool& closed)
    {
#ifdef Q_OS_WIN
        closed = false;
        if (pipe == nullptr) {
            closed = true;
            return false;
        }
        HANDLE handle = static_cast<HANDLE>(pipe);
        const qint64 remaining = deadlineMs - qint64(GetTickCount64());
        if (remaining <= 0) {
            return true;
        }
        ResetEvent(static_cast<HANDLE>(ioEvent));
        OVERLAPPED overlapped = {};
        overlapped.hEvent = static_cast<HANDLE>(ioEvent);
        char buffer[4096];
        DWORD read = 0;
        const BOOL started = ReadFile(handle, buffer, DWORD(sizeof(buffer)), &read, &overlapped);
        if (started) {
            if (read == 0) {
                closed = true;
                return false;
            }
            out.append(buffer, int(read));
            return true;
        }
        if (GetLastError() != ERROR_IO_PENDING) {
            closed = true;
            return false;
        }
        HANDLE waits[2] = { static_cast<HANDLE>(ioEvent), static_cast<HANDLE>(stopEvent) };
        for (;;) {
            const qint64 left = deadlineMs - qint64(GetTickCount64());
            if (left <= 0) {
                CancelIoEx(handle, &overlapped);
                // Drain the cancellation so the OVERLAPPED outlives the I/O.
                DWORD ignored = 0;
                GetOverlappedResult(handle, &overlapped, &ignored, TRUE);
                return true;
            }
            const DWORD wait = WaitForMultipleObjects(
                2, waits, FALSE, DWORD(qMin<qint64>(left, kWorkerSliceMs)));
            if (wait == WAIT_OBJECT_0 + 1) {
                CancelIoEx(handle, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(handle, &overlapped, &ignored, TRUE);
                return true; // stop requested; the worker checks its own flag
            }
            if (wait == WAIT_OBJECT_0) {
                break;
            }
            if (wait != WAIT_TIMEOUT) {
                CancelIoEx(handle, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(handle, &overlapped, &ignored, TRUE);
                closed = true;
                return false;
            }
            // Slice expired; still waiting on the SAME read.
        }
        DWORD transferred = 0;
        if (!GetOverlappedResult(handle, &overlapped, &transferred, FALSE)) {
            if (GetLastError() == ERROR_MORE_DATA && transferred > 0) {
                out.append(buffer, int(transferred));
                return true;
            }
            closed = true;
            return false;
        }
        if (transferred == 0) {
            closed = true;
            return false;
        }
        out.append(buffer, int(transferred));
        return true;
#else
        Q_UNUSED(out);
        Q_UNUSED(deadlineMs);
        closed = true;
        return false;
#endif
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

const QString& sidecarPipePrefix()
{
    static const QString prefix = QStringLiteral("Kanade-REM2-");
    return prefix;
}

bool isSidecarPipeToken(const QString& token)
{
    if (token.size() != 32) {
        return false;
    }
    for (const QChar c : token) {
        const ushort u = c.unicode();
        const bool lower = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f');
        if (!lower) {
            return false;
        }
    }
    return true;
}

QString generateSidecarPipeToken()
{
    quint32 words[4] = { 0, 0, 0, 0 };
    QRandomGenerator::system()->fillRange(words, 4);
    QByteArray raw(16, Qt::Uninitialized);
    for (int i = 0; i < 4; ++i) {
        raw[i * 4 + 0] = static_cast<char>(words[i] & 0xff);
        raw[i * 4 + 1] = static_cast<char>((words[i] >> 8) & 0xff);
        raw[i * 4 + 2] = static_cast<char>((words[i] >> 16) & 0xff);
        raw[i * 4 + 3] = static_cast<char>((words[i] >> 24) & 0xff);
    }
    const QString token = QString::fromLatin1(raw.toHex());
    return isSidecarPipeToken(token) ? token : QString();
}

QString sidecarPipeName(const QString& token)
{
    if (!isSidecarPipeToken(token)) {
        return QString();
    }
    return QStringLiteral("\\\\.\\pipe\\") + sidecarPipePrefix() + token;
}

QStringList sidecarChildArguments(const QString& token, qint64 parentPid)
{
    // The Go side parses EXACTLY five argv entries in this order and refuses
    // everything else (no `=` form, no aliases, no repeats, no leading zero on
    // the pid).  Producing anything else here would be a launch that can only
    // fail, so the token/pid are validated to the same rules first.
    if (!isSidecarPipeToken(token) || parentPid <= 0) {
        return QStringList();
    }
    const QString pid = QString::number(parentPid);
    if (pid.isEmpty() || pid.size() > 10 || pid.startsWith(QLatin1Char('0'))) {
        return QStringList();
    }
    return { QStringLiteral("--pipe"), token, QStringLiteral("--parent-pid"), pid };
}

QByteArray encodeSidecarFrame(const QJsonObject& message)
{
    const QByteArray payload = QJsonDocument(message).toJson(QJsonDocument::Compact);
    if (payload.size() < kSidecarMinFrameBytes || payload.size() > kSidecarMaxFrameBytes) {
        return QByteArray();
    }
    QByteArray frame(4, Qt::Uninitialized);
    qToLittleEndian<quint32>(static_cast<quint32>(payload.size()),
                             reinterpret_cast<uchar*>(frame.data()));
    frame.append(payload);
    return frame;
}

QList<QJsonObject> SidecarFrameReader::feed(const QByteArray& chunk)
{
    QList<QJsonObject> messages;
    if (m_failed) {
        return messages;
    }
    m_buffer.append(chunk);
    while (m_buffer.size() >= 4) {
        const quint32 length = qFromLittleEndian<quint32>(
            reinterpret_cast<const uchar*>(m_buffer.constData()));
        if (length < static_cast<quint32>(kSidecarMinFrameBytes)
            || length > static_cast<quint32>(kSidecarMaxFrameBytes)) {
            m_failed = true;
            m_failureReason = QStringLiteral("frame_length_invalid");
            m_buffer.clear();
            return messages;
        }
        if (m_buffer.size() < 4 + static_cast<int>(length)) {
            break;
        }
        const QByteArray payload = m_buffer.mid(4, static_cast<int>(length));
        m_buffer.remove(0, 4 + static_cast<int>(length));

        QJsonParseError parseError = {};
        const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            m_failed = true;
            m_failureReason = QStringLiteral("frame_not_json_object");
            return messages;
        }
        // Strict canonical compact JSON: whitespace, another key order, an
        // escaped spelling or a duplicate key all change the re-serialization.
        if (document.toJson(QJsonDocument::Compact) != payload) {
            m_failed = true;
            m_failureReason = QStringLiteral("frame_not_canonical");
            return messages;
        }
        messages.append(document.object());
    }
    return messages;
}

void SidecarFrameReader::clear()
{
    m_buffer.clear();
    m_failed = false;
    m_failureReason.clear();
}

QByteArray signActivationProof(const QByteArray& seedBase64, const QByteArray& message)
{
#if defined(KANADE_SIDECAR_HAVE_OPENSSL)
    if (seedBase64.size() != 44 || message.isEmpty()) {
        return QByteArray();
    }
    const QByteArray seed = QByteArray::fromBase64(seedBase64);
    if (seed.size() != 32) {
        return QByteArray();
    }
    QByteArray proof;
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(seed.constData()), 32);
    EVP_MD_CTX* ctx = key != nullptr ? EVP_MD_CTX_new() : nullptr;
    if (ctx != nullptr && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) == 1) {
        size_t length = 0;
        if (EVP_DigestSign(ctx, nullptr, &length,
                           reinterpret_cast<const unsigned char*>(message.constData()),
                           static_cast<size_t>(message.size()))
                == 1
            && length == 64) {
            proof.resize(static_cast<int>(length));
            if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(proof.data()), &length,
                               reinterpret_cast<const unsigned char*>(message.constData()),
                               static_cast<size_t>(message.size()))
                != 1) {
                proof.clear();
            }
        }
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (proof.size() != 64) {
        return QByteArray();
    }
    return proof.toBase64();
#else
    Q_UNUSED(seedBase64);
    Q_UNUSED(message);
    return QByteArray(); // fail closed when this build has no OpenSSL
#endif
}

QString sidecarFaultReason(SidecarFault fault)
{
    switch (fault) {
    case SidecarFault::None:
        return QStringLiteral("ok");
    case SidecarFault::NotConfigured:
        return QStringLiteral("runtime_unconfigured");
    case SidecarFault::ExecutableUnverified:
        return QStringLiteral("sidecar_unverified");
    case SidecarFault::LaunchFailed:
        return QStringLiteral("sidecar_launch_failed");
    case SidecarFault::PeerNotProven:
        return QStringLiteral("sidecar_unverified");
    case SidecarFault::PipeUnavailable:
        return QStringLiteral("sidecar_pipe_lost");
    case SidecarFault::PipeLost:
        return QStringLiteral("sidecar_pipe_lost");
    case SidecarFault::ProtocolViolation:
        return QStringLiteral("sidecar_protocol_error");
    case SidecarFault::PeerRejected:
        return QStringLiteral("activation_failed");
    case SidecarFault::ReadyTimeout:
        return QStringLiteral("sidecar_launch_failed");
    case SidecarFault::Stopped:
        return QStringLiteral("sidecar_exited");
    }
    return QStringLiteral("sidecar_protocol_error");
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

class KanadeSidecar::Worker : public QObject {
    Q_OBJECT
public:
    Worker(SidecarPlan plan, QString sessionId, QString runId, QByteArray localSeed,
           qint64 handshakeDeadlineMs)
        : m_plan(std::move(plan))
        , m_sessionId(std::move(sessionId))
        , m_runId(std::move(runId))
        , m_seed(std::move(localSeed))
        , m_deadlineMs(handshakeDeadlineMs)
    {
    }

    ~Worker() override { m_seed.fill('\0'); }

    void requestAuthorize(qint64 deadlineMs, bool renew)
    {
        QMutexLocker locker(&m_mutex);
        m_pendingDeadline = deadlineMs;
        m_pendingRenew = renew;
        m_hasCommand = true;
    }

    void requestStop() { m_stop.store(true); }

    void execute();

signals:
    void launched();
    void prepared(quint64 sequence);
    void channel(QByteArray exporter, quint64 sequence);
    void ready(quint64 sequence);
    void faulty(Kanade::SidecarFault fault, QString reason);
    void ended();

private:
    bool sendObject(const QJsonObject& object);
    bool verifyAndLaunch(QString& reason);
    bool provePeer(QString& reason);
    Kanade::SidecarFault handshake(QString& reason);

    SidecarPlan m_plan;
    QString m_sessionId;
    QString m_runId;
    QByteArray m_seed;
    qint64 m_deadlineMs = 0;

    QMutex m_mutex;
    qint64 m_pendingDeadline = 0;
    bool m_pendingRenew = false;
    bool m_hasCommand = false;

    std::atomic<bool> m_stop{ false };

    void* m_stopEvent = nullptr;
    void* m_exeHandle = nullptr;
    QList<void*> m_directoryHandles;
    qint64 m_childPid = 0;
    quint64 m_peerCreated = 0;
    QProcess* m_process = nullptr;
    PipeChannel m_channel;
    SidecarFrameReader m_reader;
    quint64 m_sequence = 0;
    bool m_preparedSeen = false;
    bool m_channelSeen = false;
    bool m_readySeen = false;
};

bool KanadeSidecar::Worker::sendObject(const QJsonObject& object)
{
    const QByteArray frame = encodeSidecarFrame(object);
    if (frame.isEmpty()) {
        return false;
    }
    return m_channel.writeAll(frame, m_deadlineMs);
}

bool KanadeSidecar::Worker::verifyAndLaunch(QString& reason)
{
#ifdef Q_OS_WIN
    // One trust anchor for both the manifest and the executable:
    // openPinnedLaunchTarget() walks the chain from the approved root, opens
    // every ancestor WITHOUT delete share (so nothing can be renamed or
    // re-pointed), hashes the image from the returned handle, and hands the
    // handles back so they stay open across process creation.
    if (!openPinnedLaunchTarget(m_plan.approvedRoot, m_plan.executablePath,
                                m_plan.executableSha256, m_exeHandle, m_directoryHandles,
                                reason)) {
        reason = QStringLiteral("executable_unverified");
        return false;
    }

    const QStringList arguments =
        sidecarChildArguments(m_plan.pipeToken, qint64(QCoreApplication::applicationPid()));
    if (arguments.isEmpty()) {
        reason = QStringLiteral("launch_arguments_invalid");
        return false;
    }

    m_process = new QProcess();
    m_process->setProgram(m_plan.executablePath);
    m_process->setArguments(arguments);
    // Explicitly EMPTY environment: no inherited variable reaches the child,
    // and no credential is ever passed this way.
    m_process->setProcessEnvironment(QProcessEnvironment());
    m_process->setWorkingDirectory(QFileInfo(m_plan.executablePath).absolutePath());
    m_process->setStandardInputFile(QProcess::nullDevice());
    m_process->setStandardOutputFile(QProcess::nullDevice());
    m_process->setStandardErrorFile(QProcess::nullDevice());
    m_process->start();
    const qint64 remaining = m_deadlineMs - qint64(GetTickCount64());
    if (remaining <= 0 || !m_process->waitForStarted(int(qMin<qint64>(remaining, 5000)))) {
        reason = QStringLiteral("launch_failed");
        return false;
    }
    m_childPid = qint64(m_process->processId());
    if (m_childPid <= 0) {
        reason = QStringLiteral("launch_failed");
        return false;
    }
    return true;
#else
    reason = QStringLiteral("unsupported");
    return false;
#endif
}

bool KanadeSidecar::Worker::provePeer(QString& reason)
{
#ifdef Q_OS_WIN
    if (!m_channel.connectTo(sidecarPipePrefix() + m_plan.pipeToken, m_deadlineMs, reason)) {
        return false;
    }
    const DWORD serverPid = pipeServerPid(static_cast<HANDLE>(m_channel.pipe));
    if (serverPid == 0 || qint64(serverPid) != m_childPid) {
        reason = QStringLiteral("peer_not_proven");
        return false;
    }
    ProcessIdentity identity;
    if (!queryProcessIdentity(serverPid, identity)) {
        reason = QStringLiteral("peer_not_proven");
        return false;
    }
    if (identity.imagePath.compare(QDir::cleanPath(m_plan.executablePath), Qt::CaseInsensitive)
        != 0) {
        reason = QStringLiteral("peer_not_proven");
        return false;
    }
    m_peerCreated = identity.creationTime;
    return true;
#else
    reason = QStringLiteral("unsupported");
    return false;
#endif
}

Kanade::SidecarFault KanadeSidecar::Worker::handshake(QString& reason)
{
    // First frame only after the peer is proven.  Wire shape is EXACTLY
    // windows-sidecar-ipc-v1 (`protocol.Parse`): role/local/peer/local_seed/
    // peer_key, where `local` and `peer` are plain "ipv4:port" STRINGS.  No
    // extra object, field or error payload, and the role is this client end.
    QJsonObject start;
    start.insert(QLatin1String(kVersionKey), kSidecarProtocolVersion);
    start.insert(QLatin1String(kSessionIdKey), m_sessionId);
    start.insert(QLatin1String(kRunIdKey), m_runId);
    start.insert(QLatin1String(kTypeKey), kTypeStart);
    start.insert(QLatin1String(kRoleKey), QStringLiteral("client"));
    start.insert(QLatin1String(kLocalKey), m_plan.localQuic);
    start.insert(QLatin1String(kPeerKey), m_plan.peerQuic);
    start.insert(QLatin1String(kLocalSeedKey), QString::fromLatin1(m_seed));
    start.insert(QLatin1String(kPeerKeyKey), QString::fromLatin1(m_plan.hostPublicKey));

    if (!sendObject(start)) {
        reason = QStringLiteral("start_not_sent");
        return SidecarFault::PipeLost;
    }

    for (;;) {
        if (m_stop.load()) {
            // An explicit `stop` frame (base fields only) is the contract's
            // orderly end; closing the pipe without it would look like a
            // parent crash to the sidecar.
            QJsonObject stop;
            stop.insert(QLatin1String(kVersionKey), kSidecarProtocolVersion);
            stop.insert(QLatin1String(kSessionIdKey), m_sessionId);
            stop.insert(QLatin1String(kRunIdKey), m_runId);
            stop.insert(QLatin1String(kTypeKey), kTypeStop);
            sendObject(stop); // best effort: the pipe may already be gone
            reason = QStringLiteral("stopped");
            return SidecarFault::Stopped;
        }
        qint64 deadline = 0;
        bool renew = false;
        bool hasCommand = false;
        {
            QMutexLocker locker(&m_mutex);
            if (m_hasCommand) {
                deadline = m_pendingDeadline;
                renew = m_pendingRenew;
                m_hasCommand = false;
                hasCommand = true;
            }
        }
        if (hasCommand) {
            QJsonObject command;
            command.insert(QLatin1String(kVersionKey), kSidecarProtocolVersion);
            command.insert(QLatin1String(kSessionIdKey), m_sessionId);
            command.insert(QLatin1String(kRunIdKey), m_runId);
            command.insert(QLatin1String(kTypeKey), renew ? kTypeRenew : kTypeAuthorize);
            command.insert(QLatin1String(kDeadlineKey), double(deadline));
            if (!sendObject(command)) {
                reason = QStringLiteral("command_not_sent");
                return SidecarFault::PipeLost;
            }
            // The loop's own read window follows the authorized deadline; the
            // sidecar re-checks it against its own clock and its own 90 s cap.
            if (deadline > m_deadlineMs) {
                m_deadlineMs = deadline;
            }
        }

        bool closed = false;
        QByteArray chunk;
        // Bound the read to one short slice so queued authorize/renew/stop
        // commands are serviced promptly.  The sidecar enforces the real relay
        // gate on its own clock, so a slice expiry is not a failure and must not
        // spin: each iteration blocks for at most kWorkerSliceMs.
        const qint64 readDeadline = qint64(GetTickCount64()) + kWorkerSliceMs;
        if (!m_channel.readSome(chunk, readDeadline, closed)) {
            reason = closed ? QStringLiteral("pipe_closed") : QStringLiteral("read_failed");
            return SidecarFault::PipeLost;
        }
        if (chunk.isEmpty()) {
            continue;
        }
        const QList<QJsonObject> messages = m_reader.feed(chunk);
        if (m_reader.failed()) {
            reason = m_reader.failureReason();
            return SidecarFault::ProtocolViolation;
        }
        for (const QJsonObject& message : messages) {
            if (!envelopeMatches(message, m_sessionId, m_runId)) {
                reason = QStringLiteral("envelope_mismatch");
                return SidecarFault::ProtocolViolation;
            }
            QByteArray exporter;
            const Inbound kind = classifyInbound(message, exporter);
            if (kind == Inbound::Invalid) {
                reason = QStringLiteral("invalid_message");
                return SidecarFault::ProtocolViolation;
            }
            // Only an accepted, envelope-checked frame consumes a sequence
            // number, so a ReadyProof can never cite a rejected frame.
            ++m_sequence;
            switch (kind) {
            case Inbound::Prepared:
                if (m_preparedSeen) {
                    reason = QStringLiteral("duplicate_prepared");
                    return SidecarFault::ProtocolViolation;
                }
                m_preparedSeen = true;
                Q_EMIT prepared(m_sequence);
                break;
            case Inbound::Channel:
                if (!m_preparedSeen || m_channelSeen) {
                    reason = QStringLiteral("unexpected_channel");
                    return SidecarFault::ProtocolViolation;
                }
                m_channelSeen = true;
                Q_EMIT channel(exporter, m_sequence);
                break;
            case Inbound::Ready:
                if (!m_preparedSeen || !m_channelSeen || m_readySeen) {
                    reason = QStringLiteral("unexpected_ready");
                    return SidecarFault::ProtocolViolation;
                }
                m_readySeen = true;
                Q_EMIT ready(m_sequence);
                break; // authorize/renew/stop still flow
            case Inbound::Invalid:
                // No `error` frame exists in the Go contract: an unrecognized
                // message is a protocol violation, never a reason to guess.
                reason = QStringLiteral("invalid_message");
                return SidecarFault::ProtocolViolation;
            }
        }
    }
}

void KanadeSidecar::Worker::execute()
{
#ifdef Q_OS_WIN
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (m_stopEvent == nullptr) {
        Q_EMIT faulty(SidecarFault::LaunchFailed, QStringLiteral("event_failed"));
        Q_EMIT ended();
        return;
    }
    m_channel.stopEvent = m_stopEvent;
#endif

    QString reason;
    if (!verifyAndLaunch(reason)) {
        Q_EMIT faulty(reason == QStringLiteral("launch_failed") ? SidecarFault::LaunchFailed
                                                               : SidecarFault::ExecutableUnverified,
                      reason);
    } else if (!provePeer(reason)) {
        Q_EMIT faulty(reason == QStringLiteral("peer_not_proven")
                          ? SidecarFault::PeerNotProven
                          : SidecarFault::PipeUnavailable,
                      reason);
    } else {
        Q_EMIT launched();
        const SidecarFault result = handshake(reason);
        if (result != SidecarFault::Stopped) {
            Q_EMIT faulty(result, reason);
        }
    }

    if (m_process != nullptr) {
        // Teardown: close our pipe end so the child sees EOF, wait briefly,
        // then kill only if it refuses to exit.
        m_channel.close();
        if (m_process->state() != QProcess::NotRunning) {
            m_process->waitForFinished(2000);
        }
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            m_process->waitForFinished(2000);
        }
        delete m_process;
        m_process = nullptr;
    }
#ifdef Q_OS_WIN
    closePinnedLaunchHandles(m_exeHandle, m_directoryHandles);
    m_exeHandle = nullptr;
    if (m_stopEvent != nullptr) {
        CloseHandle(static_cast<HANDLE>(m_stopEvent));
        m_stopEvent = nullptr;
    }
#endif
    Q_EMIT ended();
}

// ---------------------------------------------------------------------------
// Thread wrapper
// ---------------------------------------------------------------------------

class KanadeSidecar::Thread : public QThread {
public:
    Thread(Worker* worker, QObject* parent) : QThread(parent), m_worker(worker) {}

protected:
    void run() override { m_worker->execute(); }

private:
    Worker* m_worker;
};

// ---------------------------------------------------------------------------
// KanadeSidecar
// ---------------------------------------------------------------------------

KanadeSidecar::KanadeSidecar(QObject* parent)
    : QObject(parent)
{
}

KanadeSidecar::~KanadeSidecar()
{
    // Destructor contract: never leave a running thread or child behind.  The
    // worker's own waits are all stop/deadline driven (50 ms slices plus a
    // bounded 2 s + 2 s process teardown), so this is bounded, but it is the
    // one place that may block; normal stops use the asynchronous path.
    if (m_worker != nullptr) {
        m_worker->requestStop();
    }
    if (m_thread != nullptr) {
        const bool running = m_thread->isRunning();
        if (running) {
            m_thread->wait(10000);
        }
        // The thread normally deletes itself via finished()->deleteLater(); at
        // shutdown that may never run, so take ownership back explicitly and
        // delete only when it is definitively not running.
        m_thread->disconnect(this);
        if (!m_thread->isRunning()) {
            delete m_thread;
        }
        m_thread = nullptr;
    }
    if (m_worker != nullptr) {
        // The `ended` handler normally deletes the worker; if we got here first
        // (application shutdown), it is still safe to delete now because the
        // thread above has already finished.
        m_worker->disconnect(this);
        delete m_worker;
        m_worker = nullptr;
    }
}

bool KanadeSidecar::configure(const SidecarPlan& plan, QString* reasonOut)
{
    if (m_state == State::Launching || m_state == State::Handshaking
        || m_state == State::Prepared || m_state == State::Channeled
        || m_state == State::Ready || m_state == State::Stopping) {
        if (reasonOut != nullptr) {
            *reasonOut = QStringLiteral("sidecar_busy");
        }
        return false;
    }

    // Both outer endpoints are the reviewed lab interface: numeric IPv4, never
    // loopback (a loopback UDP socket cannot reach the peer), and never the same
    // address on both ends.  GameStream's own 127.0.0.1 binds are the sidecar's
    // business and are not part of this plan.
    ManagedQuicEndpoint localEndpoint;
    ManagedQuicEndpoint peerEndpoint;
    const bool endpointsParsed = parseNumericEndpoint(plan.localQuic, localEndpoint)
        && parseNumericEndpoint(plan.peerQuic, peerEndpoint)
        && localEndpoint.ipv4 != QStringLiteral("127.0.0.1")
        && peerEndpoint.ipv4 != QStringLiteral("127.0.0.1")
        && localEndpoint.ipv4 != peerEndpoint.ipv4
        && !isForbiddenOuterPort(localEndpoint.port)
        && !isForbiddenOuterPort(peerEndpoint.port)
        && plan.localQuic != plan.peerQuic;

    const bool ok = !plan.approvedRoot.isEmpty() && !plan.executablePath.isEmpty()
        && isCanonicalSha256Hex(plan.executableSha256) && isCanonicalUuid4Text(plan.hostId)
        && isCanonicalUuid4Text(plan.hostInstallationId) && plan.hostKeyVersion >= 1
        && isCanonicalEd25519PublicKey(plan.hostPublicKey) && endpointsParsed
        && plan.handshakeTimeoutMs >= kManagedMinHandshakeMs
        && plan.handshakeTimeoutMs <= kManagedMaxHandshakeMs;
    if (!ok) {
        if (reasonOut != nullptr) {
            *reasonOut = QStringLiteral("runtime_config_invalid");
        }
        return false;
    }
    m_plan = plan;
    m_fault = SidecarFault::None;
    setState(State::Idle);
    return true;
}

void KanadeSidecar::start(const QString& sessionId, const QString& runId,
                          const QByteArray& localSeed, qint64 absoluteDeadlineMs)
{
    if (!isConfigured()) {
        fail(SidecarFault::NotConfigured, QStringLiteral("not_configured"));
        return;
    }
    if (m_state == State::Launching || m_state == State::Handshaking
        || m_state == State::Prepared || m_state == State::Channeled
        || m_state == State::Ready || m_state == State::Stopping) {
        return;
    }
    if (!isCanonicalUuid4Text(sessionId) || !isCanonicalUuid4Text(runId)) {
        fail(SidecarFault::ProtocolViolation, QStringLiteral("envelope_invalid"));
        return;
    }
    if (!isCanonicalEd25519PublicKey(localSeed)
        || !isCanonicalEd25519PublicKey(m_plan.hostPublicKey)) {
        fail(SidecarFault::ExecutableUnverified, QStringLiteral("seed_invalid"));
        return;
    }
    qint64 now = 0;
#ifdef Q_OS_WIN
    now = qint64(GetTickCount64());
#endif
    if (absoluteDeadlineMs <= now) {
        fail(SidecarFault::ReadyTimeout, QStringLiteral("deadline_invalid"));
        return;
    }
    // The bootstrap deadline only bounds launch/handshake; the sidecar's relay
    // window is armed later by the single `authorize`.  A handshake may not
    // borrow the lease's 90 s window.
    const qint64 handshakeDeadline =
        qMin<qint64>(absoluteDeadlineMs, now + m_plan.handshakeTimeoutMs);

    SidecarPlan plan = m_plan;
    const QString token = generateSidecarPipeToken();
    if (token.isEmpty()) {
        fail(SidecarFault::LaunchFailed, QStringLiteral("token_failed"));
        return;
    }
    plan.pipeToken = token;

    m_channelBinding.clear();
    m_inboundSequence = 0;
    m_childPid = 0;
    m_lastDeadlineMs = 0;
    m_authorized = false;
    m_fault = SidecarFault::None;

    auto* worker = new Worker(plan, sessionId, runId, localSeed, handshakeDeadline);
    connect(worker, &Worker::launched, this, [this] {
        if (m_state == State::Launching) {
            setState(State::Handshaking);
        }
    });
    connect(worker, &Worker::prepared, this, [this](quint64 sequence) {
        m_inboundSequence = sequence;
        if (m_state == State::Handshaking) {
            setState(State::Prepared);
        }
    });
    connect(worker, &Worker::channel, this, [this](QByteArray exporter, quint64 sequence) {
        m_inboundSequence = sequence;
        m_channelBinding = exporter;
        if (m_state == State::Prepared) {
            setState(State::Channeled);
        }
        Q_EMIT channelReady(exporter);
    });
    connect(worker, &Worker::ready, this, [this](quint64 sequence) {
        m_inboundSequence = sequence;
        if (m_state == State::Channeled) {
            setState(State::Ready);
            Q_EMIT ready();
        }
    });
    connect(worker, &Worker::faulty, this,
            [this](SidecarFault sidecarFault, QString reason) { fail(sidecarFault, reason); });
    connect(worker, &Worker::ended, this, [this, worker] {
        if (m_state != State::Failed && m_state != State::Stopped) {
            setState(State::Stopped);
            Q_EMIT stopped();
        }
        // `ended` is emitted as the last statement of execute(), so run() is
        // already unwinding.  Do NOT block here (GUI thread): quit and let the
        // thread's own finished()->deleteLater() reap it.
        if (m_thread != nullptr) {
            m_thread->quit();
            m_thread = nullptr;
        }
        worker->deleteLater();
        m_worker = nullptr;
    });

    m_worker = worker;
    m_thread = new Thread(worker, this);
    // The thread object deletes itself once run() returns; the member pointer is
    // only a handle for "still running", cleared by the `ended` handler.
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);
    setState(State::Launching);
    m_thread->start();
}

void KanadeSidecar::authorize(qint64 absoluteDeadlineMs)
{
    // The sidecar's own state machine accepts `authorize` EXACTLY ONCE, only
    // after it reported `channel`, and only while the admitted window is at
    // most 90 s ahead.  Sending it earlier is a protocol failure at the peer,
    // so it is refused locally too.
    if (m_worker == nullptr || m_authorized) {
        return;
    }
    if (m_state != State::Channeled && m_state != State::Ready) {
        return;
    }
    qint64 now = 0;
#ifdef Q_OS_WIN
    now = qint64(GetTickCount64());
#endif
    if (absoluteDeadlineMs <= now || absoluteDeadlineMs - now > 90000) {
        return; // outside the admitted window: never sent, never clamped
    }
    if (absoluteDeadlineMs <= m_lastDeadlineMs) {
        return;
    }
    m_authorized = true;
    m_lastDeadlineMs = absoluteDeadlineMs;
    m_worker->requestAuthorize(absoluteDeadlineMs, /*renew=*/false);
}

void KanadeSidecar::renewLease(qint64 absoluteDeadlineMs)
{
    // Renewal is only meaningful AFTER the single authorization, and only with
    // a strictly greater absolute deadline (the peer's gate rejects repeats).
    if (m_worker == nullptr || !m_authorized || m_state != State::Ready) {
        return;
    }
    if (absoluteDeadlineMs <= m_lastDeadlineMs) {
        return;
    }
    m_lastDeadlineMs = absoluteDeadlineMs;
    m_worker->requestAuthorize(absoluteDeadlineMs, /*renew=*/true);
}

void KanadeSidecar::stopSidecar()
{
    // Asynchronous by contract: request the stop and return immediately.  The
    // worker notices within one 50 ms slice and tears the child down; the
    // `ended` handler then finalises.  Only the destructor waits.
    if (m_worker == nullptr) {
        if (m_state != State::Idle && m_state != State::Stopped && m_state != State::Failed) {
            setState(State::Stopped);
            Q_EMIT stopped();
        }
        return;
    }
    setState(State::Stopping);
    m_worker->requestStop();
}

void KanadeSidecar::setState(State state)
{
    if (m_state == state) {
        return;
    }
    m_state = state;
    Q_EMIT stateChanged(state);
}

void KanadeSidecar::fail(SidecarFault fault, const QString& reason)
{
    if (m_fault == SidecarFault::None) {
        m_fault = fault;
    }
    setState(State::Failed);
    Q_EMIT faulted(fault, reason.isEmpty() ? sidecarFaultReason(fault) : reason);
}

} // namespace Kanade

#include "kanadesidecar.moc"
