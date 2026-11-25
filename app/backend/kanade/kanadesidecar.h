#pragma once

#ifndef KANADESIDECAR_H
#define KANADESIDECAR_H

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include "kanaderuntime.h"

// Kanade managed-transport sidecar (client side): launch guard, framed pipe
// client, activation proof signing.
//
// This is the ONLY component allowed to start the reviewed transport process.
// Everything it does is fail-closed; there is no LAN fallback and no
// "start anyway" path.
//
// Launch provenance (SHA verification must not be a TOCTOU window):
//   1. The executable is opened read-only with FILE_SHARE_READ only (no write,
//      no delete) and the SHA-256 is computed from THAT handle.
//   2. Every ancestor directory up to the approved root is opened with
//      FILE_SHARE_READ | FILE_SHARE_WRITE but WITHOUT FILE_SHARE_DELETE, so the
//      chain cannot be renamed or removed either.
//   3. Both handle sets stay open until the child has exited.
//   4. After the child starts, the pipe server PID is checked against the child
//      PID AND the server's image path is queried; only then is the first
//      secret-bearing frame written.  GetNamedPipeServerProcessId alone is not
//      provenance -- it proves which process, not which bytes.
//
// Child contract (fixed, no extra arguments, empty environment):
//     kanade-sidecar.exe --pipe <32 lowercase hex> --parent-pid <pid>
// Pipe name: "\\.\pipe\Kanade-REM2-<the same 32 hex>".  No credential is ever
// passed on the command line or through the environment; the client's
// installation seed travels only inside the first framed `start` message.
//
// Framing: 4-byte unsigned little-endian length in 1..8192, then exactly that
// many bytes of strict canonical compact JSON.  Every message carries
// "version": 1, "session_id" (canonical lowercase UUID4; uppercase refused),
// "run_id" (canonical lowercase UUID4) and "type".
namespace Kanade {

constexpr int kSidecarMaxFrameBytes = 8192;
constexpr int kSidecarMinFrameBytes = 1;
constexpr int kSidecarProtocolVersion = 1;

//: Pipe name prefix; the suffix is exactly the 32 lowercase hex also passed as
//: --pipe.
const QString& sidecarPipePrefix();

//: A fresh 32-lowercase-hex pipe token from the platform CSPRNG; empty on
//: failure (the caller must then not launch).
QString generateSidecarPipeToken();

//: "\\.\pipe\Kanade-REM2-<token>"; empty when the token is not canonical.
QString sidecarPipeName(const QString& token);

bool isSidecarPipeToken(const QString& token);

//: Exact child argument vector (never extended, never shell-quoted).
QStringList sidecarChildArguments(const QString& token, qint64 parentPid);

// --- Framing ----------------------------------------------------------------

//: Prepends the 4-byte little-endian length; empty when the object does not fit
//: in one frame.
QByteArray encodeSidecarFrame(const QJsonObject& message);

//: Incremental parser.  feed() returns every complete frame; a malformed length
//: or non-canonical JSON sets failed() and drops the buffer.
class SidecarFrameReader {
public:
    QList<QJsonObject> feed(const QByteArray& chunk);
    bool failed() const { return m_failed; }
    QString failureReason() const { return m_failureReason; }
    void clear();

private:
    bool m_failed = false;
    QString m_failureReason;
    QByteArray m_buffer;
};

// --- Activation proof (OpenSSL Ed25519) -------------------------------------

//: Signs a canonical `session-activation-v1` message (built by
//: KanadeSession::activationMessage(), the single implementation shared with the
//: server contract) using the installation seed (canonical standard base64 of 32
//: raw bytes).  Returns the canonical standard-base64 (padded) 64-byte proof, or
//: empty on any failure (including a build without OpenSSL).  Keeping only the
//: signer here means the message format cannot drift between the two modules.
QByteArray signActivationProof(const QByteArray& seedBase64, const QByteArray& message);

// --- Launch plan ------------------------------------------------------------

// One immutable, fully validated launch+bind plan, derived from the runtime
// manifest only (never from QML, the device directory or a session snapshot).
struct SidecarPlan {
    QString approvedRoot;          // absolute non-reparse root for pinning
    QString executablePath;        // absolute file inside approvedRoot
    QString executableSha256;      // 64 lowercase hex
    QString pipeToken;             // 32 lowercase hex (fresh per association)

    QString hostId;                // canonical UUID4
    QString hostInstallationId;    // canonical UUID4
    int hostKeyVersion = 0;        // >= 1
    QByteArray hostPublicKey;      // canonical standard base64 of 32 raw bytes

    QString localQuic;             // "<lab ipv4>:<port>" for the outer transport
    QString peerQuic;              // "<lab ipv4>:<port>" for the outer transport
    int handshakeTimeoutMs = 0;
};

enum class SidecarFault {
    None = 0,
    NotConfigured,
    ExecutableUnverified,
    LaunchFailed,
    PeerNotProven,
    PipeUnavailable,
    PipeLost,
    ProtocolViolation,
    PeerRejected,
    ReadyTimeout,
    Stopped
};

QString sidecarFaultReason(SidecarFault fault);

class KanadeSidecar : public QObject {
    Q_OBJECT
public:
    enum class State {
        Idle,
        Launching,
        Handshaking,
        Prepared, // sidecar answered `prepared`
        Channeled, // exporter received; activation with Kanade may proceed
        Ready,     // sidecar answered `ready` ONLY after an actual listen
        Stopping,
        Stopped,
        Failed
    };
    Q_ENUM(State)

    explicit KanadeSidecar(QObject* parent = nullptr);
    ~KanadeSidecar() override;

    // Validates and stores the plan.  Refuses while an association is live.
    bool configure(const SidecarPlan& plan, QString* reasonOut = nullptr);

    bool isConfigured() const { return !m_plan.executablePath.isEmpty(); }
    State state() const { return m_state; }
    SidecarFault fault() const { return m_fault; }
    QByteArray channelBinding() const { return m_channelBinding; }
    qint64 childPid() const { return m_childPid; }
    // Monotonic sequence of accepted inbound frames (0 before any).  This is
    // what a ReadyProof's ipcSequence is taken from.
    quint64 inboundSequence() const { return m_inboundSequence; }

    // Starts one association.  absoluteDeadlineMs is an ABSOLUTE
    // GetTickCount64()-based instant, never a relative duration.
    // localSeed is the Ed25519 installation seed (canonical base64); it is held
    // in memory only, never logged, and written only after the peer is proven.
    void start(const QString& sessionId, const QString& runId, const QByteArray& localSeed,
               qint64 absoluteDeadlineMs);

    // Absolute deadline updates.  Equal/lower values are ignored locally and
    // must also be refused by the sidecar (no extension from either end).
    void authorize(qint64 absoluteDeadlineMs);
    void renewLease(qint64 absoluteDeadlineMs);

    // Deterministic stop: close the pipe, wait briefly, kill only if needed.
    void stopSidecar();

signals:
    void stateChanged(Kanade::KanadeSidecar::State state);
    // Exporter digest (32 raw bytes) negotiated with the peer.
    void channelReady(const QByteArray& exporter);
    // Emitted only after the sidecar reports it actually listens.
    void ready();
    void faulted(Kanade::SidecarFault fault, const QString& reason);
    void stopped();

private:
    class Worker;
    class Thread;

    void setState(State state);
    void fail(SidecarFault fault, const QString& reason);

    SidecarPlan m_plan;
    State m_state = State::Idle;
    SidecarFault m_fault = SidecarFault::None;
    QByteArray m_channelBinding;
    qint64 m_childPid = 0;
    quint64 m_inboundSequence = 0;
    qint64 m_lastDeadlineMs = 0;
    bool m_authorized = false;

    Worker* m_worker = nullptr;
    Thread* m_thread = nullptr;
};

} // namespace Kanade

#endif // KANADESIDECAR_H
