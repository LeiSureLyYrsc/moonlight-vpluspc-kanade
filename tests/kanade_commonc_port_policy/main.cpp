#include <QCoreApplication>
#include <QHostAddress>
#include <QUdpSocket>
#include <cstdio>
#include <cstring>

#include "Limelight.h"
#include "Rtsp.h"

static QUdpSocket* socketOut;
static quint16 sinkPort;
static int attempts;
static int writes;

static int emitProbe() {
    ++attempts;
    if (socketOut->writeDatagram(QByteArrayLiteral("x"), QHostAddress(QHostAddress::LocalHost), sinkPort) != 1)
        return -1;
    ++writes;
    return 0;
}

static int startConnection(PSERVER_INFORMATION, PSTREAM_CONFIGURATION,
                           PCONNECTION_LISTENER_CALLBACKS, PDECODER_RENDERER_CALLBACKS,
                           PAUDIO_RENDERER_CALLBACKS, void*, int, void*, int,
                           const LI_MANAGED_PORT_POLICY*) {
    return emitProbe();
}

#define freeMessage(message) static_cast<void>(message)
static int notifyAudioPortNegotiationComplete() { return emitProbe(); }
#include "managed-port-guards.inc"
#undef freeMessage

static bool live(void* flag) { return *static_cast<bool*>(flag); }

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QUdpSocket sink, sender;
    socketOut = &sender;
    if (!sink.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)))
        return 1;
    sinkPort = sink.localPort();
    SERVER_INFORMATION server{};
    server.address = "127.0.0.1";
    server.serverInfoAppVersion = "7.1.431.-1";
    server.rtspSessionUrl = "rtspenc://127.0.0.1:48010";
    STREAM_CONFIGURATION stream{};
    bool lease = true;
    LI_MANAGED_PORT_POLICY policy{1, 47998, 47999, 48000, live, &lease};
    const auto start = [&](const LI_MANAGED_PORT_POLICY* input) {
        return LiStartConnectionWithPortPolicy(&server, &stream, nullptr, nullptr, nullptr,
                                               nullptr, 0, nullptr, 0, input);
    };
    if (start(nullptr) != LI_MANAGED_POLICY_ERR_MISSING)
        return 2;
    policy.audioPort = 48001;
    if (start(&policy) != LI_MANAGED_POLICY_ERR_PORT)
        return 3;
    policy.audioPort = 48000;
    lease = false;
    if (start(&policy) != LI_MANAGED_POLICY_ERR_CALLBACK)
        return 4;
    lease = true;
    stream.enableMic = true;
    if (start(&policy) != LI_MANAGED_POLICY_ERR_MODE)
        return 5;
    stream.enableMic = false;
    server.rtspSessionUrl = "rtspenc://127.0.0.1:47990";
    if (start(&policy) != LI_MANAGED_POLICY_ERR_MODE)
        return 5;
    server.rtspSessionUrl = "rtspenc://127.0.0.1:48010";

    managedPorts = policy;
    const char* ports[]{"server_port=48000", "server_port=47998", "server_port=47999"};
    OPTION_ITEM transports[3]{};
    RTSP_MESSAGE responses[3]{};
    for (int i = 0; i < 3; ++i) {
        transports[i].option = const_cast<char*>("Transport");
        transports[i].content = const_cast<char*>(ports[i]);
        responses[i].options = &transports[i];
    }
    struct Case { int track; const char* wrong; };
    const Case cases[]{{0, "server_port=48001"}, {1, "server_port=47999"},
                       {2, "server_port=47998"}, {0, "server_port=48000-48001"},
                       {0, "server_port=048000"}, {0, "server_port=48000x"}};
    for (const auto& test : cases) {
        transports[test.track].content = const_cast<char*>(test.wrong);
        if (runSetupFixture(responses) != LI_MANAGED_POLICY_ERR_PORT)
            return 6;
        transports[test.track].content = const_cast<char*>(ports[test.track]);
    }
    responses[0].options = nullptr;
    if (runSetupFixture(responses) != LI_MANAGED_POLICY_ERR_PORT)
        return 7;
    responses[0].options = &transports[0];
    transports[0].flags = FLAG_DUPLICATE_OPTION;
    if (runSetupFixture(responses) != LI_MANAGED_POLICY_ERR_PORT)
        return 8;
    transports[0].flags = 0;
    lease = false;
    if (runSetupFixture(responses) != LI_MANAGED_POLICY_ERR_PORT || LiManagedPortAllowed(48000, 48000))
        return 9;
    if (attempts != 0 || writes != 0 || sink.hasPendingDatagrams() || sink.waitForReadyRead(100))
        return 10;

    // Positive control proves the OS sink is reachable and the write counter
    // really changes. The fixture uses the SETUP branches and notification call
    // from the locked source, not an end-to-end encrypted RTSP peer.
    lease = true;
    if (runSetupFixture(responses) != 0 ||
        attempts != 1 || writes != 1 || !(sink.hasPendingDatagrams() || sink.waitForReadyRead(1000)))
        return 11;
    char datagram[8];
    sink.readDatagram(datagram, sizeof(datagram));
    const int audioStartAttempts = attempts;
    const int audioStartWrites = writes;
    if (runAudioGuardFixture(48001) != 0 || attempts != audioStartAttempts ||
        writes != audioStartWrites || sink.hasPendingDatagrams() || sink.waitForReadyRead(100))
        return 12;
    lease = false;
    if (runAudioGuardFixture(48000) != 0 || attempts != audioStartAttempts ||
        writes != audioStartWrites || sink.hasPendingDatagrams() || sink.waitForReadyRead(100))
        return 13;
    lease = true;
    if (runAudioGuardFixture(48000) != 1 || attempts != audioStartAttempts + 1 ||
        writes != audioStartWrites + 1 || !(sink.hasPendingDatagrams() || sink.waitForReadyRead(1000)))
        return 14;
    std::puts("SETUP managed reject: sends=0; SETUP accepted sink control: sends=1; audio guard rejects: sends=0; audio accepted sink control: sends=1");
    return 0;
}
