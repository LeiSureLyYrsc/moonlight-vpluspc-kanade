// Focused, offline tests for the Kanade client control plane.
//
// Explicitly NON-NETWORK and NON-ACCOUNT:
//   * No socket is opened, no DNS lookup, no HTTP request, no QML engine.
//   * No OS trust store, CA or root certificate is installed or read.  No TLS
//     fixture material is checked in for this lane at all: a live mock-HTTPS
//     lane, when one is added, must generate throwaway material into a temp
//     directory at run time and never install it as system trust.
//   * No DPAPI identity is created: this target defines
//     KANADE_DISABLE_WIN32_IDENTITY, so the store reports Unsupported and the
//     controller reports supported()==false.  The assertions below verify that
//     closure instead of enabling it.
//
// What it proves:
//   1. KanadeApi::normalizeOrigin is a strict HTTPS funnel: the only shape that
//      ever reaches a request builder.
//   2. The controller is inert and secret-free while the platform/storage gate
//      is closed: no authenticated state, no device rows, no origin, and calls
//      are no-ops that cannot leak an error code or crash.
//   3. The runtime manifest contract (origin / ids / key versions / outer
//      endpoints) and the sidecar framing + activation-message helpers are
//      strict, canonical and fail closed.  These are pure functions.

#include "backend/kanade/kanadeapi.h"
#include "backend/kanade/kanadecontroller.h"
#include "backend/kanade/kanaderuntime.h"
#include "backend/kanade/kanadesession.h"
#include "backend/kanade/kanadesidecar.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QUrl>

#include <cstdio>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* what)
{
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::printf("FAIL: %s\n", what);
    }
}

void testNormalizeOriginAcceptsOnlyBareHttps()
{
    QUrl out;

    check(KanadeApi::normalizeOrigin(QStringLiteral("https://kanade.example.test"), out),
          "bare https origin accepted");
    check(out.scheme() == QLatin1String("https"), "origin scheme is https");
    check(out.toString() == QStringLiteral("https://kanade.example.test"),
          "origin has no trailing slash, path or port");

    // Default port is stripped; explicit non-default port is kept.
    check(KanadeApi::normalizeOrigin(QStringLiteral("https://kanade.example.test:443"), out),
          "explicit :443 accepted");
    check(out.port() == -1, ":443 normalized away");
    check(KanadeApi::normalizeOrigin(QStringLiteral("https://kanade.example.test:8443"), out),
          "explicit non-default port accepted");
    check(out.port() == 8443, "non-default port preserved");

    // Host case is normalized; uppercase scheme is accepted and lowercased.
    check(KanadeApi::normalizeOrigin(QStringLiteral("HTTPS://Kanade.Example.TEST"), out),
          "uppercase scheme/host accepted");
    check(out.scheme() == QLatin1String("https"), "scheme lowercased");
    check(out.host() == QStringLiteral("kanade.example.test"), "host lowercased");

    // A single trailing slash is tolerated and dropped.
    check(KanadeApi::normalizeOrigin(QStringLiteral("https://kanade.example.test/"), out),
          "trailing slash tolerated");
    check(out.path().isEmpty() || out.path() == QLatin1String("/"), "no path retained");

    // Surrounding whitespace is trimmed (user paste), interior is not invented.
    check(KanadeApi::normalizeOrigin(QStringLiteral("  https://kanade.example.test  "), out),
          "surrounding whitespace trimmed");
}

void testNormalizeOriginRejectsEverythingElse()
{
    QUrl out = QUrl(QStringLiteral("https://sentinel.invalid"));
    const QUrl sentinel = out;

    const char* rejected[] = {
        "",
        "   ",
        "kanade.example.test",              // relative
        "http://kanade.example.test",      // plaintext
        "ftp://kanade.example.test",       // wrong scheme
        "wss://kanade.example.test",       // wrong scheme (no WS here)
        "https://",                        // no host
        "https://user:pass@kanade.example.test",             // userinfo
        "https://user@kanade.example.test",                  // userinfo
        "https://@kanade.example.test",                      // empty userinfo delimiter
        "https://kanade.example.test/api",                   // path
        "https://kanade.example.test/a/b",                   // path
        "https://kanade.example.test?x=1",                   // query
        "https://kanade.example.test/#frag",                 // fragment
        "https://kanade.example.test#frag",                  // fragment
        "https://kanade.example.test#",                      // empty fragment delimiter
        "https://kanade.example.test:0",                     // disallowed port
        "https://[::1]",                                    // unsupported by installation identity
        "https://kanade.example.test:notaport",              // bad port
        "https://kanade example.test",                       // space in host
    };
    for (const char* value : rejected) {
        const QString input = QString::fromUtf8(value);
        const bool accepted = KanadeApi::normalizeOrigin(input, out);
        check(!accepted, "non-canonical origin rejected");
        if (!accepted) {
            // A rejected input must never overwrite the caller's value.
            check(out == sentinel, "rejected origin leaves the output untouched");
        }
        out = sentinel;
    }

    // An http -> https "upgrade" is never performed silently.
    check(!KanadeApi::normalizeOrigin(QStringLiteral("http://kanade.example.test"), out),
          "http is rejected, not upgraded");
}

void testControllerIsClosedWhenStorageIsNotProven()
{
#ifdef KANADE_ENABLE_WIN32_IDENTITY
    // This test target must never be built with the Win32 storage macro: it has
    // no isolation fixture for the DACL proof and must not create a real
    // identity.  Fail loudly if a build tries.
    check(false, "kanade_control_test must not define KANADE_ENABLE_WIN32_IDENTITY");
#endif
    KanadeController controller(QStringLiteral("D:/tmp/opencode-temp/kanade-test-root"));
    check(!controller.supported(),
          "controller reports unsupported while the Win32 storage proof is disabled");
    check(!controller.authenticated(), "controller starts unauthenticated");
    check(!controller.busy(), "controller starts idle");
    check(controller.devices().isEmpty(), "controller starts with no device rows");
    check(controller.pairState().isEmpty(), "controller starts with no pair state");
    check(controller.errorCode().isEmpty(), "controller starts with no error code");
    check(controller.origin().isEmpty(), "controller starts with no origin");
    // The managed path is closed until a runtime is configured AND the identity
    // store works; both are false here.
    check(!controller.onlineSupported(), "online path starts unsupported");
    check(controller.onlineState() == QStringLiteral("idle"), "online state starts idle");
    check(!controller.activationConfirmed(), "no activation is fabricated");
    check(!controller.onlineReady(), "managed ready gate starts closed");
    check(controller.leaseRemainingMs() == 0, "no lease is fabricated");

    // The native bridge of a control-plane fixture has no native path at all:
    // it must report unavailable and never claim readiness or a pairing.
    check(controller.nativePairingState() == QStringLiteral("unavailable"),
          "native bridge starts unavailable");
    check(controller.nativeApps().isEmpty(), "native app list starts empty");
    check(!controller.nativeBusy(), "native bridge starts idle");
    check(controller.nativePin().isEmpty(), "no PIN is generated before pairing");
    check(controller.nativeErrorCode().isEmpty(), "native bridge starts without an error");

    // Every operation is inert and must not crash, assert or claim success.
    controller.login(QStringLiteral("https://kanade.example.test"), QStringLiteral("user"),
                     QStringLiteral("not-a-real-password"));
    controller.refreshDevices();
    controller.addDevice(QStringLiteral("ABCD-EFGH"), QStringLiteral("password"),
                         QStringLiteral("not-a-real-password"));
    controller.cancelPair();
    controller.removeGrant(QStringLiteral("11111111-2222-4333-8444-555555555555"));
    controller.startOnlineSessionForGrant(QStringLiteral("11111111-2222-4333-8444-555555555555"),
                                          QStringLiteral("22222222-3333-4444-8555-666666666666"));
    controller.cancelOnlineSession();
    controller.clearOnlineError();
    // Native bridge calls are inert here and must never create a Session.
    controller.beginNativePairing();
    controller.refreshNativeApps();
    check(controller.createNativeStream(QStringLiteral("0")) == nullptr,
          "no native Session can be created in a control-plane fixture");
    controller.stopNativeApp();
    check(controller.nativePairingState() == QStringLiteral("unavailable"),
          "native bridge stays unavailable after inert calls");
    check(!controller.nativeBusy(), "native bridge never becomes busy here");
    check(controller.nativePin().isEmpty(), "no PIN leaks out of an unavailable bridge");
    controller.logout();
    controller.forgetInstallation();
    controller.disableCredentialDumps();

    check(!controller.authenticated(), "no operation authenticated a closed controller");
    check(!controller.busy(), "no operation left a stale busy flag");
    check(controller.devices().isEmpty(), "no operation produced device rows");
    check(controller.origin().isEmpty(), "no operation set an origin");
    check(controller.errorCode().isEmpty(),
          "closed controller did not surface an error code for inert calls");
    check(controller.onlineState() == QStringLiteral("idle")
              || controller.onlineState() == QStringLiteral("failed"),
          "online state stays non-authoritative for a closed controller");

    // The scope guard also rejects a plaintext or malformed service URL before
    // any of the above can matter (it must not become "origin_mismatch" or a
    // network attempt).
    controller.login(QStringLiteral("http://kanade.example.test"), QStringLiteral("user"),
                     QStringLiteral("not-a-real-password"));
    check(controller.errorCode().isEmpty(),
          "closed controller stays inert even for an http service URL");
}

void testSensitiveOperationSignalIsEmittedBeforeValidation()
{
    // The crash-dump suppression must happen even for a call that will be
    // rejected (empty fields, bad origin, unsupported platform): a password
    // may already exist in the caller's stack.
    KanadeController controller(QStringLiteral("D:/tmp/opencode-temp/kanade-test-root"));
    int emitted = 0;
    QObject::connect(&controller, &KanadeController::sensitiveOperationStarted,
                     [&emitted] { ++emitted; });

    controller.login(QString(), QString(), QString());
    check(emitted == 1, "login emits the sensitive-operation signal even when refused");

    controller.login(QStringLiteral("http://insecure.example"), QStringLiteral("u"),
                     QStringLiteral("p"));
    check(emitted == 2, "signal precedes origin validation");

    controller.disableCredentialDumps();
    check(emitted == 3, "explicit disable also emits the signal");
}

void testApiRejectsRequestBeforeOrigin()
{
    // A fresh API has no origin; an authenticated GET must fail with
    // InvalidOrigin and must never construct a network request.
    KanadeApi api;
    KanadeApi::Result captured;
    bool delivered = false;
    api.get(QStringLiteral("/v1/devices"), [&](const KanadeApi::Result& result) {
        captured = result;
        delivered = true;
    });
    check(delivered, "pre-origin request completes");
    check(captured.kind == KanadeApi::ErrorKind::InvalidOrigin,
          "pre-origin request fails with InvalidOrigin");
    check(captured.httpStatus == 0, "pre-origin failure has no HTTP status");
    check(captured.serverCode.isEmpty(), "pre-origin failure carries no server code");

    // Adopting a malformed token pair with nothing held must not fabricate state.
    api.adoptTokenPair(QJsonObject{});
    check(!api.hasTokens(), "malformed token pair does not create credentials");

    QJsonObject tokens{{QStringLiteral("token_type"), QStringLiteral("Bearer")},
                       {QStringLiteral("access_token"),
                        QStringLiteral("kat_") + QString(43, QLatin1Char('A'))},
                       {QStringLiteral("refresh_token"),
                        QStringLiteral("krt_") + QString(64, QLatin1Char('A'))}};
    check(KanadeApi::tokenPairIsUsable(tokens), "synthetic opaque token syntax accepted");
    tokens.insert(QStringLiteral("access_token"), QStringLiteral("kat_invalid\r\n"));
    check(!KanadeApi::tokenPairIsUsable(tokens), "header control characters rejected");
}

void testRuntimeManifestShapeIsStrict()
{
    using namespace Kanade;

    // Pure validators: no filesystem, no process.
    check(isCanonicalSha256Hex(QString(64, QLatin1Char('a'))), "64 lowercase hex accepted");
    check(!isCanonicalSha256Hex(QString(64, QLatin1Char('A'))), "uppercase hex rejected");
    check(!isCanonicalSha256Hex(QString(63, QLatin1Char('a'))), "short digest rejected");

    check(isCanonicalUuid4Text(QStringLiteral("11111111-1111-4111-8111-111111111111")),
          "canonical uuid4 accepted");
    check(!isCanonicalUuid4Text(QStringLiteral("11111111-1111-4111-8111-11111111111A")),
          "uppercase uuid rejected");
    check(!isCanonicalUuid4Text(QStringLiteral("11111111-1111-3111-8111-111111111111")),
          "non-v4 version nibble rejected");

    check(isFixedIpv4Literal(QStringLiteral("203.0.113.10"), false), "public dotted quad accepted");
    check(!isFixedIpv4Literal(QStringLiteral("127.0.0.1"), false), "loopback refused as a peer");
    check(isFixedIpv4Literal(QStringLiteral("127.0.0.1"), true), "loopback allowed for local binds");
    check(!isFixedIpv4Literal(QStringLiteral("203.0.113.010"), false), "leading zero rejected");
    check(!isFixedIpv4Literal(QStringLiteral("203.0.113"), false), "short quad rejected");
    check(!isFixedIpv4Literal(QStringLiteral("169.254.1.1"), false), "link-local rejected");
    check(!isFixedIpv4Literal(QStringLiteral("0.0.0.0"), false), "wildcard rejected");

    QString canonical;
    check(canonicalHttpsOrigin(QStringLiteral("https://kanade.example"), &canonical),
          "bare https origin accepted by the manifest validator");
    check(canonical == QStringLiteral("https://kanade.example"), "origin stays canonical");
    check(canonicalHttpsOrigin(QStringLiteral("https://kanade.example:8443"), &canonical)
              && canonical == QStringLiteral("https://kanade.example:8443"),
          "non-default port preserved");
    check(canonicalHttpsOrigin(QStringLiteral("https://kanade.example:443"), &canonical)
              && canonical == QStringLiteral("https://kanade.example"),
          ":443 stripped");
    check(!canonicalHttpsOrigin(QStringLiteral("https://Kanade.example"), &canonical),
          "mixed-case host is not silently normalized");
    check(!canonicalHttpsOrigin(QStringLiteral("http://kanade.example"), &canonical),
          "plaintext refused");
    check(!canonicalHttpsOrigin(QStringLiteral("https://kanade.example/"), &canonical),
          "trailing slash refused (this contract has no path)");
    check(!canonicalHttpsOrigin(QStringLiteral("https://kanade.example?x=1"), &canonical),
          "query refused");
    check(!canonicalHttpsOrigin(QStringLiteral("https://localhost"), &canonical),
          "localhost is never a service origin");

    ManagedQuicEndpoint endpoint;
    check(parseNumericEndpoint(QStringLiteral("203.0.113.11:50000"), endpoint)
              && endpoint.port == 50000 && endpoint.ipv4 == QStringLiteral("203.0.113.11"),
          "numeric endpoint parsed");
    check(parseNumericEndpoint(QStringLiteral("127.0.0.1:50000"), endpoint)
              && endpoint.port == 50000,
          "loopback parses as an endpoint (a manifest may still refuse it)");
    check(!parseNumericEndpoint(QStringLiteral("203.0.113.11"), endpoint), "port is mandatory");
    check(!parseNumericEndpoint(QStringLiteral("203.0.113.11:0"), endpoint), "port 0 refused");
    check(!parseNumericEndpoint(QStringLiteral("[::1]:50000"), endpoint), "ipv6 refused");
    check(!parseNumericEndpoint(QStringLiteral("localhost:50000"), endpoint),
          "hostnames refused");
    check(isForbiddenOuterPort(47989) && isForbiddenOuterPort(47990)
              && isForbiddenOuterPort(48000) && isForbiddenOuterPort(48001),
          "GameStream and management ports are never outer endpoints");
    check(!isForbiddenOuterPort(50000), "an arbitrary high port is allowed as an outer port");
}

void testSidecarFramingAndCanonicalJSON()
{
    using namespace Kanade;

    QJsonObject message;
    message.insert(QStringLiteral("type"), QStringLiteral("prepared"));
    message.insert(QStringLiteral("version"), 1);
    message.insert(QStringLiteral("session_id"),
                   QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd"));
    message.insert(QStringLiteral("run_id"),
                   QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"));

    const QByteArray frame = encodeSidecarFrame(message);
    check(!frame.isEmpty(), "frame encoded");
    check(frame.size() > 4, "frame has a payload");
    check(quint8(frame.at(0)) == quint8(frame.size() - 4), "length prefix is little-endian");
    check(quint8(frame.at(1)) == 0 && quint8(frame.at(2)) == 0 && quint8(frame.at(3)) == 0,
          "high length bytes are zero");

    SidecarFrameReader reader;
    // Delivered one byte at a time: the parser must be resynchronisation-free and
    // reassemble exactly one message.
    QList<QJsonObject> received;
    for (int i = 0; i < frame.size(); ++i) {
        received += reader.feed(frame.mid(i, 1));
    }
    check(!reader.failed(), "byte-wise framing parsed");
    check(received.size() == 1, "exactly one message decoded");
    check(received.value(0).value(QStringLiteral("type")).toString()
              == QStringLiteral("prepared"),
          "decoded message keeps its type");

    // A zero-length frame is a violation, never "empty message".
    SidecarFrameReader zero;
    QByteArray zeroFrame(4, '\0');
    zero.feed(zeroFrame);
    check(zero.failed(), "zero-length frame refused");

    // Oversized length is refused before allocating.
    SidecarFrameReader oversized;
    QByteArray oversizedFrame(4, '\0');
    oversizedFrame[0] = char(0x01);
    oversizedFrame[1] = char(0x20); // 0x2001 = 8193
    oversized.feed(oversizedFrame);
    check(oversized.failed(), "frame over 8192 refused");

    // Non-canonical JSON (whitespace) is refused even though it parses.
    SidecarFrameReader loose;
    const QByteArray loosePayload = "{ \"type\" : \"prepared\" }";
    QByteArray looseFrame(4, '\0');
    looseFrame[0] = char(loosePayload.size());
    looseFrame.append(loosePayload);
    loose.feed(looseFrame);
    check(loose.failed(), "non-canonical spelling refused");

    // Duplicate keys cannot survive canonical re-serialization either.
    SidecarFrameReader duplicate;
    const QByteArray duplicatePayload = "{\"a\":1,\"a\":1}";
    QByteArray duplicateFrame(4, '\0');
    duplicateFrame[0] = char(duplicatePayload.size());
    duplicateFrame.append(duplicatePayload);
    duplicate.feed(duplicateFrame);
    check(duplicate.failed(), "duplicate keys refused");

    // Pipe token / name / argv contract.
    check(isSidecarPipeToken(QStringLiteral("0123456789abcdef0123456789abcdef")),
          "canonical pipe token accepted");
    check(!isSidecarPipeToken(QStringLiteral("0123456789ABCDEF0123456789abcdef")),
          "uppercase pipe token refused");
    check(sidecarPipeName(QStringLiteral("0123456789abcdef0123456789abcdef"))
              == QStringLiteral("\\\\.\\pipe\\Kanade-REM2-0123456789abcdef0123456789abcdef"),
          "pipe name matches the Go prefix");
    const QStringList argv =
        sidecarChildArguments(QStringLiteral("0123456789abcdef0123456789abcdef"), 4321);
    check(argv.size() == 4, "exactly two flag pairs");
    check(argv.value(0) == QStringLiteral("--pipe")
              && argv.value(2) == QStringLiteral("--parent-pid")
              && argv.value(3) == QStringLiteral("4321"),
          "child arguments are the fixed four values");
    check(sidecarChildArguments(QStringLiteral("not-a-token"), 4321).isEmpty(),
          "invalid token produces no launch arguments");
}

void testActivationMessageMatchesTheServerContract()
{
    // This is the exact byte string Kanade's
    // kanade.security.session_activation.activation_message() produces for the
    // same inputs (verified against the Python implementation, which sorts keys
    // and uses compact separators).
    const QByteArray message = Kanade::KanadeSession::activationMessage(
        QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), QStringLiteral("client"),
        QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff"), 3, 2,
        QString(64, QLatin1Char('0')), QString(64, QLatin1Char('1')));

    const QByteArray expected =
        "kanade.session-activation.v1\n"
        "{\"channel_binding\":\"1111111111111111111111111111111111111111111111111111111111111111\","
        "\"client_installation_id\":\"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee\","
        "\"client_key_version\":3,"
        "\"host_installation_id\":\"ffffffff-ffff-4fff-9fff-ffffffffffff\","
        "\"host_key_version\":2,"
        "\"role\":\"client\","
        "\"session_id\":\"dddddddd-dddd-4ddd-8ddd-dddddddddddd\","
        "\"ticket_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
        "\"version\":1}";
    check(message == expected, "canonical activation message is byte-identical");

    // Fail closed on any non-canonical or inconsistent input.
    check(Kanade::KanadeSession::activationMessage(
              QStringLiteral("DDDDDDDD-dddd-4ddd-8ddd-dddddddddddd"), QStringLiteral("client"),
              QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
              QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff"), 3, 2,
              QString(64, QLatin1Char('0')), QString(64, QLatin1Char('1')))
              .isEmpty(),
          "uppercase session id refused");
    check(Kanade::KanadeSession::activationMessage(
              QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), QStringLiteral("server"),
              QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
              QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff"), 3, 2,
              QString(64, QLatin1Char('0')), QString(64, QLatin1Char('1')))
              .isEmpty(),
          "unknown role refused");
    check(Kanade::KanadeSession::activationMessage(
              QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), QStringLiteral("client"),
              QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
              QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff"), 0, 2,
              QString(64, QLatin1Char('0')), QString(64, QLatin1Char('1')))
              .isEmpty(),
          "zero client key version refused");
    check(Kanade::KanadeSession::activationMessage(
              QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), QStringLiteral("client"),
              QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
              QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff"), 3, 2,
              QString(63, QLatin1Char('0')), QString(64, QLatin1Char('1')))
              .isEmpty(),
          "short ticket digest refused");
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    testNormalizeOriginAcceptsOnlyBareHttps();
    testNormalizeOriginRejectsEverythingElse();
    testControllerIsClosedWhenStorageIsNotProven();
    testSensitiveOperationSignalIsEmittedBeforeValidation();
    testApiRejectsRequestBeforeOrigin();
    testRuntimeManifestShapeIsStrict();
    testSidecarFramingAndCanonicalJSON();
    testActivationMessageMatchesTheServerContract();

    std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
