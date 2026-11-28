#include "backend/kanade/managedendpoint.h"
#include "backend/kanade/managednative.h"
#include "backend/kanade/managednativecontroller.h"

#include <QtTest>

#include <optional>

// Regression tests for the immutable managed endpoint context.
//
// No sockets, TLS sessions, or live NvHTTP/Session objects. Tests that
// supply their own monotonic instant use a fixed fixture time.

namespace {

using Kanade::ManagedEndpointContext;
using Kanade::ManagedEndpointSpec;
using Kanade::ValidationReason;
using Kanade::ValidationResult;

const QString kHostId = QStringLiteral("a1111111-1111-4111-8111-111111111111");
const QString kGrantId = QStringLiteral("22222222-2222-4222-9222-222222222222");
const QString kSessionId = QStringLiteral("33333333-3333-4333-a333-333333333333");
const QString kClientInst = QStringLiteral("44444444-4444-4444-b444-444444444444");
const QString kHostInst = QStringLiteral("55555555-5555-4555-8555-555555555555");

// Synthetic monotonic instant for checks that take an explicit now (ms).
constexpr qint64 kNow = 1000000;

ManagedEndpointSpec validSpec()
{
    ManagedEndpointSpec spec;
    spec.apiOrigin = QStringLiteral("https://kanade.example");
    spec.hostId = kHostId;
    spec.grantId = kGrantId;
    spec.sessionId = kSessionId;
    spec.clientInstallationId = kClientInst;
    spec.hostInstallationId = kHostInst;
    spec.clientKeyVersion = 1;
    spec.hostKeyVersion = 2;
    spec.runGeneration = 7;
    spec.confirmedDeadlineMs = kNow + 90000;
    return spec;
}

std::optional<ManagedEndpointContext> makeContext(ManagedEndpointSpec spec,
                                                  ValidationResult& reason,
                                                  qint64 now = kNow)
{
    const auto context = ManagedEndpointContext::create(spec, now, reason);
    return context;
}

} // namespace

class KanadeManagedEndpointTest : public QObject {
    Q_OBJECT

private slots:
    void canonicalOriginAccepted()
    {
        struct Case {
            const char* input;
            const char* canonical;
        };
        const Case cases[] = {
            { "https://kanade.example", "https://kanade.example" },
            { "HTTPS://KANADE.EXAMPLE", "https://kanade.example" },
            { "https://kanade.example/", "https://kanade.example" },
            { "https://kanade.example:443", "https://kanade.example" },
            { "https://kanade.example:8443", "https://kanade.example:8443" },
            { "https://127.0.0.1:8443", "https://127.0.0.1:8443" },
        };
        for (const Case& test : cases) {
            QString canonical;
            const ValidationResult result =
                ManagedEndpointContext::validateApiOrigin(QString::fromLatin1(test.input),
                                                          &canonical);
            QVERIFY2(result.ok(), test.input);
            QCOMPARE(canonical, QString::fromLatin1(test.canonical));
            QVERIFY(result.detail.isEmpty());
        }
    }

    void nonCanonicalOriginRejected()
    {
        struct Case {
            const char* input;
            ValidationReason reason;
        };
        const Case cases[] = {
            { "", ValidationReason::OriginEmpty },
            { "http://kanade.example", ValidationReason::OriginSchemeNotHttps },
            { "https:/kanade.example", ValidationReason::OriginSchemeNotHttps },
            { "https://", ValidationReason::OriginHostInvalid },
            { " https://kanade.example", ValidationReason::OriginNotCanonical },
            { "https://kanade.example ", ValidationReason::OriginNotCanonical },
            { "https://user:pw@kanade.example", ValidationReason::OriginUserInfoNotAllowed },
            { "https://kanade.example/v1", ValidationReason::OriginPathNotAllowed },
            { "https://kanade.example//", ValidationReason::OriginPathNotAllowed },
            { "https://kanade.example?x=1", ValidationReason::OriginQueryNotAllowed },
            { "https://kanade.example#frag", ValidationReason::OriginFragmentNotAllowed },
            { "https://kanade.example:0", ValidationReason::OriginPortInvalid },
            { "https://kanade.example:65536", ValidationReason::OriginPortInvalid },
            { "https://kanade.example:080", ValidationReason::OriginPortInvalid },
            { "https://kanade.example:", ValidationReason::OriginPortInvalid },
            { "https://01.2.3.4", ValidationReason::OriginHostInvalid },
            { "https://1.2.3", ValidationReason::OriginHostInvalid },
            { "https://1.2.3.256", ValidationReason::OriginHostInvalid },
            { "https://kana de.example", ValidationReason::OriginNotCanonical },
            { "https://kanade_example", ValidationReason::OriginHostInvalid },
            { "https://-kanade.example", ValidationReason::OriginHostInvalid },
            { "https://kanade.example.", ValidationReason::OriginHostInvalid },
            { "https://[::1", ValidationReason::OriginHostInvalid },
            { "https://::1", ValidationReason::OriginHostInvalid },
        };
        for (const Case& test : cases) {
            QString canonical;
            const ValidationResult result =
                ManagedEndpointContext::validateApiOrigin(QString::fromLatin1(test.input),
                                                          &canonical);
            QVERIFY2(!result.ok(), test.input);
            QCOMPARE(int(result.reason), int(test.reason));
            QVERIFY2(!result.detail.isEmpty(), test.input);
            QVERIFY2(canonical.isEmpty(), test.input);
        }
    }

    void strictPortParserNeverDefaults()
    {
        quint16 port = 0;
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QString(), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("0"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("00"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("01"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("+80"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("-80"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("80a"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("65536"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral("123456"), &port));
        QVERIFY(!ManagedEndpointContext::parseStrictPort(QStringLiteral(" 80"), &port));

        QVERIFY(ManagedEndpointContext::parseStrictPort(QStringLiteral("1"), &port));
        QCOMPARE(port, quint16(1));
        QVERIFY(ManagedEndpointContext::parseStrictPort(QStringLiteral("47989"), &port));
        QCOMPARE(port, quint16(47989));
        QVERIFY(ManagedEndpointContext::parseStrictPort(QStringLiteral("65535"), &port));
        QCOMPARE(port, quint16(65535));
    }

    void canonicalUuid4Strictness()
    {
        QVERIFY(ManagedEndpointContext::isCanonicalUuid4(kHostId));
        QVERIFY(!ManagedEndpointContext::isCanonicalUuid4(kHostId.toUpper()));
        QVERIFY(!ManagedEndpointContext::isCanonicalUuid4(QString()));
        QVERIFY(!ManagedEndpointContext::isCanonicalUuid4(kHostId + QLatin1Char('x')));
        // Version nibble must be 4, variant 8/9/a/b.
        QVERIFY(!ManagedEndpointContext::isCanonicalUuid4(
            QStringLiteral("11111111-1111-3111-8111-111111111111")));
        QVERIFY(!ManagedEndpointContext::isCanonicalUuid4(
            QStringLiteral("11111111-1111-4111-c111-111111111111")));
        QVERIFY(ManagedEndpointContext::isCanonicalUuid4(
            QStringLiteral("11111111-1111-4111-a111-111111111111")));
    }

    void pinnedLoopbackEndpointsOnly()
    {
        QVERIFY(ManagedEndpointContext::validateHttpEndpoint(
            QStringLiteral("127.0.0.1"), ManagedEndpointContext::kManagedHttpPort).ok());
        QVERIFY(ManagedEndpointContext::validateHttpsEndpoint(
            QStringLiteral("127.0.0.1"), ManagedEndpointContext::kManagedHttpsPort).ok());

        // Crossed ports are never interchangeable.
        QCOMPARE(int(ManagedEndpointContext::validateHttpEndpoint(
                         QStringLiteral("127.0.0.1"),
                         ManagedEndpointContext::kManagedHttpsPort).reason),
                 int(ValidationReason::EndpointPortNotPinned));
        QCOMPARE(int(ManagedEndpointContext::validateHttpsEndpoint(
                         QStringLiteral("127.0.0.1"),
                         ManagedEndpointContext::kManagedHttpPort).reason),
                 int(ValidationReason::EndpointPortNotPinned));

        const QStringList aliases = {
            QStringLiteral("localhost"), QStringLiteral("::1"), QStringLiteral("0.0.0.0"),
            QStringLiteral("127.0.0.2"), QStringLiteral("127.1"), QStringLiteral("2130706433"),
            QStringLiteral(""), QStringLiteral("127.0.0.1 ")
        };
        for (const QString& alias : aliases) {
            const ValidationResult result = ManagedEndpointContext::validateHttpEndpoint(
                alias, ManagedEndpointContext::kManagedHttpPort);
            QVERIFY2(!result.ok(), qPrintable(alias));
            QCOMPARE(int(result.reason), int(ValidationReason::EndpointHostNotPinnedLoopback));
        }

        const quint16 wrongPorts[] = { 0, 80, 443, 47990, 48001, 48010, 65535 };
        for (const quint16 port : wrongPorts) {
            QCOMPARE(int(ManagedEndpointContext::validateHttpEndpoint(
                             QStringLiteral("127.0.0.1"), port).reason),
                     int(ValidationReason::EndpointPortNotPinned));
            QCOMPARE(int(ManagedEndpointContext::validateHttpsEndpoint(
                             QStringLiteral("127.0.0.1"), port).reason),
                     int(ValidationReason::EndpointPortNotPinned));
        }
    }

    void onlyExactEncryptedRtspShapeAccepted()
    {
        QCOMPARE(ManagedEndpointContext::expectedRtspUrl(),
                 QStringLiteral("rtspenc://127.0.0.1:48010"));
        QVERIFY(ManagedEndpointContext::validateRtspUrl(
            ManagedEndpointContext::expectedRtspUrl()).ok());

        struct Case {
            const char* input;
            ValidationReason reason;
        };
        const Case cases[] = {
            { "", ValidationReason::RtspUrlNotCanonical },
            { "rtsp://127.0.0.1:48010", ValidationReason::RtspSchemePlaintextNotAllowed },
            { "RTSP://127.0.0.1:48010", ValidationReason::RtspSchemePlaintextNotAllowed },
            { "rtspenc", ValidationReason::RtspUrlNotCanonical },
            { "RTSPENC://127.0.0.1:48010", ValidationReason::RtspSchemeNotAllowed },
            { "RtspEnc://127.0.0.1:48010", ValidationReason::RtspSchemeNotAllowed },
            { "rtspru://127.0.0.1:48010", ValidationReason::RtspSchemeNotAllowed },
            { "rtspenc://localhost:48010", ValidationReason::RtspHostNotPinnedLoopback },
            { "rtspenc://[::1]:48010", ValidationReason::RtspHostNotPinnedLoopback },
            { "rtspenc://127.0.0.1", ValidationReason::RtspPortNotPinned },
            { "rtspenc://127.0.0.1:48011", ValidationReason::RtspPortNotPinned },
            { "rtspenc://127.0.0.1:47989", ValidationReason::RtspPortNotPinned },
            { "rtspenc://127.0.0.1:048010", ValidationReason::RtspPortInvalid },
            { "rtspenc://127.0.0.1:4801x", ValidationReason::RtspPortInvalid },
            { "rtspenc://127.0.0.1:48010/", ValidationReason::RtspPathNotAllowed },
            { "rtspenc://127.0.0.1:48010/stream", ValidationReason::RtspPathNotAllowed },
            { "rtspenc://127.0.0.1:48010?x=1", ValidationReason::RtspQueryNotAllowed },
            { "rtspenc://127.0.0.1:48010#f", ValidationReason::RtspFragmentNotAllowed },
            { "rtspenc://a@127.0.0.1:48010", ValidationReason::RtspUserInfoNotAllowed },
            { "rtspenc://127.0.0.1:48010 ", ValidationReason::RtspUrlNotCanonical },
        };
        for (const Case& test : cases) {
            const ValidationResult result =
                ManagedEndpointContext::validateRtspUrl(QString::fromLatin1(test.input));
            QVERIFY2(!result.ok(), test.input);
            QCOMPARE(int(result.reason), int(test.reason));
        }
    }

    void createBindsExactIdentifiers()
    {
        ValidationResult reason;
        const auto context = makeContext(validSpec(), reason);
        QVERIFY2(context.has_value(), qPrintable(reason.detail));
        QVERIFY(reason.ok());
        QVERIFY(reason.detail.isEmpty());

        QCOMPARE(context->apiOrigin(), QStringLiteral("https://kanade.example"));
        QCOMPARE(context->hostId(), kHostId);
        QCOMPARE(context->grantId(), kGrantId);
        QCOMPARE(context->sessionId(), kSessionId);
        QCOMPARE(context->clientInstallationId(), kClientInst);
        QCOMPARE(context->hostInstallationId(), kHostInst);
        QCOMPARE(context->clientKeyVersion(), 1);
        QCOMPARE(context->hostKeyVersion(), 2);
        QCOMPARE(context->runGeneration(), quint64(7));
        QCOMPARE(context->confirmedDeadlineMs(), kNow + 90000);
    }

    void createCanonicalizesOriginAndKeepsEverythingElseBitExact()
    {
        ManagedEndpointSpec spec = validSpec();
        spec.apiOrigin = QStringLiteral("HTTPS://Kanade.Example:443/");
        ValidationResult reason;
        const auto context = makeContext(spec, reason);
        QVERIFY(context.has_value());
        QCOMPARE(context->apiOrigin(), QStringLiteral("https://kanade.example"));
        // Identifier spelling is not normalized: a non-canonical id is rejected,
        // never coerced.
        QCOMPARE(context->hostId(), kHostId);
    }

    void createRejectsEachUnsafeField()
    {
        struct Mutation {
            const char* what;
            void (*apply)(ManagedEndpointSpec&);
            ValidationReason reason;
        };
        const Mutation mutations[] = {
            { "http origin", [](ManagedEndpointSpec& s) {
                  s.apiOrigin = QStringLiteral("http://kanade.example"); },
              ValidationReason::OriginSchemeNotHttps },
            { "origin path", [](ManagedEndpointSpec& s) {
                  s.apiOrigin = QStringLiteral("https://kanade.example/api"); },
              ValidationReason::OriginPathNotAllowed },
            { "bad host id", [](ManagedEndpointSpec& s) {
                  s.hostId = QStringLiteral("not-a-uuid"); },
              ValidationReason::HostIdInvalid },
            { "bad grant id", [](ManagedEndpointSpec& s) { s.grantId.clear(); },
              ValidationReason::GrantIdInvalid },
            { "bad session id", [](ManagedEndpointSpec& s) {
                  s.sessionId = kSessionId.toUpper(); },
              ValidationReason::SessionIdInvalid },
            { "bad client install", [](ManagedEndpointSpec& s) {
                  s.clientInstallationId = QStringLiteral("44444444-4444-4444-b444-44444444444"); },
              ValidationReason::ClientInstallationIdInvalid },
            { "bad host install", [](ManagedEndpointSpec& s) {
                  s.hostInstallationId = QStringLiteral("55555555-5555-3555-8555-555555555555"); },
              ValidationReason::HostInstallationIdInvalid },
            { "same participants", [](ManagedEndpointSpec& s) {
                  s.hostInstallationId = s.clientInstallationId; },
              ValidationReason::ParticipantsNotDistinct },
            { "client key 0", [](ManagedEndpointSpec& s) { s.clientKeyVersion = 0; },
              ValidationReason::KeyVersionInvalid },
            { "host key negative", [](ManagedEndpointSpec& s) { s.hostKeyVersion = -1; },
              ValidationReason::KeyVersionInvalid },
            { "run generation 0", [](ManagedEndpointSpec& s) { s.runGeneration = 0; },
              ValidationReason::RunGenerationInvalid },
            { "deadline at now", [](ManagedEndpointSpec& s) {
                  s.confirmedDeadlineMs = kNow; },
              ValidationReason::LeaseExpired },
            { "deadline in past", [](ManagedEndpointSpec& s) {
                  s.confirmedDeadlineMs = kNow - 1; },
              ValidationReason::LeaseExpired },
            { "deadline beyond cap", [](ManagedEndpointSpec& s) {
                  s.confirmedDeadlineMs = kNow + 90001; },
              ValidationReason::LeaseDeadlineInvalid },
        };
        for (const Mutation& mutation : mutations) {
            ManagedEndpointSpec spec = validSpec();
            mutation.apply(spec);
            ValidationResult reason;
            const auto context = makeContext(spec, reason);
            QVERIFY2(!context.has_value(), mutation.what);
            QCOMPARE(int(reason.reason), int(mutation.reason));
            QVERIFY2(!reason.detail.isEmpty(), mutation.what);
        }
    }

    void createAcceptsCapBoundaryExactly()
    {
        ManagedEndpointSpec spec = validSpec();
        spec.confirmedDeadlineMs = kNow + 1;
        ValidationResult reason;
        QVERIFY(makeContext(spec, reason).has_value());

        spec.confirmedDeadlineMs = kNow + ManagedEndpointContext::kLeaseTtlCapMs;
        QVERIFY(makeContext(spec, reason).has_value());

        // Unusable monotonic instant.
        spec = validSpec();
        QVERIFY(!makeContext(spec, reason, -1).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseClockInvalid));
    }

    void leaseGateIsStrictAndRunBound()
    {
        ValidationResult reason;
        const auto context = makeContext(validSpec(), reason);
        QVERIFY(context.has_value());

        QVERIFY(context->checkLeaseGate(kNow, 7).ok());
        QVERIFY(context->checkLeaseGate(kNow + 1, 7).ok());
        QVERIFY(context->checkLeaseGate(kNow + 89999, 7).ok());

        // At the deadline the lease is already expired.
        QCOMPARE(int(context->checkLeaseGate(kNow + 90000, 7).reason),
                 int(ValidationReason::LeaseExpired));

        // Wall-clock moves backward are not part of this gate at all: only the
        // explicit monotonic instant matters.
        QVERIFY(context->checkLeaseGate(kNow + 100, 7).ok());

        QCOMPARE(int(context->checkLeaseGate(kNow, 6).reason),
                 int(ValidationReason::LeaseStaleRunGeneration));
        QCOMPARE(int(context->checkLeaseGate(kNow, 8).reason),
                 int(ValidationReason::LeaseStaleRunGeneration));
        QCOMPARE(int(context->checkLeaseGate(kNow, 0).reason),
                 int(ValidationReason::RunGenerationInvalid));
        QCOMPARE(int(context->checkLeaseGate(-1, 7).reason),
                 int(ValidationReason::LeaseClockInvalid));
    }

    void renewalRequiresStrictIncreaseAndLiveContext()
    {
        ValidationResult reason;
        const auto context = makeContext(validSpec(), reason);
        QVERIFY(context.has_value());

        // Strictly later: accepted, original untouched.
        const auto renewed = context->renewed(kNow + 120000, kNow + 30000, kSessionId, 7, reason);
        QVERIFY2(renewed.has_value(), qPrintable(reason.detail));
        QVERIFY(reason.ok());
        QCOMPARE(renewed->confirmedDeadlineMs(), kNow + 120000);
        QCOMPARE(renewed->sessionId(), kSessionId);
        QCOMPARE(context->confirmedDeadlineMs(), kNow + 90000);

        // Equal deadline: a replay.  Rejected, gate not moved.
        reason = ValidationResult{};
        QVERIFY(!context->renewed(kNow + 90000, kNow + 100, kSessionId, 7, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseNotExtended));

        // Lower deadline: out-of-order.  Rejected.
        QVERIFY(!context->renewed(kNow + 80000, kNow + 100, kSessionId, 7, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseNotExtended));

        // THE case: the context we renew FROM already elapsed locally.  A late
        // confirmation carrying a perfectly good future deadline must not
        // revive a dead lease.
        reason = ValidationResult{};
        const auto dead = context->renewed(kNow + 200000, kNow + 90000, kSessionId, 7, reason);
        QVERIFY(!dead.has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseExpired));

        // One millisecond before the old deadline is still renewable, as long
        // as the new deadline stays inside the locally honoured span.
        const auto almostDead = context->renewed(kNow + 140000, kNow + 89999,
                                                 kSessionId, 7, reason);
        QVERIFY2(almostDead.has_value(), qPrintable(reason.detail));
        QCOMPARE(almostDead->confirmedDeadlineMs(), kNow + 140000);
    }

    void renewalBoundsSessionRunAndClock()
    {
        ValidationResult reason;
        const auto context = makeContext(validSpec(), reason);
        QVERIFY(context.has_value());

        QVERIFY(!context->renewed(kNow + 120000, kNow, QStringLiteral("deadbeef"), 7,
                                  reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseSessionMismatch));

        QVERIFY(!context->renewed(kNow + 120000, kNow, kSessionId, 6, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseStaleRunGeneration));

        QVERIFY(!context->renewed(kNow + 120000, kNow, kSessionId, 0, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::RunGenerationInvalid));

        QVERIFY(!context->renewed(kNow + 120000, -1, kSessionId, 7, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseClockInvalid));

        // Not in the future.
        QVERIFY(!context->renewed(kNow, kNow, kSessionId, 7, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseExpired));

        // Beyond the locally honoured span.
        QVERIFY(!context->renewed(kNow + 300000, kNow, kSessionId, 7, reason).has_value());
        QCOMPARE(int(reason.reason), int(ValidationReason::LeaseDeadlineInvalid));
    }

    void requestLimitsOfChainedRenewalStayBounded()
    {
        ValidationResult reason;
        ManagedEndpointSpec spec = validSpec();
        spec.confirmedDeadlineMs = kNow + 30000; // start from a short lease
        auto context = makeContext(spec, reason);
        QVERIFY(context.has_value());

        // Each confirmed renewal is bounded by the SAME cap relative to the
        // trusted instant at confirmation; chaining cannot creep past it.
        qint64 now = kNow;
        for (int i = 0; i < 5; ++i) {
            const auto next = context->renewed(now + 90000, now, kSessionId, 7, reason);
            QVERIFY2(next.has_value(), qPrintable(reason.detail));
            QVERIFY(next->confirmedDeadlineMs() - now
                    <= ManagedEndpointContext::kLeaseTtlCapMs);
            now += 30000;
            context = next;
        }

        const qint64 deadline = context->confirmedDeadlineMs();
        QVERIFY(context->checkLeaseGate(deadline - 1, 7).ok());
        QCOMPARE(int(context->checkLeaseGate(deadline, 7).reason),
                 int(ValidationReason::LeaseExpired));
    }

    void reasonNamesAreStableAndNonSecret()
    {
        const ValidationReason all[] = {
            ValidationReason::Ok,
            ValidationReason::OriginEmpty,
            ValidationReason::OriginSchemeNotHttps,
            ValidationReason::LeaseExpired,
            ValidationReason::LeaseStaleRunGeneration,
            ValidationReason::LeaseNotExtended,
        };
        for (const ValidationReason reason : all) {
            const QString name = Kanade::reasonToString(reason);
            QVERIFY(!name.isEmpty());
            QVERIFY(!name.contains(QLatin1Char(' ')));
        }
        QCOMPARE(Kanade::reasonToString(ValidationReason::LeaseExpired),
                 QStringLiteral("lease_expired"));
        QCOMPARE(Kanade::reasonToString(ValidationReason::LeaseNotExtended),
                 QStringLiteral("lease_not_extended"));
    }

    // --- Managed native gate / lease guard --------------------------------

    void leaseGuardRequiresLiveBoundedDeadline()
    {
        Kanade::NativeResult why;

        // Not a canonical uuid4.
        QVERIFY(!Kanade::LiveLeaseGuard::create(QStringLiteral("not-a-uuid"), 1, kNow + 1000, kNow,
                                               90000, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::ContextInvalid));

        // Zero generation.
        QVERIFY(!Kanade::LiveLeaseGuard::create(kSessionId, 0, kNow + 1000, kNow, 90000, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::RunGenerationInvalid));

        // Deadline at/behind now is already expired.
        QVERIFY(!Kanade::LiveLeaseGuard::create(kSessionId, 1, kNow, kNow, 90000, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseExpired));

        // Beyond the cap.
        QVERIFY(!Kanade::LiveLeaseGuard::create(kSessionId, 1, kNow + 90001, kNow, 90000, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseDeadlineInvalid));

        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 1, kNow + 90000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);
        QVERIFY(why.ok());
        QVERIFY(guard->isLive(kNow));
        // At the deadline itself the lease is gone.
        QVERIFY(!guard->isLive(kNow + 90000));
    }

    void leaseGuardFromRemainingIsOriginIndependentAndClamped()
    {
        Kanade::NativeResult why;

        // Zero or negative remaining time is already expired.
        QVERIFY(!Kanade::LiveLeaseGuard::createFromRemaining(kSessionId, 1, 0, 90000, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseExpired));
        QVERIFY(!Kanade::LiveLeaseGuard::createFromRemaining(kSessionId, 1, -5, 90000, &why));

        // A normal interval yields a live guard with a bounded future deadline.
        auto guard =
            Kanade::LiveLeaseGuard::createFromRemaining(kSessionId, 3, 30000, 90000, &why);
        QVERIFY(guard != nullptr);
        QVERIFY(why.ok());
        const Kanade::LiveLeaseSnapshot snapshot = guard->snapshot(Kanade::managedMonotonicNowMs());
        QVERIFY(snapshot.live);
        QCOMPARE(snapshot.generation, quint64(3));
        QCOMPARE(snapshot.sessionId, kSessionId);
        const qint64 remaining =
            snapshot.deadlineMs - Kanade::managedMonotonicNowMs();
        // Never longer than requested, and never beyond the honoured cap.
        QVERIFY(remaining <= 30000);
        QVERIFY(remaining > 25000);

        // An over-long interval is clamped, never trusted.
        auto clamped =
            Kanade::LiveLeaseGuard::createFromRemaining(kSessionId, 3, 10 * 90000, 90000, &why);
        QVERIFY(clamped != nullptr);
        const Kanade::LiveLeaseSnapshot clampedSnapshot =
            clamped->snapshot(Kanade::managedMonotonicNowMs());
        QVERIFY(clampedSnapshot.live);
        QVERIFY(clampedSnapshot.deadlineMs - Kanade::managedMonotonicNowMs() <= 90000);
    }

    void leaseExtensionIsForwardOnlyAndLatchesDeath()
    {
        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 10000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);

        // Wrong generation / session.
        QVERIFY(!guard->extend(kNow, kNow + 20000, 8, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseGenerationMismatch));
        QVERIFY(!guard->extend(kNow, kNow + 20000, 7, kHostId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseSessionMismatch));

        // Forward extension works; equal or lower does not move the gate.
        QVERIFY(guard->extend(kNow, kNow + 20000, 7, kSessionId, &why));
        const qint64 afterFirst = guard->snapshot(kNow).deadlineMs;
        QCOMPARE(afterFirst, kNow + 20000);
        QVERIFY(!guard->extend(kNow, kNow + 20000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseNotExtended));
        QCOMPARE(guard->snapshot(kNow).deadlineMs, afterFirst);

        // A late confirmation after the deadline cannot revive it, and the
        // guard records the expiry permanently.
        QVERIFY(!guard->extend(kNow + 20000, kNow + 40000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseExpired));
        QCOMPARE(int(guard->deadReason()), int(Kanade::NativeReason::LeaseExpired));
        QVERIFY(!guard->isLive(kNow));

        // Revocation is permanent too.
        auto other = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 10000, kNow, 90000, &why);
        QVERIFY(other != nullptr);
        const quint64 before = other->epoch();
        other->revoke(Kanade::NativeReason::LeaseRevoked);
        QVERIFY(other->epoch() > before);
        QVERIFY(!other->extend(kNow, kNow + 20000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseRevoked));
    }

    void gateRefusesWithoutVerifiedBinding()
    {
        ValidationResult contextReason;
        const auto context = makeContext(validSpec(), contextReason);
        QVERIFY(context.has_value());

        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);

        Kanade::ManagedNativeGate gate;

        // No binding at all: nothing may become callable.
        Kanade::RuntimeBinding unverified;
        unverified.sessionId = kSessionId;
        unverified.runGeneration = 7;
        unverified.ipcVerified = false;
        QCOMPARE(int(gate.arm(*context, guard, unverified, kNow).reason),
                 int(Kanade::NativeReason::RuntimeBindingUnverified));
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Idle));
        QVERIFY(!gate.permits(Kanade::NativeCall::ServerInfo, kNow, 7).ok());
        QVERIFY(!gate.permits(Kanade::NativeCall::Stream, kNow, 7).ok());

        // Verified but for another session/generation.
        Kanade::RuntimeBinding binding = unverified;
        binding.ipcVerified = true;
        binding.sessionId = kHostId;
        QCOMPARE(int(gate.arm(*context, guard, binding, kNow).reason),
                 int(Kanade::NativeReason::RuntimeBindingSessionMismatch));
        binding.sessionId = kSessionId;
        binding.runGeneration = 8;
        QCOMPARE(int(gate.arm(*context, guard, binding, kNow).reason),
                 int(Kanade::NativeReason::RuntimeBindingGenerationMismatch));
    }

    void gateBindingEnablesDiscoveryButNotStreaming()
    {
        ValidationResult contextReason;
        const auto context = makeContext(validSpec(), contextReason);
        QVERIFY(context.has_value());

        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.transportId = QStringLiteral("t1");
        binding.ipcSequence = 5;
        binding.ipcVerified = true;

        Kanade::ManagedNativeGate gate;
        QVERIFY(gate.arm(*context, guard, binding, kNow).ok());
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Bound));

        // Discovery and pairing are allowed once the runtime owns the listeners.
        QVERIFY(gate.permits(Kanade::NativeCall::ServerInfo, kNow, 7).ok());
        QVERIFY(gate.permits(Kanade::NativeCall::AppList, kNow, 7).ok());
        QVERIFY(gate.permits(Kanade::NativeCall::PairCert, kNow, 7).ok());
        QVERIFY(gate.permits(Kanade::NativeCall::Pair, kNow, 7).ok());
        QVERIFY(gate.permits(Kanade::NativeCall::Quit, kNow, 7).ok());

        // Launch/resume/stream stay closed until a verified ready proof AND the
        // common-c pre-send validator exist.
        QVERIFY(!gate.permits(Kanade::NativeCall::Launch, kNow, 7).ok());
        QVERIFY(!gate.permits(Kanade::NativeCall::Resume, kNow, 7).ok());
        QVERIFY(!gate.canOpenManagedStream(kNow));

        // Wrong generation is refused everywhere.
        QVERIFY(!gate.permits(Kanade::NativeCall::ServerInfo, kNow, 8).ok());

        // Ready proof for the wrong transport is refused.
        Kanade::ReadyProof proof;
        proof.sessionId = kSessionId;
        proof.runGeneration = 7;
        proof.transportId = QStringLiteral("t2");
        proof.ipcSequence = 6;
        proof.ipcVerified = true;
        QCOMPARE(int(gate.markReady(proof, kNow).reason),
                 int(Kanade::NativeReason::ReadyProofTransportMismatch));

        // Unverified proof is refused outright.
        proof.transportId = QStringLiteral("t1");
        proof.ipcVerified = false;
        QCOMPARE(int(gate.markReady(proof, kNow).reason),
                 int(Kanade::NativeReason::ReadyProofUnverified));

        // A proof that would extend the lease is a protocol error.
        proof.ipcVerified = true;
        proof.leaseDeadlineMs = kNow + 90000;
        QCOMPARE(int(gate.markReady(proof, kNow).reason),
                 int(Kanade::NativeReason::ReadyProofDeadlineInvalid));

        // Correct proof: ready, but launch stays closed without the hook.
        proof.leaseDeadlineMs = -1;
        QVERIFY(gate.markReady(proof, kNow).ok());
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Ready));
        QCOMPARE(int(gate.permits(Kanade::NativeCall::Launch, kNow, 7).reason),
                 Kanade::ManagedNativeGate::presendValidatorAvailable()
                     ? int(Kanade::NativeReason::Ok)
                     : int(Kanade::NativeReason::PresendHookUnavailable));
        QCOMPARE(gate.canOpenManagedStream(kNow),
                 Kanade::ManagedNativeGate::presendValidatorAvailable());

        // Replayed ready proof.
        proof.ipcSequence = 5;
        QCOMPARE(int(gate.markReady(proof, kNow).reason),
                 int(Kanade::NativeReason::NotArmed)); // already Ready, not Bound
    }

    void gateDeathIsTerminalAndStopsEverything()
    {
        ValidationResult contextReason;
        const auto context = makeContext(validSpec(), contextReason);
        QVERIFY(context.has_value());

        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.ipcVerified = true;

        Kanade::ManagedNativeGate gate;
        QVERIFY(gate.arm(*context, guard, binding, kNow).ok());
        QVERIFY(gate.permits(Kanade::NativeCall::ServerInfo, kNow, 7).ok());

        gate.revoke(Kanade::NativeReason::LeaseRevoked);
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Dead));
        // The shared guard is dead too, so the runtime's own renewals fail.
        QVERIFY(!guard->isLive(kNow));
        QCOMPARE(int(guard->deadReason()), int(Kanade::NativeReason::LeaseRevoked));

        for (const Kanade::NativeCall call : { Kanade::NativeCall::ServerInfo,
                                               Kanade::NativeCall::AppList,
                                               Kanade::NativeCall::Pair,
                                               Kanade::NativeCall::Launch,
                                               Kanade::NativeCall::Quit }) {
            QCOMPARE(int(gate.permits(call, kNow, 7).reason),
                     int(Kanade::NativeReason::Dead));
        }
        // No revival path exists.
        QVERIFY(!gate.arm(*context, guard, binding, kNow).ok());
        QVERIFY(!gate.beginStop(kNow, &why));
        QVERIFY(!gate.canOpenManagedStream(kNow));
    }

    void gateStopAllowsOnlyCleanupThenDies()
    {
        ValidationResult contextReason;
        const auto context = makeContext(validSpec(), contextReason);
        QVERIFY(context.has_value());

        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.ipcVerified = true;

        Kanade::ManagedNativeGate gate;
        QVERIFY(gate.arm(*context, guard, binding, kNow).ok());

        QVERIFY(gate.beginStop(kNow, &why));
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Stopping));
        QVERIFY(gate.permits(Kanade::NativeCall::Quit, kNow, 7).ok());
        QVERIFY(!gate.permits(Kanade::NativeCall::ServerInfo, kNow, 7).ok());
        QVERIFY(!gate.permits(Kanade::NativeCall::Launch, kNow, 7).ok());
        QVERIFY(!gate.beginStop(kNow, &why));

        gate.finishStop();
        QCOMPARE(int(gate.state()), int(Kanade::ManagedNativeGate::State::Dead));
        QVERIFY(!gate.permits(Kanade::NativeCall::Quit, kNow, 7).ok());
    }

    void gateRefusesExpiredLeaseAtEveryStep()
    {
        ValidationResult contextReason;
        const auto context = makeContext(validSpec(), contextReason);
        QVERIFY(context.has_value());
        QCOMPARE(context->confirmedDeadlineMs(), kNow + 90000);

        Kanade::NativeResult why;
        auto guard =
            Kanade::LiveLeaseGuard::create(kSessionId, 7, context->confirmedDeadlineMs(), kNow,
                                         90000, &why);
        QVERIFY(guard != nullptr);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.ipcVerified = true;

        Kanade::ManagedNativeGate gate;
        QVERIFY(gate.arm(*context, guard, binding, kNow).ok());

        const qint64 expired = context->confirmedDeadlineMs();
        for (const Kanade::NativeCall call : { Kanade::NativeCall::ServerInfo,
                                               Kanade::NativeCall::Launch,
                                               Kanade::NativeCall::Quit }) {
            QVERIFY(!gate.permits(call, expired, 7).ok());
        }
        QVERIFY(!gate.canOpenManagedStream(expired));
        // Arming with an already-dead guard must dead-end the gate.
        Kanade::ManagedNativeGate late;
        QVERIFY(!late.arm(*context, guard, binding, expired).ok());
        QCOMPARE(int(late.state()), int(Kanade::ManagedNativeGate::State::Dead));
    }

    void managedEndpointAndPacketPolicyAreStrict()
    {
        QCOMPARE(Kanade::managedPacketSize(), 1392);

        // The UDP group is ordered, not just a set: foundation-sunshine
        // src/stream.h:32-34 maps VIDEO=9, CONTROL=10, AUDIO=11 over 47989.
        QCOMPARE(Kanade::kManagedVideoUdpPort, quint16(47998));
        QCOMPARE(Kanade::kManagedControlUdpPort, quint16(47999));
        QCOMPARE(Kanade::kManagedAudioUdpPort, quint16(48000));
        Kanade::NativeResult why;
        QVERIFY(Kanade::checkManagedPacketSize(0, &why));
        QVERIFY(Kanade::checkManagedPacketSize(1392, &why));
        // No silent 1024 downgrade is ever implied by this layer.
        QVERIFY(!Kanade::checkManagedPacketSize(1024, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::PacketSizeNotSupported));
        QVERIFY(!Kanade::checkManagedPacketSize(1436, &why));

        QVERIFY(Kanade::isPinnedManagedEndpoint(QStringLiteral("127.0.0.1"), 47989));
        QVERIFY(Kanade::isPinnedManagedEndpoint(QStringLiteral("127.0.0.1"), 47984));
        QVERIFY(!Kanade::isPinnedManagedEndpoint(QStringLiteral("127.0.0.1"), 47990));
        QVERIFY(!Kanade::isPinnedManagedEndpoint(QStringLiteral("127.0.0.1"), 48001));
        QVERIFY(!Kanade::isPinnedManagedEndpoint(QStringLiteral("localhost"), 47989));
        QVERIFY(!Kanade::isPinnedManagedEndpoint(QStringLiteral("::1"), 47989));
        QVERIFY(!Kanade::isPinnedManagedEndpoint(QStringLiteral("0.0.0.0"), 47989));

        const Kanade::NativeEndpoint endpoint = Kanade::pinnedManagedEndpoint();
        QCOMPARE(endpoint.host, QStringLiteral("127.0.0.1"));
        QCOMPARE(endpoint.httpPort, quint16(47989));
        QCOMPARE(endpoint.httpsPort, quint16(47984));
    }

    // --- 1 s watchdog: a repeated confirmed deadline is NOT a failure -------
    //
    // P0 regression.  onLeaseTick() fires every second and hands over
    // KanadeSession::leaseDeadlineMonotonicMs(), which only advances when the
    // server confirms a later lease (~every 30 s).  The old controller path
    // treated that repeated deadline as a failed forward extension
    // (LeaseNotExtended), called failNow() and revoked the whole run one second
    // after it went live.
    //
    // These cases drive the REAL production decision, LiveLeaseGuard::observe()
    // via ManagedNativeController::tickLease(), not a reimplementation of it.
    void leaseObserveRepeatedDeadlineIsANoOp()
    {
        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);
        const quint64 epochBefore = guard->epoch();

        // Thirty ticks at the 1 s cadence against a 30 s confirmation: all
        // succeed, nothing moves, and the guard stays live and healthy.
        for (int i = 0; i < 30; ++i) {
            why = Kanade::NativeResult{};
            QVERIFY2(guard->observe(kNow + i * 1000, kNow + 60000, 7, kSessionId, &why),
                     qPrintable(why.detail));
            QVERIFY(why.ok());
            QVERIFY(why.detail.isEmpty());
            QCOMPARE(guard->epoch(), epochBefore);
            QCOMPARE(guard->snapshot(kNow + i * 1000).deadlineMs, kNow + 60000);
            QVERIFY(guard->isLive(kNow + i * 1000));
            QCOMPARE(int(guard->deadReason()), int(Kanade::NativeReason::Ok));
        }
    }

    void leaseObserveExtendsExactlyOnce()
    {
        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);
        const quint64 epochBefore = guard->epoch();

        // A strictly later confirmed deadline is the one case that moves.
        QVERIFY2(guard->observe(kNow + 30000, kNow + 90000, 7, kSessionId, &why),
                 qPrintable(why.detail));
        QVERIFY(guard->epoch() > epochBefore);
        QCOMPARE(guard->snapshot(kNow + 30000).deadlineMs, kNow + 90000);

        // Re-observing that same deadline is a no-op again, not a second move.
        const quint64 afterExtend = guard->epoch();
        QVERIFY(guard->observe(kNow + 31000, kNow + 90000, 7, kSessionId, &why));
        QCOMPARE(guard->epoch(), afterExtend);
        QCOMPARE(guard->snapshot(kNow + 31000).deadlineMs, kNow + 90000);

        // And the strict extend() primitive still refuses the repeat.
        QVERIFY(!guard->extend(kNow + 31000, kNow + 90000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseNotExtended));
    }

    void leaseObserveStillFailsClosed()
    {
        Kanade::NativeResult why;

        // A LOWER confirmed deadline is never a successful observation: it must
        // not shorten the live lease (the review's explicit requirement).
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(guard != nullptr);
        const quint64 epochBefore = guard->epoch();
        why = Kanade::NativeResult{};
        QVERIFY(!guard->observe(kNow, kNow + 30000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseNotExtended));
        QCOMPARE(guard->epoch(), epochBefore);
        QCOMPARE(guard->snapshot(kNow).deadlineMs, kNow + 60000);
        QVERIFY(guard->isLive(kNow));

        // Wrong run generation / session is refused even when the deadline is
        // unchanged, so a stale lane can never be told "all good".
        why = Kanade::NativeResult{};
        QVERIFY(!guard->observe(kNow, kNow + 60000, 8, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseGenerationMismatch));
        why = Kanade::NativeResult{};
        QVERIFY(!guard->observe(kNow, kNow + 60000, 7, kHostId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseSessionMismatch));

        // A strictly later confirmation beyond the locally honoured span is a
        // protocol error, not an extension.
        why = Kanade::NativeResult{};
        QVERIFY(!guard->observe(kNow, kNow + 60000 + 90001, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseDeadlineInvalid));
        QCOMPARE(guard->epoch(), epochBefore);
        QVERIFY(guard->isLive(kNow));

        // Elapsed locally: latched, and no later confirmation can revive it.
        auto elapsed = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 5000, kNow, 90000, &why);
        QVERIFY(elapsed != nullptr);
        why = Kanade::NativeResult{};
        QVERIFY(!elapsed->observe(kNow + 5000, kNow + 80000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseExpired));
        QCOMPARE(int(elapsed->deadReason()), int(Kanade::NativeReason::LeaseExpired));
        QVERIFY(!elapsed->observe(kNow, kNow + 90000, 7, kSessionId, &why));
        QVERIFY(!elapsed->isLive(kNow));

        // Revoked by the owner: a later confirmation can never reopen it.
        auto revoked = Kanade::LiveLeaseGuard::create(kSessionId, 7, kNow + 60000, kNow, 90000, &why);
        QVERIFY(revoked != nullptr);
        revoked->revoke(Kanade::NativeReason::LeaseRevoked);
        why = Kanade::NativeResult{};
        QVERIFY(!revoked->observe(kNow, kNow + 90000, 7, kSessionId, &why));
        QCOMPARE(int(why.reason), int(Kanade::NativeReason::LeaseRevoked));
        QVERIFY(!revoked->isLive(kNow));
    }

    void controllerTickLeaseKeepsRepeatedDeadlineAlive()
    {
        // The production entry point onLeaseTick() calls, on the production
        // clock, with the gate armed.  A repeated confirmed deadline must leave
        // the run Bound and live; the old renewLease() call revoked it here.
        const qint64 start = Kanade::managedMonotonicNowMs();
        ManagedEndpointSpec spec = validSpec();
        spec.confirmedDeadlineMs = start + 60000;
        ValidationResult contextReason;
        const auto context = makeContext(spec, contextReason, start);
        QVERIFY2(context.has_value(), qPrintable(contextReason.detail));

        Kanade::ManagedNativeController controller;
        QVERIFY(controller.begin(*context));
        const auto guard = controller.leaseGuard();
        QVERIFY(guard != nullptr);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.transportId = QStringLiteral("tick-transport");
        binding.ipcSequence = 1;
        binding.ipcVerified = true;
        QVERIFY2(controller.runtimeBound(binding), qPrintable(controller.failureReason()));
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Bound));

        const qint64 heldDeadline = guard->snapshot(Kanade::managedMonotonicNowMs()).deadlineMs;
        QCOMPARE(heldDeadline, context->confirmedDeadlineMs());
        const quint64 epochBefore = guard->epoch();

        QString reason = QStringLiteral("sentinel");
        for (int i = 0; i < 30; ++i) {
            QVERIFY2(controller.tickLease(heldDeadline, &reason), qPrintable(reason));
            QVERIFY(reason.isEmpty());
            QCOMPARE(int(guard->deadReason()), int(Kanade::NativeReason::Ok));
            QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Bound));
        }
        QCOMPARE(guard->epoch(), epochBefore);
        QCOMPARE(guard->snapshot(Kanade::managedMonotonicNowMs()).deadlineMs, heldDeadline);

        // One real server confirmation: exactly one move, run still Bound.
        const qint64 extendedDeadline = heldDeadline + 20000;
        QVERIFY2(controller.tickLease(extendedDeadline, &reason), qPrintable(reason));
        QVERIFY(guard->epoch() > epochBefore);
        QCOMPARE(guard->snapshot(Kanade::managedMonotonicNowMs()).deadlineMs, extendedDeadline);
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Bound));
        const quint64 afterExtend = guard->epoch();
        QVERIFY(controller.tickLease(extendedDeadline, &reason));
        QCOMPARE(guard->epoch(), afterExtend);

        // An over-cap confirmation fails the run closed instead of being used.
        QString overCapReason;
        QVERIFY(!controller.tickLease(extendedDeadline
                                          + 2 * ManagedEndpointContext::kLeaseTtlCapMs,
                                      &overCapReason));
        QVERIFY(!overCapReason.isEmpty());
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Failed));
        QVERIFY(!guard->isLive(Kanade::managedMonotonicNowMs()));

        // A tick after the terminal state can never revive run or lease.
        QVERIFY(!controller.tickLease(heldDeadline, &overCapReason));
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Failed));
        QVERIFY(!guard->isLive(Kanade::managedMonotonicNowMs()));
    }

    void controllerTickBeforeArmKeepsContextInStep()
    {
        // A server confirmation lands between begin() and runtimeBound().  The
        // gate refuses a lease ahead of the context it arms with, so arming must
        // first bring the context forward to the lease's confirmed deadline.
        // Otherwise a perfectly healthy run would fail to arm.
        const qint64 start = Kanade::managedMonotonicNowMs();
        ManagedEndpointSpec spec = validSpec();
        spec.confirmedDeadlineMs = start + 60000;
        ValidationResult contextReason;
        const auto context = makeContext(spec, contextReason, start);
        QVERIFY2(context.has_value(), qPrintable(contextReason.detail));

        Kanade::ManagedNativeController controller;
        QVERIFY(controller.begin(*context));
        const auto guard = controller.leaseGuard();
        QVERIFY(guard != nullptr);

        // One real confirmation, as the 1 s tick would apply it.
        QString reason;
        const qint64 renewed = start + 85000;
        QVERIFY2(controller.tickLease(renewed, &reason), qPrintable(reason));
        QCOMPARE(guard->snapshot(Kanade::managedMonotonicNowMs()).deadlineMs, renewed);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.transportId = QStringLiteral("prearm-transport");
        binding.ipcSequence = 1;
        binding.leaseDeadlineMs = renewed;
        binding.ipcVerified = true;
        QVERIFY2(controller.runtimeBound(binding), qPrintable(controller.failureReason()));
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Bound));
    }

    void controllerArmRefusesExpiredLease()
    {
        // Same window, but the lease elapsed locally before the binding arrived:
        // arming must fail closed rather than arm a dead run.
        const qint64 start = Kanade::managedMonotonicNowMs();
        ManagedEndpointSpec spec = validSpec();
        spec.confirmedDeadlineMs = start + 60000;
        ValidationResult contextReason;
        const auto context = makeContext(spec, contextReason, start);
        QVERIFY(context.has_value());

        Kanade::ManagedNativeController controller;
        QVERIFY(controller.begin(*context));
        const auto guard = controller.leaseGuard();
        QVERIFY(guard != nullptr);

        guard->revoke(Kanade::NativeReason::LeaseRevoked);

        Kanade::RuntimeBinding binding;
        binding.sessionId = kSessionId;
        binding.runGeneration = 7;
        binding.ipcSequence = 1;
        binding.ipcVerified = true;
        QVERIFY(!controller.runtimeBound(binding));
        QCOMPARE(int(controller.state()), int(Kanade::ManagedNativeController::State::Failed));
        QVERIFY(!guard->isLive(Kanade::managedMonotonicNowMs()));
    }

    void portPolicyValidatorFailsClosed()
    {
        // No context at all: refuse (isLive == false).
        QVERIFY(!Kanade::managedPortIsLive(nullptr));

        Kanade::ManagedPortPolicyBridge empty;
        QVERIFY(!Kanade::managedPortIsLive(&empty));

        // The callback reads the production monotonic clock (system uptime
        // on Windows), so its guard must use that clock, not kNow.
        const qint64 now = Kanade::managedMonotonicNowMs();
        Kanade::NativeResult why;
        auto guard = Kanade::LiveLeaseGuard::create(kSessionId, 7, now + 60000, now, 90000, &why);
        QVERIFY(guard != nullptr);

        Kanade::ManagedPortPolicyBridge bridge;
        bridge.lease = guard;
        bridge.runGeneration = 7;
        bridge.sessionId = kSessionId;

        // Live lease for this generation/session: permitted (the ABI callback is
        // port-agnostic; the three fixed ports live in the policy struct).
        QVERIFY(Kanade::managedPortIsLive(&bridge));

        // Wrong generation refuses.
        bridge.runGeneration = 8;
        QVERIFY(!Kanade::managedPortIsLive(&bridge));
        bridge.runGeneration = 7;

        // Revocation stops the very next send.
        guard->revoke(Kanade::NativeReason::LeaseRevoked);
        QVERIFY(!Kanade::managedPortIsLive(&bridge));

        // Lease expiry alone (no revoke) also refuses.
        const qint64 freshNow = Kanade::managedMonotonicNowMs();
        auto expiring =
            Kanade::LiveLeaseGuard::create(kSessionId, 7, freshNow + 1000, freshNow, 90000, &why);
        QVERIFY(expiring != nullptr);
        Kanade::ManagedPortPolicyBridge fresh;
        fresh.lease = expiring;
        fresh.runGeneration = 7;
        fresh.sessionId = kSessionId;
        QVERIFY(Kanade::managedPortIsLive(&fresh));
        QTRY_VERIFY_WITH_TIMEOUT(!Kanade::managedPortIsLive(&fresh), 5000);
    }

    void nativeReasonNamesAreStableAndNonSecret()
    {
        const Kanade::NativeReason all[] = {
            Kanade::NativeReason::Ok,
            Kanade::NativeReason::ContextInvalid,
            Kanade::NativeReason::PacketSizeNotSupported,
            Kanade::NativeReason::NotArmed,
            Kanade::NativeReason::NotReady,
            Kanade::NativeReason::Dead,
            Kanade::NativeReason::PresendHookUnavailable,
            Kanade::NativeReason::LeaseExpired,
            Kanade::NativeReason::LeaseGenerationMismatch,
            Kanade::NativeReason::ReadyProofUnverified,
            Kanade::NativeReason::ReadyProofDeadlineInvalid,
            Kanade::NativeReason::RuntimeBindingUnverified,
        };
        for (const Kanade::NativeReason reason : all) {
            const QString name = Kanade::nativeReasonToString(reason);
            QVERIFY(!name.isEmpty());
            QVERIFY(!name.contains(QLatin1Char(' ')));
        }
        QCOMPARE(Kanade::nativeReasonToString(Kanade::NativeReason::PresendHookUnavailable),
                 QStringLiteral("presend_hook_unavailable"));
        QCOMPARE(Kanade::nativeReasonToString(Kanade::NativeReason::LeaseExpired),
                 QStringLiteral("lease_expired"));
    }
};

QTEST_GUILESS_MAIN(KanadeManagedEndpointTest)
#include "main.moc"
