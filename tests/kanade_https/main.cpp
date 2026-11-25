// kanade_https: real-HTTPS exercise of the Kanade client control plane.
//
// CI-ONLY lane.  It starts an in-process Kanade control-plane mock that speaks
// REAL TLS over 127.0.0.1 on a kernel-assigned port, using certificates
// generated at RUN TIME into memory (tests/kanade_https/testpki.cpp).  No PEM
// file, private key or certificate is checked in, written to disk, or installed
// into the OS trust store; the client under test receives only the synthetic CA
// through an injected QSslConfiguration, and certificate/hostname verification
// stays ON (never VerifyNone on the client, never ignoreSslErrors()).
//
// Nothing here contacts a real account, host, Kanade service or the OS trust
// store.  The only files written are the sealed identities under the scratch
// root named by KANADE_DPAPI_TEST_ROOT, which this lane deletes afterwards.
//
// Windows storage: the DPAPI + private-DACL store is compiled into Windows
// desktop builds by default, and this lane uses it.  The store refuses the
// system volume and any non-fixed volume, so the runner MUST provide
//     KANADE_DPAPI_TEST_ROOT=<absolute path on a fixed non-system volume>
// (the CI job checks the volume and creates the directory).  A missing or
// unusable value fails this lane loudly instead of skipping the real login
// cases: an unverified HTTPS path is not a pass.
//
// What this proves (product sources compiled directly, not reimplemented):
//   1. KanadeApi completes a real HTTPS request only when the chain validates
//      under the injected CA AND the hostname matches.  An untrusted chain and a
//      trusted-but-wrong-host certificate both fail closed as ErrorKind::Tls.
//   2. Redirects are never followed (3xx -> ErrorKind::Redirect, one request).
//   3. Tokens: adopt -> authenticated call -> forced 401 token_expired -> exactly
//      one single-flight refresh -> one retry; a failed refresh clears tokens,
//      emits authenticationLost and never re-sends the old refresh token.
//   4. Logout is local-first; the best-effort request carries the captured
//      bearer; a late reply cannot clear newer credentials.
//   5. abortAll() delivers Cancelled and no earlier completion fires later.
//   6. Timeout and body-size bounds fail closed.
//   7. KanadeController, over the same mock: login, /auth/me verification, a real
//      Ed25519 enrollment the mock VERIFIES, the device-token exchange, the
//      device list, both pairing paths, grant revocation, identity reuse without
//      re-enrolling, and local-first sign-out.

#include "backend/kanade/kanadeapi.h"
#include "backend/kanade/kanadecontroller.h"
#include "backend/kanade/kanadeidentity.h"

#include "mockkanadeserver.h"
#include "testpki.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSsl>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QUrl>
#include <QVariantMap>
#include <QtTest>

namespace {

const QString kAccountLogin = QStringLiteral("synthetic.user@kanade.invalid");
const QString kPassword = QStringLiteral("correct horse battery staple");
const QString kPairCode = QStringLiteral("ABCD-EFGH");

// Client configuration that trusts ONLY the supplied synthetic CA.  Replacing the
// CA list removes the system store from this configuration entirely, and the
// verify mode stays VerifyPeer: a passing handshake can only come from the
// fixture, and a failing one can only be a real verification failure.
QSslConfiguration trustingOnly(const QSslCertificate& authority)
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
    configuration.setCaCertificates({authority});
    configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    return configuration;
}

// The product's own funnel, applied to a fixture URL: proves the fixture origin
// is in the exact canonical shape KanadeApi::setOrigin accepts.
QUrl canonicalOrigin(const QUrl& url)
{
    QUrl canonical;
    if (!KanadeApi::normalizeOrigin(url.toString(QUrl::FullyEncoded), canonical)) {
        return QUrl();
    }
    return canonical;
}

bool setOriginFromServer(KanadeApi& api, const MockKanadeServer& server)
{
    const QUrl canonical = canonicalOrigin(server.origin());
    return canonical.isValid() && api.setOrigin(canonical);
}

template <typename Predicate>
bool waitUntil(Predicate predicate, int timeoutMs = 15000)
{
    QElapsedTimer timer;
    timer.start();
    while (!predicate() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    return predicate();
}

struct SyncCall {
    bool done = false;
    KanadeApi::Result result;

    KanadeApi::Completion completion()
    {
        return [this](const KanadeApi::Result& value) {
            result = value;
            done = true;
        };
    }
    bool wait(int timeoutMs = 15000) { return waitUntil([this]() { return done; }, timeoutMs); }
};

// Synthetic token pair with the exact opaque shapes KanadeApi accepts.  Used only
// where the server side is not exercised (origin/token-state unit properties).
QJsonObject syntheticTokens(const QString& accessSuffix, const QString& refreshSuffix)
{
    return QJsonObject{
        {QStringLiteral("token_type"), QStringLiteral("Bearer")},
        {QStringLiteral("access_token"),
         QStringLiteral("kat_") + QString(43 - accessSuffix.size(), QLatin1Char('A'))
             + accessSuffix},
        {QStringLiteral("refresh_token"),
         QStringLiteral("krt_") + QString(64 - refreshSuffix.size(), QLatin1Char('B'))
             + refreshSuffix},
    };
}

int kindOf(const KanadeApi::Result& result)
{
    return static_cast<int>(result.kind);
}

// A unique, NOT-yet-created directory directly under the approved root.
//
// The store refuses to re-ACL a pre-existing directory (only a root it created
// itself receives the private DACL), so the test hands it a fresh leaf and lets
// the store create it.  The leaf is removed on destruction; because it is a
// single path component, the store's own ancestor creation has nothing extra to
// leave behind.
class ScratchRoot {
public:
    explicit ScratchRoot(const QString& approvedRoot, const QString& label)
    {
        if (approvedRoot.isEmpty()) {
            return;
        }
        for (int attempt = 0; attempt < 64; ++attempt) {
            const QString candidate =
                approvedRoot + QLatin1Char('/') + label + QLatin1Char('-')
                + QString::number(QCoreApplication::applicationPid()) + QLatin1Char('-')
                + QStringLiteral("%1").arg(QRandomGenerator::global()->generate(), 8, 16,
                                           QLatin1Char('0'));
            if (!QDir(candidate).exists()) {
                m_path = QDir::cleanPath(candidate);
                return;
            }
        }
    }

    ~ScratchRoot()
    {
        if (!m_path.isEmpty()) {
            QDir(m_path).removeRecursively();
        }
    }

    bool valid() const { return !m_path.isEmpty(); }
    QString path() const { return m_path; }

private:
    QString m_path;
};

} // namespace

class KanadeHttpsTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();

    // KanadeApi: transport hardening over real TLS.
    void apiCompletesLoginOverVerifiedTls();
    void apiRejectsUntrustedCertificate();
    void apiRejectsTrustedCertificateForWrongHost();
    void apiNeverFollowsRedirect();
    void apiRefusesCrossOriginSwapWithLiveTokens();

    // KanadeApi: auth / token transitions.
    void apiTreatsMissingTokenAsUnauthorized();
    void apiRefreshesOnceThenRetries();
    void apiFailsClosedWhenRefreshFails();
    void apiAbortsOutstandingRequest();
    void apiTimesOutSlowReply();
    void apiBoundsOversizedBody();

    // KanadeApi: sign-out semantics.
    void apiLogoutIsLocalFirst();
    void apiLateLogoutReplyCannotClearNewerTokens();

    // KanadeController over the same real HTTPS mock.
    void controllerRejectsUntrustedCertificate();
    void controllerMapsRedirectToOriginMismatch();
    void controllerRunsFullDeviceSessionAndPasswordPairing();
    void controllerReusesPersistedIdentityAndConfirmsPairing();
    void controllerDropsLateLoginReplyAfterLogout();

private:
    // The approved scratch root from KANADE_DPAPI_TEST_ROOT.  Empty means the
    // runner is misconfigured and every controller case fails (never skips).
    QString m_approvedRoot;
    TestPki::Material m_pki;
};

void KanadeHttpsTest::initTestCase()
{
    // This lane's whole point is the REAL Windows online path, so an opt-out
    // build must be a hard error rather than a set of silently unsupported
    // controllers.
#ifdef KANADE_DISABLE_WIN32_IDENTITY
    QFAIL("kanade_https must not be built with KANADE_DISABLE_WIN32_IDENTITY: the lane "
          "exists to exercise the real DPAPI identity store");
#endif

    // This lane plays a TLS SERVER, which Qt's Schannel backend cannot do.  Pick
    // the OpenSSL backend explicitly and BEFORE any QSslSocket is constructed,
    // because backend selection is only honoured before first use.  The .pro
    // ships libssl/libcrypto next to the binary so this normally resolves.
    const QStringList backends = QSslSocket::availableBackends();
    QVERIFY2(backends.contains(QStringLiteral("openssl")),
             "this lane needs Qt's OpenSSL backend for server-side TLS; available backends do "
             "not include openssl (ship libssl+libcrypto next to the test binary)");
    if (QSslSocket::activeBackend() != QLatin1String("openssl")) {
        QVERIFY2(QSslSocket::setActiveBackend(QStringLiteral("openssl")),
                 "could not switch Qt to the OpenSSL TLS backend");
    }
    QVERIFY2(QSslSocket::supportsSsl(), "Qt's OpenSSL backend reports no usable TLS");
    qInfo("TLS backend: %s (available: %s, Qt %s)", qPrintable(QSslSocket::activeBackend()),
          qPrintable(backends.join(QStringLiteral(", "))), qVersion());

    // The DPAPI store only accepts a fixed, non-system volume, so the runner must
    // name the root explicitly.  Missing or unusable => FAIL, never skip: the
    // real login/enrollment cases below would otherwise go unverified silently.
    const QByteArray fromEnv = qgetenv("KANADE_DPAPI_TEST_ROOT");
    QVERIFY2(!fromEnv.isEmpty(),
             "KANADE_DPAPI_TEST_ROOT is not set. The Windows DPAPI store refuses the OS volume "
             "and non-fixed volumes, so this lane needs an explicit scratch root (one absolute "
             "path on a fixed non-system volume, created by the CI job).");
    const QString candidate = QString::fromLocal8Bit(fromEnv);
    QVERIFY2(QDir::isAbsolutePath(candidate),
             qPrintable(QStringLiteral("KANADE_DPAPI_TEST_ROOT must be an absolute path: %1")
                            .arg(candidate)));
    // The parent sets this on the runner after its own volume checks; the store
    // then creates a fresh private leaf inside it.  Missing means the runner is
    // misconfigured, so fail here instead of creating a directory on a volume the
    // store would refuse anyway.
    QVERIFY2(QDir(candidate).exists(),
             qPrintable(QStringLiteral("KANADE_DPAPI_TEST_ROOT does not exist: %1")
                            .arg(candidate)));
    m_approvedRoot = QDir::cleanPath(candidate);

    // Prove the whole storage stack works BEFORE any HTTPS case runs, so a
    // misconfigured runner fails with one precise message instead of eight
    // opaque "identity_storage_failed" results.  This exercises the real path:
    // the store creates a fresh leaf under the supplied directory with its own
    // private DACL, seals a throwaway Ed25519 seed with DPAPI, reloads it and
    // deletes it.  (A pre-existing directory is never re-ACLed, which is why the
    // probe uses a leaf the store itself creates.)
    QVERIFY2(Kanade::IdentityStore::platformSupported(),
             "the Win32 identity store is not compiled in; do not build this lane with "
             "KANADE_DISABLE_WIN32_IDENTITY");
    {
        ScratchRoot probeRoot(m_approvedRoot, QStringLiteral("kanade-https-probe"));
        QVERIFY2(probeRoot.valid(), "could not build a scratch leaf under KANADE_DPAPI_TEST_ROOT");
        Kanade::IdentityStore store(probeRoot.path());
        const QUrl scope = canonicalOrigin(QUrl(QStringLiteral("https://kanade.invalid")));
        QVERIFY(scope.isValid());
        const Kanade::InstallationIdentity generated = Kanade::generateIdentity();
        QVERIFY(!generated.privateKey.isEmpty());
        QVERIFY2(store.save(scope, QStringLiteral("root-probe"), generated),
                 qPrintable(QStringLiteral("store refused KANADE_DPAPI_TEST_ROOT (needs a fixed "
                                           "non-system volume with no reparse point): %1")
                                .arg(m_approvedRoot)));
        Kanade::InstallationIdentity loaded;
        QVERIFY2(store.load(scope, QStringLiteral("root-probe"), loaded),
                 "the sealed identity could not be loaded back (DPAPI unusable here?)");
        QCOMPARE(loaded.publicKey, generated.publicKey);
        QVERIFY(store.forget(scope, QStringLiteral("root-probe")));
        QVERIFY(!store.load(scope, QStringLiteral("root-probe"), loaded));
    }

    QString error;
    QVERIFY2(TestPki::generate(m_pki, &error),
             qPrintable(QStringLiteral("test PKI generation failed: %1").arg(error)));
    QVERIFY(!m_pki.trustedAuthority.isNull());
    QVERIFY(m_pki.trustedServer.certificate.toDer() != m_pki.wrongHostServer.certificate.toDer());
    // The trusted and untrusted chains differ, so the negative cases cannot pass
    // by accident.
    QVERIFY(m_pki.trustedAuthority.toDer() != m_pki.untrustedAuthority.toDer());
}

// ---------------------------------------------------------------------------
// KanadeApi: verified TLS
// ---------------------------------------------------------------------------

void KanadeHttpsTest::apiCompletesLoginOverVerifiedTls()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             /*authenticated=*/false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::None));
    QCOMPARE(login.result.httpStatus, 200);
    QVERIFY(KanadeApi::tokenPairIsUsable(login.result.body));

    // A real TLS session was negotiated with a concrete cipher.
    QVERIFY(server.negotiatedProtocol() != QSsl::UnknownProtocol);
    QVERIFY(!server.negotiatedCipher().isEmpty());
    QVERIFY(server.handshakeCount() >= 1);

    api.adoptTokenPair(login.result.body);
    QVERIFY(api.hasTokens());

    SyncCall me;
    api.get(QStringLiteral("/v1/auth/me"), me.completion());
    QVERIFY(me.wait());
    QCOMPARE(kindOf(me.result), int(KanadeApi::ErrorKind::None));
    QCOMPARE(me.result.body.value(QStringLiteral("user"))
                 .toObject()
                 .value(QStringLiteral("id"))
                 .toString(),
             server.userId());
    // The authenticated call carried the access token issued by the TLS peer.
    QCOMPARE(server.lastAuthorization(),
             QByteArrayLiteral("Bearer ")
                 + login.result.body.value(QStringLiteral("access_token")).toString().toUtf8());
    // Two independent TLS connections (the fixture closes after every reply).
    QVERIFY(server.handshakeCount() >= 2);
}

void KanadeHttpsTest::apiRejectsUntrustedCertificate()
{
    MockKanadeServer server;
    QString error;
    // The server presents a chain from an authority the client does not trust.
    QVERIFY2(server.listenTls(m_pki.untrustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             /*authenticated=*/false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::Tls));
    QVERIFY(login.result.body.isEmpty());
    QVERIFY(!KanadeApi::tokenPairIsUsable(login.result.body));
    QVERIFY(!api.hasTokens());
    // Verification aborted the connection before any HTTP request was written.
    QCOMPARE(server.requestCount(), 0);
}

void KanadeHttpsTest::apiRejectsTrustedCertificateForWrongHost()
{
    MockKanadeServer server;
    QString error;
    // Chain validates under the trusted CA, but the SAN is kanade.invalid only.
    QVERIFY2(server.listenTls(m_pki.wrongHostServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             /*authenticated=*/false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::Tls));
    QCOMPARE(server.requestCount(), 0);
}

void KanadeHttpsTest::apiNeverFollowsRedirect()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    // Redirect to a real endpoint on the SAME server: if the client followed it,
    // a second request would be recorded.
    server.redirectNextLoginTo(server.origin().toString() + QStringLiteral("/v1/auth/me"));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             /*authenticated=*/false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::Redirect));
    QCOMPARE(login.result.httpStatus, 302);
    QVERIFY(!KanadeApi::tokenPairIsUsable(login.result.body));
    QCOMPARE(server.requestCount(), 1);
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("GET"), QStringLiteral("/v1/auth/me")), 0);
}

void KanadeHttpsTest::apiRefusesCrossOriginSwapWithLiveTokens()
{
    KanadeApi api;
    QUrl first;
    QVERIFY(KanadeApi::normalizeOrigin(QStringLiteral("https://first.invalid"), first));
    QVERIFY(api.setOrigin(first));
    api.adoptTokenPair(syntheticTokens(QStringLiteral("a"), QStringLiteral("b")));
    QVERIFY(api.hasTokens());

    QUrl second;
    QVERIFY(KanadeApi::normalizeOrigin(QStringLiteral("https://second.invalid"), second));
    QVERIFY(!api.setOrigin(second));
    QCOMPARE(api.origin(), first);

    api.clearTokens();
    QVERIFY(api.setOrigin(second));
}

// ---------------------------------------------------------------------------
// KanadeApi: auth / token transitions
// ---------------------------------------------------------------------------

void KanadeHttpsTest::apiTreatsMissingTokenAsUnauthorized()
{
    KanadeApi api;
    QUrl origin;
    QVERIFY(KanadeApi::normalizeOrigin(QStringLiteral("https://kanade.invalid"), origin));
    QVERIFY(api.setOrigin(origin));

    // No access and no refresh token: fail locally, never on the wire.
    SyncCall devices;
    api.get(QStringLiteral("/v1/devices"), devices.completion());
    QVERIFY(devices.done); // synchronous
    QCOMPARE(kindOf(devices.result), int(KanadeApi::ErrorKind::HttpError));
    QCOMPARE(devices.result.httpStatus, 401);
    QCOMPARE(devices.result.serverCode, QStringLiteral("token_missing"));
}

void KanadeHttpsTest::apiRefreshesOnceThenRetries()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::None));
    api.adoptTokenPair(login.result.body);

    int authLost = 0;
    connect(&api, &KanadeApi::authenticationLost, this, [&authLost]() { ++authLost; });

    // Force the next authenticated call to answer 401 token_expired once.
    server.expireNextAuthenticatedRequest();

    SyncCall devices;
    api.get(QStringLiteral("/v1/devices"), devices.completion());
    QVERIFY(devices.wait());
    QCOMPARE(kindOf(devices.result), int(KanadeApi::ErrorKind::None)); // retried after refresh
    QCOMPARE(server.refreshCount(), 1);
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("GET"), QStringLiteral("/v1/devices")), 2);
    QCOMPARE(authLost, 0);
    QVERIFY(api.hasTokens());
}

void KanadeHttpsTest::apiFailsClosedWhenRefreshFails()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    api.adoptTokenPair(login.result.body);
    QVERIFY(api.hasTokens());

    int authLost = 0;
    connect(&api, &KanadeApi::authenticationLost, this, [&authLost]() { ++authLost; });

    server.failRefresh();
    server.expireNextAuthenticatedRequest();

    SyncCall devices;
    api.get(QStringLiteral("/v1/devices"), devices.completion());
    QVERIFY(devices.wait());
    QCOMPARE(kindOf(devices.result), int(KanadeApi::ErrorKind::HttpError));
    QCOMPARE(devices.result.httpStatus, 401);
    QCOMPARE(authLost, 1);
    QVERIFY(!api.hasTokens());

    // The dead refresh token was presented once and never re-sent.
    QCOMPARE(server.refreshCount(), 1);
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("GET"), QStringLiteral("/v1/devices")), 1);
}

void KanadeHttpsTest::apiAbortsOutstandingRequest()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));
    api.adoptTokenPair(syntheticTokens(QStringLiteral("c"), QStringLiteral("d")));

    server.delayPath(QStringLiteral("/v1/devices"), 4000);

    int completions = 0;
    KanadeApi::Result captured;
    api.get(QStringLiteral("/v1/devices"), [&](const KanadeApi::Result& result) {
        ++completions;
        captured = result;
    });
    QTest::qWait(50);
    api.abortAll();
    QCOMPARE(completions, 1);
    QCOMPARE(kindOf(captured), int(KanadeApi::ErrorKind::Cancelled));

    // No pre-existing completion may fire later, even when the reply arrives.
    QTest::qWait(600);
    QCOMPARE(completions, 1);
}

void KanadeHttpsTest::apiTimesOutSlowReply()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));
    api.setTimeouts(250, KanadeApi::kDefaultMaxBodyBytes);

    server.delayPath(QStringLiteral("/v1/auth/login"), 3000);

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::Timeout));
}

void KanadeHttpsTest::apiBoundsOversizedBody()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));
    api.setTimeouts(15000, 512); // tiny bound; the padded login reply exceeds it

    server.setLoginPadding(4096);

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    QCOMPARE(kindOf(login.result), int(KanadeApi::ErrorKind::BodyTooLarge));
}

// ---------------------------------------------------------------------------
// KanadeApi: sign-out semantics
// ---------------------------------------------------------------------------

void KanadeHttpsTest::apiLogoutIsLocalFirst()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    api.adoptTokenPair(login.result.body);
    const QByteArray capturedBearer =
        QByteArrayLiteral("Bearer ")
        + login.result.body.value(QStringLiteral("access_token")).toString().toUtf8();

    // A device read is still in flight when we sign out.
    server.delayPath(QStringLiteral("/v1/devices"), 500);
    SyncCall devices;
    api.get(QStringLiteral("/v1/devices"), devices.completion());
    QTest::qWait(30);

    SyncCall logout;
    api.logoutBestEffort(logout.completion());
    // Local-first: credentials are already gone, before any reply.
    QVERIFY(!api.hasTokens());

    QVERIFY(devices.wait(5000)); // the in-flight read still completes (harmlessly)
    QVERIFY(logout.wait(5000));

    qsizetype logoutIndex = -1;
    for (qsizetype i = 0; i < server.requests().size(); ++i) {
        if (server.requests().at(i).path == QLatin1String("/v1/auth/logout")) {
            logoutIndex = i;
        }
    }
    QVERIFY(logoutIndex >= 0);
    // The best-effort request carried the credential captured before the clear.
    QCOMPARE(server.requests().at(logoutIndex).authorization, capturedBearer);
    // Nothing restored credentials after the reply landed.
    QVERIFY(!api.hasTokens());
}

void KanadeHttpsTest::apiLateLogoutReplyCannotClearNewerTokens()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    KanadeApi api;
    api.setSslConfiguration(trustingOnly(m_pki.trustedAuthority));
    QVERIFY(setOriginFromServer(api, server));

    SyncCall login;
    api.post(QStringLiteral("/v1/auth/login"),
             QJsonObject{{QStringLiteral("login"), kAccountLogin},
                         {QStringLiteral("password"), kPassword}},
             false, login.completion());
    QVERIFY(login.wait());
    api.adoptTokenPair(login.result.body);

    int authLost = 0;
    connect(&api, &KanadeApi::authenticationLost, this, [&authLost]() { ++authLost; });

    server.delayPath(QStringLiteral("/v1/auth/logout"), 400);
    SyncCall logout;
    api.logoutBestEffort(logout.completion());
    QVERIFY(!api.hasTokens());

    // A new session starts before the old logout reply lands.
    api.adoptTokenPair(syntheticTokens(QStringLiteral("e"), QStringLiteral("f")));
    QVERIFY(api.hasTokens());

    QVERIFY(logout.wait(5000));
    // The stale logout reply must not clear the newer credentials.
    QVERIFY(api.hasTokens());
    QCOMPARE(authLost, 0);
}

// ---------------------------------------------------------------------------
// KanadeController over real HTTPS
// ---------------------------------------------------------------------------

void KanadeHttpsTest::controllerRejectsUntrustedCertificate()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.untrustedServer, &error), qPrintable(error));

    ScratchRoot root(m_approvedRoot, QStringLiteral("kanade-https-tls"));
    QVERIFY(root.valid());
    KanadeController controller(root.path());
    QVERIFY2(controller.supported(),
             "the Win32 identity store is not compiled in; this lane must not be built with "
             "KANADE_DISABLE_WIN32_IDENTITY");
    controller.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));

    controller.login(server.origin().toString(), kAccountLogin, kPassword);
    QVERIFY(waitUntil([&]() { return !controller.busy(); }, 15000));
    QCOMPARE(controller.errorCode(), QStringLiteral("tls_error"));
    QVERIFY(!controller.authenticated());
    QVERIFY(controller.devices().isEmpty());
    // The failure happened during the handshake: no HTTP request, nor an identity
    // file, was ever created.
    QCOMPARE(server.requestCount(), 0);
    QVERIFY(!QDir(root.path()).exists());
}

void KanadeHttpsTest::controllerMapsRedirectToOriginMismatch()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));
    server.redirectNextLoginTo(server.origin().toString() + QStringLiteral("/v1/auth/me"));

    ScratchRoot root(m_approvedRoot, QStringLiteral("kanade-https-redirect"));
    QVERIFY(root.valid());
    KanadeController controller(root.path());
    QVERIFY2(controller.supported(), "the Win32 identity store is not compiled in");
    controller.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));

    controller.login(server.origin().toString(), kAccountLogin, kPassword);
    QVERIFY(waitUntil([&]() { return !controller.busy(); }, 15000));
    QCOMPARE(controller.errorCode(), QStringLiteral("origin_mismatch"));
    QVERIFY(!controller.authenticated());
    QCOMPARE(server.requestCount(), 1); // redirect never followed
}

void KanadeHttpsTest::controllerRunsFullDeviceSessionAndPasswordPairing()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    ScratchRoot root(m_approvedRoot, QStringLiteral("kanade-https-password"));
    QVERIFY(root.valid());
    KanadeController controller(root.path());
    QVERIFY2(controller.supported(), "the Win32 identity store is not compiled in");
    controller.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));

    controller.login(server.origin().toString(), kAccountLogin, kPassword);
    QVERIFY(waitUntil([&]() { return !controller.busy(); }, 30000));

    QCOMPARE(server.requestCountFor(QByteArrayLiteral("POST"),
                                    QStringLiteral("/v1/auth/login")),
             1);
    QVERIFY2(controller.errorCode().isEmpty(),
             qPrintable(QStringLiteral("login failed with %1; the DPAPI store rejected the "
                                       "scratch root (check KANADE_DPAPI_TEST_ROOT is on a "
                                       "fixed non-system volume)")
                            .arg(controller.errorCode())));
    QVERIFY(controller.authenticated());
    // Real Ed25519 enrollment + device-token exchange happened and the mock
    // VERIFIED both proofs: a signing mismatch would have produced protocol_error
    // instead of an authenticated session.
    QCOMPARE(server.enrollmentsCreated(), 1);
    QCOMPARE(server.proofFailures(), 0);
    QVERIFY(!server.installationId().isEmpty());
    QVERIFY(controller.devices().isEmpty());

    // Password pairing: the password is the host's approval, so the grant is
    // issued immediately and the device list is re-read from the server.
    controller.addDevice(kPairCode, QStringLiteral("password"), server.pairPassword());
    QVERIFY2(waitUntil([&]() { return !controller.busy() && controller.devices().size() == 1; },
                       30000),
             qPrintable(QStringLiteral("password pairing did not produce a device row (error %1)")
                            .arg(controller.errorCode())));
    QCOMPARE(controller.pairState(), QStringLiteral("approved"));
    QCOMPARE(controller.errorCode(), QString());

    const QVariantMap device = controller.devices().at(0).toMap();
    const QString grantId = device.value(QStringLiteral("grantId")).toString();
    QVERIFY(!grantId.isEmpty());
    QCOMPARE(device.value(QStringLiteral("connectionState")).toString(),
             QStringLiteral("unknown"));
    QCOMPARE(server.grantCount(), 1);

    // Revocation: the server snapshot is authoritative and the row disappears.
    controller.removeGrant(grantId);
    QVERIFY(waitUntil([&]() { return !controller.busy() && controller.devices().isEmpty(); },
                      30000));
    QCOMPARE(controller.errorCode(), QString());
    QCOMPARE(server.grantCount(), 0);

    // Sign-out is local-first and still sends exactly one best-effort logout that
    // carries a bearer credential captured before the local clear.
    const int logoutBefore =
        server.requestCountFor(QByteArrayLiteral("POST"), QStringLiteral("/v1/auth/logout"));
    controller.logout();
    QVERIFY(!controller.authenticated());
    QVERIFY(controller.devices().isEmpty());
    QVERIFY(waitUntil(
        [&]() {
            return server.requestCountFor(QByteArrayLiteral("POST"),
                                          QStringLiteral("/v1/auth/logout"))
                == logoutBefore + 1;
        },
        10000));
    QVERIFY(server.lastAuthorization().startsWith("Bearer kat_"));
}

void KanadeHttpsTest::controllerReusesPersistedIdentityAndConfirmsPairing()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    ScratchRoot root(m_approvedRoot, QStringLiteral("kanade-https-reuse"));
    QVERIFY(root.valid());

    KanadeController first(root.path());
    QVERIFY2(first.supported(), "the Win32 identity store is not compiled in");
    first.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));
    first.login(server.origin().toString(), kAccountLogin, kPassword);
    QVERIFY(waitUntil([&]() { return !first.busy(); }, 30000));
    QVERIFY2(first.authenticated(),
             qPrintable(QStringLiteral("first login failed with %1; check "
                                       "KANADE_DPAPI_TEST_ROOT is on a fixed non-system volume")
                            .arg(first.errorCode())));
    QCOMPARE(server.enrollmentsCreated(), 1);
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("POST"),
                                    QStringLiteral("/v1/installations/challenge")),
             1);

    // Second controller, same approved root and origin: the persisted identity
    // must be reused (no new key, no new enrollment) and go straight to the
    // device-token exchange over real TLS.
    KanadeController second(root.path());
    second.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));
    second.login(server.origin().toString(), kAccountLogin, kPassword);
    QVERIFY(waitUntil([&]() { return !second.busy(); }, 30000));
    QVERIFY2(second.authenticated(),
             qPrintable(QStringLiteral("identity reuse failed with %1")
                            .arg(second.errorCode())));
    QCOMPARE(server.enrollmentsCreated(), 1); // no second key was enrolled
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("POST"),
                                    QStringLiteral("/v1/installations/challenge")),
             1); // no second enrollment challenge

    // Host-approval pairing: the request starts pending, the host approves, and
    // the controller polls until the authoritative snapshot says so.
    second.addDevice(QStringLiteral("WXYZ-1234"), QStringLiteral("confirm"), QString());
    QVERIFY2(
        waitUntil([&]() { return second.pairState() == QStringLiteral("pending"); }, 15000),
        qPrintable(QStringLiteral("confirm pairing never reported pending (error %1)")
                       .arg(second.errorCode())));
    server.approvePendingPair();
    QVERIFY2(waitUntil([&]() { return !second.busy() && second.devices().size() == 1; }, 30000),
             qPrintable(QStringLiteral("host approval was not adopted (state %1, error %2)")
                            .arg(second.pairState(), second.errorCode())));
    QCOMPARE(second.pairState(), QStringLiteral("approved"));
    QCOMPARE(second.errorCode(), QString());
    QCOMPARE(server.grantCount(), 1);

    second.logout();
    QVERIFY(!second.authenticated());
    first.logout();
    QVERIFY(!first.authenticated());
}

void KanadeHttpsTest::controllerDropsLateLoginReplyAfterLogout()
{
    MockKanadeServer server;
    QString error;
    QVERIFY2(server.listenTls(m_pki.trustedServer, &error), qPrintable(error));

    ScratchRoot root(m_approvedRoot, QStringLiteral("kanade-https-late"));
    QVERIFY(root.valid());
    KanadeController controller(root.path());
    QVERIFY2(controller.supported(), "the Win32 identity store is not compiled in");
    controller.setSslConfigurationForTesting(trustingOnly(m_pki.trustedAuthority));

    server.delayPath(QStringLiteral("/v1/auth/login"), 700);
    controller.login(server.origin().toString(), kAccountLogin, kPassword);
    // Sign out before the login reply can land: the generation bump must make the
    // late reply a no-op (no authenticated state, no error, no /auth/me request).
    controller.logout();
    QTest::qWait(1500);

    QVERIFY(!controller.authenticated());
    QVERIFY(controller.errorCode().isEmpty());
    QVERIFY(controller.devices().isEmpty());
    QCOMPARE(server.requestCountFor(QByteArrayLiteral("GET"), QStringLiteral("/v1/auth/me")), 0);
}

QTEST_GUILESS_MAIN(KanadeHttpsTest)
#include "main.moc"
