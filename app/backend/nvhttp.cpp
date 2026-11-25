#include "nvcomputer.h"
#include "pairedcertificate.h"
#include <Limelight.h>

#include <QHostInfo>
#include <QDebug>
#include <QUuid>
#include <QtNetwork/QNetworkReply>
#include <QEventLoop>
#include <QTimer>
#include <QXmlStreamReader>
#include <QSslKey>
#include <QImageReader>
#include <QtEndian>
#include <QNetworkProxy>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <memory>

#define FAST_FAIL_TIMEOUT_MS 2000
#define REQUEST_TIMEOUT_MS 5000
#define LAUNCH_TIMEOUT_MS 120000
#define RESUME_TIMEOUT_MS 30000
#define QUIT_TIMEOUT_MS 30000

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#define XML_NAME_EQUALS(x, y) ((x) == (y))
#else
#define XML_NAME_EQUALS(x, y) ((x) == (u##y))
#endif

NvHTTP::NvHTTP(NvAddress address, uint16_t httpsPort, QSslCertificate serverCert, bool useTrueUid, QNetworkAccessManager* nam, QString uuid) :
    m_Nam(nam ? nam : new QNetworkAccessManager(this)),
    m_ServerCert(serverCert),
    m_UseTrueUid(useTrueUid),
    m_Uuid(uuid)
{
    m_BaseUrlHttp.setScheme("http");
    m_BaseUrlHttps.setScheme("https");

    setAddress(address);
    setHttpsPort(httpsPort);

    // Never use a proxy server
    QNetworkProxy noProxy(QNetworkProxy::NoProxy);
    m_Nam->setProxy(noProxy);
}

NvHTTP::NvHTTP(NvComputer* computer, QNetworkAccessManager* nam) :
    NvHTTP(computer->activeAddress, computer->activeHttpsPort, computer->serverCert, !computer->isNvidiaServerSoftware, nam, computer->uuid)
{
}

NvHTTP::NvHTTP(const Kanade::ManagedNativePolicy& policy, QSslCertificate serverCert,
               QNetworkAccessManager* nam) :
    m_Nam(nam ? nam : new QNetworkAccessManager(this)),
    m_ServerCert(std::move(serverCert)),
    m_UseTrueUid(true),
    m_Managed(policy)
{
    // Fail closed at construction: a managed instance must never exist in a
    // state that could degrade to unmanaged behaviour.  Nothing has been sent
    // yet, so throwing here is safe.
    if (!policy.valid()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed native policy is invalid"));
    }
    if (m_ServerCert.isNull() && policy.call != Kanade::NativeCall::PairCert) {
        // Managed native trust is always an explicit pin, with ONE narrow
        // exception: the pre-pairing certificate exchange has no peer
        // certificate yet.  Anything else without a pin refuses to construct.
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      QStringLiteral("Managed native policy has no pinned certificate"));
    }

    // The managed endpoint is fixed by the policy; nothing here reads a host
    // object, an address list or a settings entry.  httpPort()/httpsPort() are
    // therefore always the locked pair.
    m_BaseUrlHttp.setScheme("http");
    m_BaseUrlHttps.setScheme("https");
    m_Address = NvAddress(policy.endpoint.host, policy.endpoint.httpPort);
    m_BaseUrlHttp.setHost(policy.endpoint.host);
    m_BaseUrlHttps.setHost(policy.endpoint.host);
    m_BaseUrlHttp.setPort(policy.endpoint.httpPort);
    m_BaseUrlHttps.setPort(policy.endpoint.httpsPort);

    // Never use a proxy server
    QNetworkProxy noProxy(QNetworkProxy::NoProxy);
    m_Nam->setProxy(noProxy);
}

bool NvHTTP::managedActive() const
{
    if (!m_Managed.has_value()) {
        return false;
    }
    if (!m_Managed->valid()) {
        // An engaged-but-invalid managed descriptor is an error, never a
        // silent downgrade to the legacy client.
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed native policy is not usable"));
    }
    return true;
}

bool NvHTTP::setManagedCall(Kanade::NativeCall call, QString* reasonOut)
{
    if (!m_Managed.has_value()) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("not a managed native client");
        }
        return false;
    }
    if (!m_Managed->valid()) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("managed_native_policy_invalid");
        }
        return false;
    }
    if (call == Kanade::NativeCall::Quit) {
        // Cleanup-only slot: it may move the instance to quit, never re-open.
        m_Managed->call = call;
        return true;
    }
    const Kanade::NativeResult permit =
        m_Managed->gate->permits(call, Kanade::managedMonotonicNowMs(), m_Managed->runGeneration);
    if (!permit.ok()) {
        if (reasonOut) {
            *reasonOut = Kanade::nativeReasonToString(permit.reason);
        }
        return false;
    }
    m_Managed->call = call;
    return true;
}

void NvHTTP::requireManagedPermission(Kanade::NativeCall call) const
{
    if (!m_Managed.has_value()) {
        return; // unmanaged instance: legacy behaviour is untouched
    }
    if (!m_Managed->valid()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed native policy is not usable"));
    }
    const Kanade::NativeResult permit =
        m_Managed->gate->permits(call, Kanade::managedMonotonicNowMs(), m_Managed->runGeneration);
    if (!permit.ok()) {
        // Thrown before any socket is touched; no managed fallback exists.
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed native call refused: ")
                                          + Kanade::nativeReasonToString(permit.reason));
    }
}

void NvHTTP::setServerCert(QSslCertificate serverCert)
{
    m_ServerCert = serverCert;
}

void NvHTTP::setAddress(NvAddress address)
{
    Q_ASSERT(!address.isNull());

    // A managed client may never be re-pointed: its only target is the pinned
    // loopback endpoint of the immutable policy.
    if (m_Managed.has_value()) {
        Q_ASSERT(false);
        return;
    }

    m_Address = address;

    m_BaseUrlHttp.setHost(address.address());
    m_BaseUrlHttps.setHost(address.address());

    m_BaseUrlHttp.setPort(address.port());
}

void NvHTTP::setHttpsPort(uint16_t port)
{
    if (managedActive()) {
        // Strict managed HTTPS port: an advertised value that is not the locked
        // 47984 is refused, not silently adopted.
        if (port != Kanade::ManagedEndpointContext::kManagedHttpsPort) {
            throw GfeHttpResponseException(-1, "Managed host advertised a non-pinned HttpsPort");
        }
        return;
    }
    m_BaseUrlHttps.setPort(port);
}

void NvHTTP::setTrueUid(bool useTrueUid)
{
    m_UseTrueUid = useTrueUid;
}

void NvHTTP::setHostUuid(QString uuid)
{
    m_Uuid = uuid;
}

NvAddress NvHTTP::address()
{
    return m_Address;
}

QSslCertificate NvHTTP::serverCert()
{
    return m_ServerCert;
}

uint16_t NvHTTP::httpPort()
{
    return m_BaseUrlHttp.port();
}

uint16_t NvHTTP::httpsPort()
{
    return m_BaseUrlHttps.port();
}

QVector<int>
NvHTTP::parseQuad(QString quad)
{
    QVector<int> ret;

    // Return an empty vector for old GFE versions
    // that were missing GfeVersion.
    if (quad.isEmpty()) {
        return ret;
    }

    QStringList parts = quad.split(".");
    ret.reserve(parts.length());
    for (int i = 0; i < parts.length(); i++)
    {
        ret.append(parts.at(i).toInt());
    }

    return ret;
}

int
NvHTTP::getCurrentGame(QString serverInfo)
{
    // GFE 2.8 started keeping currentgame set to the last game played. As a result, it no longer
    // has the semantics that its name would indicate. To contain the effects of this change as much
    // as possible, we'll force the current game to zero if the server isn't in a streaming session.
    QString serverState = getXmlString(serverInfo, "state");
    if (serverState.endsWith("_SERVER_BUSY"))
    {
        return getXmlString(serverInfo, "currentgame").toInt();
    }
    else
    {
        return 0;
    }
}

QString
NvHTTP::getServerInfo(NvLogLevel logLevel, bool fastFail)
{
    QString serverInfo;

    if (managedActive()) {
        return getManagedServerInfo(logLevel, fastFail);
    }

    // Check if we have a pinned cert and HTTPS port for this host yet
    if (!m_ServerCert.isNull() && httpsPort() != 0)
    {
        try
        {
            // Always try HTTPS first, since it properly reports
            // pairing status (and a few other attributes).
            serverInfo = openConnectionToString(m_BaseUrlHttps,
                                                "serverinfo",
                                                nullptr,
                                                fastFail ? FAST_FAIL_TIMEOUT_MS : REQUEST_TIMEOUT_MS,
                                                logLevel);
            // Throws if the request failed
            verifyResponseStatus(serverInfo);
        }
        catch (const GfeHttpResponseException& e)
        {
            if (e.getStatusCode() == 401)
            {
                // Only a remote status from the paired TLS peer permits this
                // recovery. Local TLS failures are QtNetworkReplyException.
                serverInfo = openConnectionToString(m_BaseUrlHttp,
                                                    "serverinfo",
                                                    nullptr,
                                                    fastFail ? FAST_FAIL_TIMEOUT_MS : REQUEST_TIMEOUT_MS,
                                                    logLevel);
                verifyResponseStatus(serverInfo);
            }
            else
            {
                // Rethrow real errors
                throw e;
            }
        }
    }
    else
    {
        // Only use HTTP prior to pairing or fetching HTTPS port
        serverInfo = openConnectionToString(m_BaseUrlHttp,
                                            "serverinfo",
                                            nullptr,
                                            fastFail ? FAST_FAIL_TIMEOUT_MS : REQUEST_TIMEOUT_MS,
                                            logLevel);
        verifyResponseStatus(serverInfo);

        // Populate the HTTPS port
        uint16_t httpsPort = getXmlString(serverInfo, "HttpsPort").toUShort();
        if (httpsPort == 0) {
            httpsPort = DEFAULT_HTTPS_PORT;
        }
        setHttpsPort(httpsPort);

        // If we just needed to determine the HTTPS port, we'll try again over
        // HTTPS now that we have the port number
        if (!m_ServerCert.isNull()) {
            return getServerInfo(logLevel, fastFail);
        }
    }

    return serverInfo;
}

QString
NvHTTP::getManagedServerInfo(NvLogLevel logLevel, bool fastFail)
{
    const int timeout = fastFail ? FAST_FAIL_TIMEOUT_MS : REQUEST_TIMEOUT_MS;

    requireManagedPermission(Kanade::NativeCall::ServerInfo);

    if (m_ServerCert.isNull()) {
        // Discovery on the managed path always runs against the already-pinned
        // certificate.  Without one there is nothing to authenticate the peer,
        // so the snapshot is refused instead of being taken over plaintext.
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      QStringLiteral("Managed discovery requires a pinned certificate"));
    }

    // Managed discovery is HTTPS-only with the already-pinned certificate.
    // There is deliberately NO plaintext fallback: a 401, a TLS failure, a
    // certificate mismatch or a missing HttpsPort all end the call.  A managed
    // run therefore never depends on an unauthenticated bootstrap reply, and a
    // replaced certificate can never trigger automatic HTTP recovery.
    const QString serverInfo = openConnectionToString(m_BaseUrlHttps, "serverinfo", nullptr,
                                                      timeout, logLevel);
    verifyManagedResponseStatus(serverInfo);
    requireManagedHttpsPort(serverInfo);
    return serverInfo;
}

QString
NvHTTP::getManagedPairingBootstrap(NvLogLevel logLevel)
{
    // Narrow, purpose-built exception to "managed discovery is HTTPS-only".
    //
    // The GameStream pairing exchange legitimately begins over plaintext HTTP
    // because no peer certificate exists yet.  That reply is needed for exactly
    // two things: the host app version (to pick the pairing hash generation) and
    // confirmation of the pinned HttpsPort for the stage-5 TLS exchange.
    //
    // It is therefore available ONLY:
    //   * while this instance's managed call slot is PairCert (i.e. reached
    //     through the native pairing path, never through discovery);
    //   * while NO certificate is pinned yet - once one exists, a replaced
    //     certificate can never be re-bootstrapped or re-paired automatically;
    //   * against the pinned loopback HTTP endpoint only.
    //
    // The reply is never retained as host state, never merged into a projection
    // and never used to choose a dial target beyond the fixed pinned endpoint.
    if (!m_Managed.has_value()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed pairing bootstrap requires the managed path"));
    }
    if (!m_Managed->valid()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed native policy is not usable"));
    }
    if (m_Managed->call != Kanade::NativeCall::PairCert) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Managed bootstrap is only available to native pairing"));
    }
    if (!m_ServerCert.isNull()) {
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      QStringLiteral("A certificate is already pinned; no pairing bootstrap"));
    }

    requireManagedPermission(Kanade::NativeCall::PairCert);

    const QString serverInfo = openConnectionToString(m_BaseUrlHttp, "serverinfo", nullptr,
                                                      FAST_FAIL_TIMEOUT_MS, logLevel);
    verifyManagedResponseStatus(serverInfo);

    // The stage-5 target must be the pinned port, and it must be advertised by
    // the host rather than assumed.  This is a validation, never an adoption.
    requireManagedHttpsPort(serverInfo);
    return serverInfo;
}

void
NvHTTP::requireManagedHttpsPort(const QString& serverInfoXml)
{
    // Foundation nvhttp.cpp:534 always emits root.HttpsPort.  On the managed
    // path it is not advice to adopt: it must be present EXACTLY once and be the
    // canonical text of the locked 47984.  Missing, duplicated, alternate,
    // zero-padded or non-numeric values all refuse the whole snapshot, before
    // it can be projected into any host object or fed to a native launch.
    static const QString kTag = QStringLiteral("HttpsPort");
    static const QString kExpected = QString::number(Kanade::ManagedEndpointContext::kManagedHttpsPort);

    int occurrences = 0;
    QString value;
    QXmlStreamReader xmlReader(serverInfoXml);
    while (!xmlReader.atEnd()) {
        if (xmlReader.readNext() != QXmlStreamReader::StartElement) {
            continue;
        }
        if (xmlReader.name() != kTag) {
            continue;
        }
        ++occurrences;
        if (occurrences == 1) {
            value = xmlReader.readElementText();
        }
    }
    if (xmlReader.hasError() || occurrences != 1 || value != kExpected) {
        throw GfeHttpResponseException(-1, "Managed host snapshot has no single pinned HttpsPort");
    }
}

void
NvHTTP::startApp(QString verb,
                 bool isGfe,
                 int appId,
                 PSTREAM_CONFIGURATION streamConfig,
                 bool sops,
                 bool localAudio,
                 int gamepadMask,
                 bool persistGameControllersOnDisconnect,
                 QString& rtspSessionUrl,
                 int screenCombinationMode,
                 const std::optional<bool>& useVdd,
                 const QString& displayName,
                 RemoteStreamConfig &remoteStreamConfig)
{
    int riKeyId;

    memcpy(&riKeyId, streamConfig->remoteInputAesIv, sizeof(riKeyId));
    riKeyId = qFromBigEndian(riKeyId);
    // Using an FPS value over 60 causes SOPS to default to 720p60,
    // so force it to 0 to ensure the correct resolution is set. We
    // used to use 60 here but that locked the frame rate to 60 FPS
    // on GFE 3.20.3. We don't need this hack for Sunshine.
    QString appWidth = QString::number(streamConfig->width);
    QString appHeight = QString::number(streamConfig->height);
    QString appFps = QString::number((streamConfig->fps > 60 && isGfe) ? 0 : streamConfig->fps);

    // 流分辨率缩放覆盖
    if (remoteStreamConfig.originalStreamWidth > 0 && remoteStreamConfig.originalStreamHeight > 0) {
        appWidth = QString::number(remoteStreamConfig.originalStreamWidth);
        appHeight = QString::number(remoteStreamConfig.originalStreamHeight);
    }

    // 远程分辨率覆盖
    if (remoteStreamConfig.remoteResolution) {
        if (remoteStreamConfig.remoteResolutionWidth > 0) {
            appWidth = QString::number(remoteStreamConfig.remoteResolutionWidth);
        }
        if (remoteStreamConfig.remoteResolutionHeight > 0) {
            appHeight = QString::number(remoteStreamConfig.remoteResolutionHeight);
        }
    }
    // 远程帧率覆盖
    if (remoteStreamConfig.remoteFps) {
        if (remoteStreamConfig.remoteFpsRate > 0) {
            appFps = QString::number(remoteStreamConfig.remoteFpsRate);
        }
    }

    QString query =
            "appid="+QString::number(appId)+
            "&mode="+appWidth+"x"+
            appHeight+"x"+
            appFps+
            "&additionalStates=1&sops="+QString::number(sops ? 1 : 0)+
            "&rikey="+QByteArray(streamConfig->remoteInputAesKey, sizeof(streamConfig->remoteInputAesKey)).toHex()+
            "&rikeyid="+QString::number(riKeyId)+
            ((streamConfig->supportedVideoFormats & VIDEO_FORMAT_MASK_10BIT) ?
                "&hdrMode="+QString::number(streamConfig->hdrMode)+
                "&clientHdrCapVersion=0&clientHdrCapSupportedFlagsInUint32=0&clientHdrCapMetaDataId=NV_STATIC_METADATA_TYPE_1&clientHdrCapDisplayData=0x0x0x0x0x0x0x0x0x0x0" :
                 "")+
            "&localAudioPlayMode="+QString::number(localAudio ? 1 : 0)+
            "&surroundAudioInfo="+QString::number(SURROUNDAUDIOINFO_FROM_AUDIO_CONFIGURATION(streamConfig->audioConfiguration))+
            "&remoteControllersBitmap="+QString::number(gamepadMask)+
            "&gcmap="+QString::number(gamepadMask)+
            "&gcpersist="+QString::number(persistGameControllersOnDisconnect ? 1 : 0);

    if (screenCombinationMode != -1) {
        query += "&customScreenMode="+QString::number(screenCombinationMode);
    }
    if (useVdd.has_value()) {
        query += "&useVdd="+QString::number(*useVdd ? 1 : 0);
    }
    if (!displayName.isEmpty()) {
        query += "&display_name="+QString::fromLatin1(QUrl::toPercentEncoding(displayName));
    }
    if (remoteStreamConfig.maxBrightness > 0) {
        query += "&maxBrightness="+QString::number(remoteStreamConfig.maxBrightness, 'f', 3)+
                 "&minBrightness="+QString::number(remoteStreamConfig.minBrightness, 'f', 6)+
                 "&maxAverageBrightness="+QString::number(remoteStreamConfig.maxAverageBrightness, 'f', 3);
    }
    if (remoteStreamConfig.sdrWhiteBrightness >= 50.0f &&
            remoteStreamConfig.sdrWhiteBrightness <= 1000.0f) {
        // Foundation Sunshine parses this extension as an integer number of
        // nits. It uses the value to re-anchor SDR-referred content before
        // converting the host's scRGB desktop to the negotiated HDR transfer.
        query += "&sdrBrightness="+
                 QString::number(qRound(remoteStreamConfig.sdrWhiteBrightness));
    }

    query += LiGetLaunchUrlQueryParameters();

    if (managedActive()) {
        requireManagedPermission(verb == QStringLiteral("resume")
                                     ? Kanade::NativeCall::Resume
                                     : Kanade::NativeCall::Launch);
    }

    QString response = openConnectionToString(m_BaseUrlHttps,
                                              verb,
                                              query,
                                              LAUNCH_TIMEOUT_MS,
                                              m_Managed.has_value() ? NVLL_NONE : NVLL_VERBOSE);

    if (!m_Managed.has_value()) {
        qInfo() << "Launch response:" << response;
    }
    // Managed: never echo the launch reply -- the body carries the RTSP session
    // URL and per-session material.  Managed logging is reason codes only.

    // Throws if the request failed
    if (managedActive()) {
        verifyManagedResponseStatus(response);
    }
    else {
        verifyResponseStatus(response);
    }

    rtspSessionUrl = getXmlString(response, "sessionUrl0");

    if (managedActive()) {
        // Strict RTSP URL: only the exact encrypted loopback shape is accepted.
        // Anything else (plaintext scheme, another host/port, a path/suffix)
        // would let common-c dial somewhere this context never approved.
        const Kanade::ValidationResult rtsp =
            Kanade::ManagedEndpointContext::validateRtspUrl(rtspSessionUrl);
        if (!rtsp.ok()) {
            rtspSessionUrl.clear();
            throw GfeHttpResponseException(-1, "Managed host returned a non-pinned RTSP URL");
        }
    }
}

void
NvHTTP::quitApp()
{
    if (managedActive()) {
        // Quit is the only managed call allowed while stopping, and only while
        // the gate is still alive (never after death).
        requireManagedPermission(Kanade::NativeCall::Quit);
    }

    QString response =
            openConnectionToString(m_BaseUrlHttps,
                                   "cancel",
                                   nullptr,
                                   QUIT_TIMEOUT_MS,
                                   m_Managed.has_value() ? NVLL_NONE : NVLL_VERBOSE);

    if (!m_Managed.has_value()) {
        qInfo() << "Quit response:" << response;
    }

    // Throws if the request failed
    if (managedActive()) {
        verifyManagedResponseStatus(response);
    }
    else {
        verifyResponseStatus(response);
    }

    // Newer GFE versions will just return success even if quitting fails
    // if we're not the original requester.
    if (managedActive()) {
        // No follow-up discovery on the managed path: the stop must not make
        // any further contact, and "someone else's stream" cannot apply to a
        // single managed session.
        return;
    }
    if (getCurrentGame(getServerInfo(NvHTTP::NVLL_ERROR)) != 0) {
        // Generate a synthetic GfeResponseException letting the caller know
        // that they can't kill someone else's stream.
        throw GfeHttpResponseException(599, "");
    }
}

QVector<NvDisplayMode>
NvHTTP::getDisplayModeList(QString serverInfo)
{
    QXmlStreamReader xmlReader(serverInfo);
    QVector<NvDisplayMode> modes;

    while (!xmlReader.atEnd()) {
        while (xmlReader.readNextStartElement()) {
            auto name = xmlReader.name();
            if (XML_NAME_EQUALS(name, "DisplayMode")) {
                modes.append(NvDisplayMode());
            }
            else if (!modes.isEmpty()) {
                if (XML_NAME_EQUALS(name, "Width")) {
                    modes.last().width = xmlReader.readElementText().toInt();
                }
                else if (XML_NAME_EQUALS(name, "Height")) {
                    modes.last().height = xmlReader.readElementText().toInt();
                }
                else if (XML_NAME_EQUALS(name, "RefreshRate")) {
                    modes.last().refreshRate = xmlReader.readElementText().toInt();
                }
            }
        }
    }

    return modes;
}

QVector<NvApp>
NvHTTP::getAppList()
{
    if (managedActive()) {
        requireManagedPermission(Kanade::NativeCall::AppList);
    }

    QString appxml = openConnectionToString(m_BaseUrlHttps,
                                            "applist",
                                            nullptr,
                                            REQUEST_TIMEOUT_MS,
                                            NvLogLevel::NVLL_ERROR);
    verifyResponseStatus(appxml);

    QXmlStreamReader xmlReader(appxml);
    QVector<NvApp> apps;
    while (!xmlReader.atEnd()) {
        while (xmlReader.readNextStartElement()) {
            auto name = xmlReader.name();
            if (XML_NAME_EQUALS(name, "App")) {
                // We must have a valid app before advancing to the next one
                if (!apps.isEmpty() && !apps.last().isInitialized()) {
                    qWarning() << "Invalid applist XML";
                    throw std::runtime_error("Invalid applist XML");
                }
                apps.append(NvApp());
            }
            else if (!apps.isEmpty()) {
                if (XML_NAME_EQUALS(name, "AppTitle")) {
                    // If an app has no name, Sunshine may send us <AppTitle/>,
                    // which readElementText() returns as a null QString.
                    // We want to treat this as an empty QString instead, so we
                    // will explicitly convert it. An empty string will satisfy
                    // NvApp's isInitialized() check.
                    QString name = xmlReader.readElementText();
                    if (name.isNull()) {
                        name = "";
                    }
                    apps.last().name = name;
                }
                else if (XML_NAME_EQUALS(name, "ID")) {
                    apps.last().id = xmlReader.readElementText().toInt();
                }
                else if (XML_NAME_EQUALS(name, "IsHdrSupported")) {
                    apps.last().hdrSupported = xmlReader.readElementText() == "1";
                }
                else if (XML_NAME_EQUALS(name, "IsAppCollectorGame")) {
                    apps.last().isAppCollectorGame = xmlReader.readElementText() == "1";
                }
            }
        }
    }

    return apps;
}

QVariantList
NvHTTP::getDisplays()
{
    QVariantList displays;

    try {
        QString response = openConnectionToString(m_BaseUrlHttps,
                                                   "displays",
                                                   nullptr,
                                                   REQUEST_TIMEOUT_MS,
                                                   NvLogLevel::NVLL_VERBOSE);

        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            qWarning() << "Failed to parse displays JSON:" << parseError.errorString();
            return displays;
        }

        QJsonObject root = doc.object();
        int statusCode = root.value("status_code").toInt(0);
        if (statusCode != 200) {
            qWarning() << "getDisplays failed:" << root.value("status_message").toString();
            return displays;
        }

        QJsonArray displaysArray = root.value("displays").toArray();
        for (int i = 0; i < displaysArray.size(); i++) {
            QJsonObject displayObj = displaysArray[i].toObject();

            const QString displayName = displayObj.value("display_name").toString();
            QString friendlyName = displayObj.value("friendly_name").toString();
            if (friendlyName.isEmpty()) {
                friendlyName = displayName;
            }
            if (friendlyName.isEmpty()) {
                friendlyName = QString("Display %1").arg(i + 1);
            }

            QString displayTarget = displayObj.value("device_id").toString();
            if (displayTarget.isEmpty()) {
                displayTarget = displayName.isEmpty() ? friendlyName : displayName;
            }

            QVariantMap display;
            display["name"] = friendlyName;
            display["id"] = QStringLiteral("physical:%1:%2").arg(i).arg(displayTarget);
            display["target"] = displayTarget;
            display["index"] = i;
            displays.append(display);
        }
    } catch (...) {
        qWarning() << "Exception in getDisplays()";
    }

    return displays;
}

void
NvHTTP::verifyResponseStatus(QString xml)
{
    QXmlStreamReader xmlReader(xml);

    while (xmlReader.readNextStartElement())
    {
        if (XML_NAME_EQUALS(xmlReader.name(), "root"))
        {
            // Status code can be 0xFFFFFFFF in some rare cases on GFE 3.20.3, and
            // QString::toInt() will fail in that case, so use QString::toUInt()
            // and cast the result to an int instead.
            int statusCode = (int)xmlReader.attributes().value("status_code").toUInt();
            if (statusCode == 200)
            {
                // Successful
                return;
            }
            else
            {
                QString statusMessage = xmlReader.attributes().value("status_message").toString();
                if (statusCode != 401) {
                    // 401 is expected for unpaired PCs when we fetch serverinfo over HTTPS
                    qWarning() << "Request failed:" << statusCode << statusMessage;
                }
                if (statusCode == -1 && statusMessage == "Invalid") {
                    // Special case handling an audio capture error which GFE doesn't
                    // provide any useful status message for.
                    statusCode = 418;
                    statusMessage = tr("Missing audio capture device. Reinstalling GeForce Experience should resolve this error.");
                }
                throw GfeHttpResponseException(statusCode, statusMessage);
            }
        }
    }

    throw GfeHttpResponseException(-1, "Malformed XML (missing root element)");
}

void
NvHTTP::verifyManagedResponseStatus(QString xml)
{
    QXmlStreamReader xmlReader(xml);

    while (xmlReader.readNextStartElement())
    {
        if (XML_NAME_EQUALS(xmlReader.name(), "root"))
        {
            const int statusCode = (int)xmlReader.attributes().value("status_code").toUInt();
            if (statusCode == 200)
            {
                return;
            }

            // Never copy status_message: it is host-controlled text that can
            // echo request material.  Only the numeric status and a fixed
            // reason leave this function.
            if (statusCode == -1) {
                throw GfeHttpResponseException(418, QStringLiteral("Managed host rejected the request"));
            }
            throw GfeHttpResponseException(statusCode, QStringLiteral("Managed host request failed"));
        }
    }

    throw GfeHttpResponseException(-1, QStringLiteral("Managed host reply was malformed"));
}

QImage
NvHTTP::getBoxArt(int appId)
{
    if (managedActive()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("Box art is disabled on the managed path"));
    }
    QNetworkReply* reply = openConnection(m_BaseUrlHttps,
                                          "appasset",
                                          "appid="+QString::number(appId)+
                                          "&AssetType=2&AssetIdx=0",
                                          REQUEST_TIMEOUT_MS,
                                          NvLogLevel::NVLL_VERBOSE);
    QImage image = QImageReader(reply).read();
    delete reply;

    return image;
}

QByteArray
NvHTTP::getXmlStringFromHex(QString xml,
                            QString tagName)
{
    return QByteArray::fromHex(getXmlString(xml, tagName).toUtf8());
}

QString
NvHTTP::getXmlString(QString xml,
                     QString tagName)
{
    QXmlStreamReader xmlReader(xml);

    while (!xmlReader.atEnd())
    {
        if (xmlReader.readNext() != QXmlStreamReader::StartElement)
        {
            continue;
        }

        if (xmlReader.name() == tagName)
        {
            return xmlReader.readElementText();
        }
    }

    return QString();
}

void NvHTTP::handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors)
{
    if (PairedCertificate::canIgnoreErrors(m_ServerCert, errors)) {
        reply->ignoreSslErrors(errors);
    }
}

QString
NvHTTP::openConnectionToString(QUrl baseUrl,
                               QString command,
                               QString arguments,
                               int timeoutMs,
                               NvLogLevel logLevel)
{
    QNetworkReply* reply = openConnection(baseUrl, command, arguments, timeoutMs, logLevel);
    QString ret;

    QTextStream stream(reply);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    stream.setEncoding(QStringConverter::Utf8);
#else
    stream.setCodec("UTF-8");
#endif

    ret = stream.readAll();
    delete reply;

    return ret;
}

UsbForwarding::Capability NvHTTP::getUsbForwardingCapability()
{
    if (managedActive()) {
        // Managed path: host extensions are disabled.  Refused before any
        // connection, not a warning.
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("USB forwarding is disabled on the managed path"));
    }
    if (m_ServerCert.isNull() || httpsPort() == 0) {
        throw GfeHttpResponseException(401, "USB forwarding requires a paired host");
    }
    std::unique_ptr<QNetworkReply> reply(openConnection(m_BaseUrlHttps,
        "api/v1/usb-forwarding", QString(), 5000, NVLL_NONE, 4096));
    // A normally trusted certificate may not emit sslErrors at all. Require
    // the paired leaf certificate even on that path before accepting credentials.
    if (!PairedCertificate::matches(m_ServerCert, reply->sslConfiguration().peerCertificate())) {
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      "USB forwarding host certificate mismatch");
    }
    if (reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200) {
        throw GfeHttpResponseException(400, "USB capability request failed");
    }
    const auto capability = UsbForwarding::Capability::parse(reply->readAll());
    if (!capability) throw GfeHttpResponseException(400, "Invalid USB capability response");
    return *capability;
}

bool
NvHTTP::getAbrCapabilities(int* hostMaxBitrateKbps)
{
    if (managedActive()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("ABR is disabled on the managed path"));
    }
    QJsonObject response = openJsonConnectionToObject(m_BaseUrlHttps,
                                                      "api/abr/capabilities",
                                                      QJsonObject(),
                                                      false,
                                                      FAST_FAIL_TIMEOUT_MS,
                                                      NvLogLevel::NVLL_ERROR);
    if (hostMaxBitrateKbps != nullptr) {
        *hostMaxBitrateKbps = response.value("hostMaxBitrate").toInt(0);
    }

    return response.value("supported").toBool(false);
}

QJsonObject
NvHTTP::configureAbr(bool enabled,
                     int minBitrateKbps,
                     int maxBitrateKbps,
                     QString mode,
                     int timeoutMs)
{
    if (managedActive()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("ABR is disabled on the managed path"));
    }
    QJsonObject body;
    body["enabled"] = enabled;
    if (enabled) {
        body["minBitrate"] = minBitrateKbps;
        body["maxBitrate"] = maxBitrateKbps;
        body["mode"] = mode;
    }

    return openJsonConnectionToObject(m_BaseUrlHttps,
                                      "api/abr",
                                      body,
                                      true,
                                      timeoutMs,
                                      NvLogLevel::NVLL_ERROR);
}

QJsonObject
NvHTTP::sendAbrFeedback(double packetLoss,
                        double rttMs,
                        double decodeFps,
                        int droppedFrames,
                        int currentBitrateKbps,
                        int timeoutMs)
{
    if (managedActive()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("ABR is disabled on the managed path"));
    }
    QJsonObject body;
    body["packetLoss"] = packetLoss;
    body["rttMs"] = rttMs;
    body["decodeFps"] = decodeFps;
    body["droppedFrames"] = droppedFrames;
    body["currentBitrate"] = currentBitrateKbps;

    return openJsonConnectionToObject(m_BaseUrlHttps,
                                      "api/abr/feedback",
                                      body,
                                      true,
                                      timeoutMs,
                                      NvLogLevel::NVLL_ERROR);
}

QNetworkReply*
NvHTTP::openConnection(QUrl baseUrl,
                       QString command,
                       QString arguments,
                       int timeoutMs,
                       NvLogLevel logLevel,
                       qint64 maxResponseBytes)
{
    // Port must be set
    Q_ASSERT(baseUrl.port(0) != 0);

    // Managed: every request re-checks the shared gate at the moment it would
    // open a connection.  A revoked/expired lease stops here, before any byte
    // leaves the process.
    if (managedActive()) {
        requireManagedPermission(m_Managed->call);
    }

    // Build a URL for the request
    QUrl url(baseUrl);
    url.setPath("/" + command);

    // Managed path: the target is fixed by the policy.  Any attempt to reach a
    // different host/port is refused, and clientname/pairname settings are never
    // read (that would introduce a global identity/history dependency).
    if (managedActive()) {
        if (url.host() != m_Managed->endpoint.host
            || (url.port(0) != m_Managed->endpoint.httpPort
                && url.port(0) != m_Managed->endpoint.httpsPort)) {
            throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                          QStringLiteral("Managed request target is not pinned"));
        }
    }

    // Get clientname - prefer pairname if available, otherwise use local hostname
    QString clientname;
    if (!m_Managed.has_value()) {
        clientname = QHostInfo::localHostName().toUtf8();
        if (!m_Uuid.isEmpty()) {
            QString pairname = NvComputer::getPairname(m_Uuid);
            if (!pairname.isEmpty()) {
                clientname = pairname;
            }
        }

        qInfo() << "clientname:" << clientname;
    }
    else {
        // Fixed, non-identifying label: the managed path must not disclose the
        // local host name or read a persisted per-host pairname.
        clientname = QStringLiteral("Kanade");
    }

    // Use a placeholder UID for GFE allow them to quit games for each other.
    url.setQuery("uniqueid=" + (m_UseTrueUid ? IdentityManager::get()->getUniqueId() : "0123456789ABCDEF") +
                 "&uuid=" + QUuid::createUuid().toRfc4122().toHex() +
                 "&clientname=" + clientname +
                 (!arguments.isNull() ? ("&" + arguments) : ""));

    QNetworkRequest request(url);

    // Host-control endpoints must never forward credentials to another URL.
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);

    // Add our client certificate
    request.setSslConfiguration(IdentityManager::get()->getSslConfig());

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    // Disable HTTP/2 (GFE 3.22 doesn't like it) and Qt 6 enables it by default
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
#endif

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0)
    // Use fine-grained idle timeouts to avoid calling QNetworkAccessManager::clearAccessCache(),
    // which tears down the NAM's global thread each time. We must not keep persistent connections
    // or GFE will puke.
    request.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 0);
#endif

    auto sslErrorsConnection = connect(m_Nam, &QNetworkAccessManager::sslErrors, this, &NvHTTP::handleSslErrors);
    auto pinnedConnection = PairedCertificate::enforce(m_Nam, this, m_ServerCert);
    QNetworkReply* reply = m_Nam->get(request);

    // Run the request with a timeout if requested
    QEventLoop loop;
    bool oversized = false;
    if (maxResponseBytes > 0) {
        reply->setReadBufferSize(maxResponseBytes + 1);
        connect(reply, &QNetworkReply::readyRead, &loop, [&] {
            if (reply->bytesAvailable() > maxResponseBytes) {
                oversized = true;
                reply->abort();
            }
        });
    }
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, &loop, &QEventLoop::quit);
    if (timeoutMs) {
        QTimer::singleShot(timeoutMs, &loop, &QEventLoop::quit);
    }
    if (logLevel >= NvLogLevel::NVLL_VERBOSE && !m_Managed.has_value()) {
        qInfo() << "Executing request:" << url.toString();
    }
    loop.exec(QEventLoop::ExcludeUserInputEvents);

    // Abort the request if it timed out
    if (!reply->isFinished())
    {
        if (logLevel >= NvLogLevel::NVLL_ERROR && !m_Managed.has_value()) {
            qWarning() << "Aborting timed out request for" << url.toString();
        }
        reply->abort();
    }

#if QT_VERSION < QT_VERSION_CHECK(6, 3, 0)
    // If we couldn't use fine-grained connection idle timeouts, kill them all now
    m_Nam->clearAccessCache();
#endif
    disconnect(sslErrorsConnection);
    disconnect(pinnedConnection);
    if (url.scheme() == QStringLiteral("https") &&
        (reply->error() == QNetworkReply::NoError ||
         !reply->sslConfiguration().peerCertificate().isNull()) &&
        !PairedCertificate::matches(m_ServerCert, reply->sslConfiguration().peerCertificate())) {
        delete reply;
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      "Server certificate mismatch");
    }

    // Handle error
    if (oversized) {
        delete reply;
        throw GfeHttpResponseException(400, "USB capability response too large");
    }
    if (reply->error() != QNetworkReply::NoError)
    {
        if (logLevel >= NvLogLevel::NVLL_ERROR && !m_Managed.has_value()) {
            qWarning() << command << "request failed with error:" << reply->error();
        }

        if (reply->error() == QNetworkReply::OperationCanceledError) {
            QtNetworkReplyException exception(QNetworkReply::TimeoutError, "Request timed out");
            delete reply;
            throw exception;
        } else {
            // Managed: never surface the transport-supplied error text (it can
            // echo request material).  A fixed reason fails the call closed.
            QtNetworkReplyException exception(
                reply->error(),
                m_Managed.has_value() ? QStringLiteral("Managed host request failed")
                                      : reply->errorString());
            delete reply;
            throw exception;
        }
    }

    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (httpStatus >= 300 && httpStatus < 400) {
        delete reply;
        throw GfeHttpResponseException(httpStatus, "Host API redirects are not allowed");
    }
    return reply;
}

QJsonObject
NvHTTP::openJsonConnectionToObject(QUrl baseUrl,
                                   QString command,
                                   QJsonObject body,
                                   bool post,
                                   int timeoutMs,
                                   NvLogLevel logLevel)
{
    QNetworkReply* reply = openJsonConnection(baseUrl, command, body, post, timeoutMs, logLevel);
    QByteArray response = reply->readAll();
    delete reply;

    QJsonParseError parseError;
    QJsonDocument document = QJsonDocument::fromJson(response, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        qWarning() << command << "JSON response parse failed:" << parseError.errorString();
        throw GfeHttpResponseException(-1, "Malformed JSON response");
    }

    return document.object();
}

QNetworkReply*
NvHTTP::openJsonConnection(QUrl baseUrl,
                           QString command,
                           QJsonObject body,
                           bool post,
                           int timeoutMs,
                           NvLogLevel logLevel)
{
    // Port must be set
    Q_ASSERT(baseUrl.port(0) != 0);

    // Managed JSON calls are refused outright (ABR/extension slots); the early
    // guards above already throw, so reaching here with a policy is a bug and
    // must not silently continue.
    if (managedActive()) {
        throw QtNetworkReplyException(QNetworkReply::OperationCanceledError,
                                      QStringLiteral("JSON host API is disabled on the managed path"));
    }

    QUrl url(baseUrl);
    url.setPath("/" + command);

    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setSslConfiguration(IdentityManager::get()->getSslConfig());

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    // Disable HTTP/2 (GFE 3.22 doesn't like it) and Qt 6 enables it by default
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
#endif

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0)
    // Use fine-grained idle timeouts to avoid calling QNetworkAccessManager::clearAccessCache(),
    // which tears down the NAM's global thread each time. We must not keep persistent connections
    // or GFE will puke.
    request.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 0);
#endif

    auto sslErrorsConnection = connect(m_Nam, &QNetworkAccessManager::sslErrors, this, &NvHTTP::handleSslErrors);
    auto pinnedConnection = PairedCertificate::enforce(m_Nam, this, m_ServerCert);
    QNetworkReply* reply = post ?
                m_Nam->post(request, QJsonDocument(body).toJson(QJsonDocument::Compact)) :
                m_Nam->get(request);

    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, &loop, &QEventLoop::quit);
    if (timeoutMs) {
        QTimer::singleShot(timeoutMs, &loop, &QEventLoop::quit);
    }
    if (logLevel >= NvLogLevel::NVLL_VERBOSE) {
        qInfo() << "Executing JSON request:" << url.toString();
    }
    loop.exec(QEventLoop::ExcludeUserInputEvents);

    if (!reply->isFinished())
    {
        if (logLevel >= NvLogLevel::NVLL_ERROR) {
            qWarning() << "Aborting timed out JSON request for" << url.toString();
        }
        reply->abort();
    }

#if QT_VERSION < QT_VERSION_CHECK(6, 3, 0)
    m_Nam->clearAccessCache();
#endif
    disconnect(sslErrorsConnection);
    disconnect(pinnedConnection);
    if (url.scheme() == QStringLiteral("https") &&
        (reply->error() == QNetworkReply::NoError ||
         !reply->sslConfiguration().peerCertificate().isNull()) &&
        !PairedCertificate::matches(m_ServerCert, reply->sslConfiguration().peerCertificate())) {
        delete reply;
        throw QtNetworkReplyException(QNetworkReply::SslHandshakeFailedError,
                                      "Server certificate mismatch");
    }

    if (reply->error() != QNetworkReply::NoError)
    {
        if (logLevel >= NvLogLevel::NVLL_ERROR) {
            qWarning() << command << "JSON request failed with error:" << reply->error();
        }

        if (reply->error() == QNetworkReply::OperationCanceledError) {
            QtNetworkReplyException exception(QNetworkReply::TimeoutError, "Request timed out");
            delete reply;
            throw exception;
        } else {
            QtNetworkReplyException exception(reply->error(), reply->errorString());
            delete reply;
            throw exception;
        }
    }

    int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (httpStatus >= 300 && httpStatus < 400) {
        delete reply;
        throw GfeHttpResponseException(httpStatus, "Host API redirects are not allowed");
    }
    if (httpStatus >= 400) {
        QString errorText = QString::fromUtf8(reply->readAll());
        if (logLevel >= NvLogLevel::NVLL_ERROR) {
            qWarning() << command << "JSON request failed with HTTP status" << httpStatus << errorText;
        }
        delete reply;
        throw GfeHttpResponseException(httpStatus, errorText);
    }

    return reply;
}
