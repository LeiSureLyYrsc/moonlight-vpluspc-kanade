#pragma once

#include "identitymanager.h"
#include "nvapp.h"
#include "nvaddress.h"
#include "remotecomputer.h"
#include "usbforwardingcapability.h"

#include "kanade/managednative.h"

#include <Limelight.h>

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QVariant>

#include <optional>

class NvComputer;

class NvDisplayMode
{
public:
    bool operator==(const NvDisplayMode& other) const
    {
        return width == other.width &&
                height == other.height &&
                refreshRate == other.refreshRate;
    }

    int width;
    int height;
    int refreshRate;
};
Q_DECLARE_TYPEINFO(NvDisplayMode, Q_PRIMITIVE_TYPE);

class GfeHttpResponseException : public std::exception
{
public:
    GfeHttpResponseException(int statusCode, QString message) :
        m_StatusCode(statusCode),
        m_StatusMessage(message.toUtf8())
    {

    }

    const char* what() const throw()
    {
        return m_StatusMessage.constData();
    }

    const char* getStatusMessage() const
    {
        return m_StatusMessage.constData();
    }

    int getStatusCode() const
    {
        return m_StatusCode;
    }

    QString toQString() const
    {
        return QString::fromUtf8(m_StatusMessage) + " (Error " + QString::number(m_StatusCode) + ")";
    }

private:
    int m_StatusCode;
    QByteArray m_StatusMessage;
};

class QtNetworkReplyException : public std::exception
{
public:
    QtNetworkReplyException(QNetworkReply::NetworkError error, QString errorText) :
        m_Error(error),
        m_ErrorText(errorText.toUtf8())
    {

    }

    const char* what() const throw()
    {
        return m_ErrorText.constData();
    }

    const char* getErrorText() const
    {
        return m_ErrorText.constData();
    }

    QNetworkReply::NetworkError getError() const
    {
        return m_Error;
    }

    QString toQString() const
    {
        return QString::fromUtf8(m_ErrorText) + " (Error " + QString::number(m_Error) + ")";
    }

private:
    QNetworkReply::NetworkError m_Error;
    QByteArray m_ErrorText;
};

class NvHTTP : public QObject
{
    Q_OBJECT

public:
    enum NvLogLevel {
        NVLL_NONE,
        NVLL_ERROR,
        NVLL_VERBOSE
    };

    // An injected manager is exclusive to sequential NvHTTP requests on its
    // owning thread. Changing the paired identity discards cached connections.
    explicit NvHTTP(NvAddress address, uint16_t httpsPort, QSslCertificate serverCert, bool useTrueUid = false, QNetworkAccessManager* nam = nullptr, QString uuid = "");

    // Managed (Kanade online) native control client.  The endpoint is not a
    // parameter: it is always the pinned loopback pair from the policy, the
    // HTTPS port is always the locked 47984, redirects are never followed, and
    // every request first asks the shared ManagedNativeGate for permission.
    // There is no address history, no discovery, no UUID merge and no
    // clientname/pairname settings lookup on this path.
    //
    // A managed instance is created from an explicit policy only.  It has no
    // legacy fallback: a missing, dead or invalid gate refuses every call and
    // can never degrade into the unmanaged behaviour.
    explicit NvHTTP(const Kanade::ManagedNativePolicy& policy, QSslCertificate serverCert,
                    QNetworkAccessManager* nam = nullptr);

    explicit NvHTTP(NvComputer* computer, QNetworkAccessManager* nam = nullptr);

    // True when this instance was constructed for the managed path.  Managed
    // instances refuse every host extension below.
    bool isManaged() const { return m_Managed.has_value(); }

    static
    int
    getCurrentGame(QString serverInfo);

    QString
    getServerInfo(NvLogLevel logLevel, bool fastFail = false);

    // Managed-only discovery: HTTPS whenever a pinned certificate is present,
    // HTTP only for the bootstrap/not-paired reply, exact advertised HttpsPort
    // required, no address fallback.  Never used by unmanaged hosts.
    QString
    getManagedServerInfo(NvLogLevel logLevel, bool fastFail);

    // Managed snapshots must carry exactly one canonical HttpsPort equal to the
    // locked 47984.  No fallback on a missing/duplicate/alternate value.
    static
    void
    requireManagedHttpsPort(const QString& serverInfoXml);

    // Managed FIRST-PAIR bootstrap only: the one narrow case where the managed
    // path may read a plaintext `serverinfo` reply.  Requires managed call slot
    // PairCert, no pinned certificate yet, and the pinned loopback endpoint.
    // Rejects everything else; the reply is validated (single canonical
    // HttpsPort) and never retained as host state.
    QString
    getManagedPairingBootstrap(NvLogLevel logLevel = NvLogLevel::NVLL_NONE);

    static
    void
    verifyResponseStatus(QString xml);

    // Managed variant: identical status handling but the host-supplied
    // status_message is never logged or surfaced (it can echo request
    // material).  Thrown messages are fixed strings.
    static
    void
    verifyManagedResponseStatus(QString xml);

    static
    QString
    getXmlString(QString xml,
                 QString tagName);

    static
    QByteArray
    getXmlStringFromHex(QString xml,
                        QString tagName);

    QString
    openConnectionToString(QUrl baseUrl,
                           QString command,
                           QString arguments,
                           int timeoutMs,
                           NvLogLevel logLevel = NvLogLevel::NVLL_VERBOSE);

    UsbForwarding::Capability getUsbForwardingCapability();

    bool
    getAbrCapabilities(int* hostMaxBitrateKbps = nullptr);

    QJsonObject
    configureAbr(bool enabled,
                 int minBitrateKbps,
                 int maxBitrateKbps,
                 QString mode,
                 int timeoutMs = 2000);

    QJsonObject
    sendAbrFeedback(double packetLoss,
                    double rttMs,
                    double decodeFps,
                    int droppedFrames,
                    int currentBitrateKbps,
                    int timeoutMs = 2000);

    void setServerCert(QSslCertificate serverCert);
    void setAddress(NvAddress address);
    void setHttpsPort(uint16_t port);
    void setTrueUid(bool useTrueUid);
    void setHostUuid(QString uuid);

    // Managed path only: moves the policy to the next permitted native call
    // (e.g. ServerInfo -> AppList -> Launch).  Refused on unmanaged instances.
    bool setManagedCall(Kanade::NativeCall call, QString* reasonOut = nullptr);

    NvAddress address();

    QSslCertificate serverCert();

    uint16_t httpPort();

    uint16_t httpsPort();

    static
    QVector<int>
    parseQuad(QString quad);

    void
    quitApp();

    void
    startApp(QString verb,
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
             RemoteStreamConfig &remoteStreamConfig);

    QVector<NvApp>
    getAppList();

    QVariantList
    getDisplays();

    QImage
    getBoxArt(int appId);

    static
    QVector<NvDisplayMode>
    getDisplayModeList(QString serverInfo);

    QUrl m_BaseUrlHttp;
    QUrl m_BaseUrlHttps;
private:
    void
    handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors);

    QNetworkReply*
    openConnection(QUrl baseUrl,
                   QString command,
                   QString arguments,
                   int timeoutMs,
                   NvLogLevel logLevel,
                   qint64 maxResponseBytes = 0);

    QNetworkReply*
    openJsonConnection(QUrl baseUrl,
                       QString command,
                       QJsonObject body,
                       bool post,
                       int timeoutMs,
                       NvLogLevel logLevel);

    QJsonObject
    openJsonConnectionToObject(QUrl baseUrl,
                               QString command,
                               QJsonObject body,
                               bool post,
                               int timeoutMs,
                               NvLogLevel logLevel = NvLogLevel::NVLL_VERBOSE);

    NvAddress m_Address;
    QNetworkAccessManager* m_Nam;
    QSslCertificate m_ServerCert;
    bool m_UseTrueUid;
    QString m_Uuid;
    // Set exactly when the managed constructor was used.  An engaged value with
    // an invalid policy is a hard error, never a downgrade.
    std::optional<Kanade::ManagedNativePolicy> m_Managed;

    // Refuses a managed request whose gate no longer permits it.  Throws, so
    // no byte is written, and never falls back to an unmanaged request.
    void requireManagedPermission(Kanade::NativeCall call) const;
    // True only when a managed instance's policy is fully valid.  Throws when
    // the instance is managed but the policy is not usable.
    bool managedActive() const;
};
