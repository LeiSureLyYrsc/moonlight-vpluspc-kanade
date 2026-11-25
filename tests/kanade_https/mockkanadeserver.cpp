#include "mockkanadeserver.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslKey>
#include <QSslSocket>
#include <QTimer>

#include <memory>

#include <openssl/evp.h>

namespace {

QByteArray b64decode(const QByteArray& text)
{
    return QByteArray::fromBase64(text, QByteArray::Base64Encoding);
}

// 32/48 deterministic bytes from a label, rendered as unpadded base64url: the
// exact opaque shapes Kanade emits (43 chars for nonces/access tokens, 64 chars
// for refresh tokens).  Deterministic on purpose: reproducible fixtures, no
// random source, and no real secret is ever involved.
QByteArray tokenBytes(const QByteArray& label, int bytes)
{
    QByteArray material;
    int counter = 0;
    while (material.size() < bytes) {
        material += QCryptographicHash::hash(label + QByteArray::number(counter++),
                                             QCryptographicHash::Sha256);
    }
    return material.left(bytes)
        .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

QString canonicalUuid(const QByteArray& seed)
{
    const QByteArray hex = QCryptographicHash::hash(seed, QCryptographicHash::Sha256).toHex();
    return QStringLiteral("%1-%2-%3-%4-%5")
        .arg(QString::fromLatin1(hex.mid(0, 8)), QString::fromLatin1(hex.mid(8, 4)),
             QString::fromLatin1(hex.mid(12, 4)), QString::fromLatin1(hex.mid(16, 4)),
             QString::fromLatin1(hex.mid(20, 12)));
}

QByteArray jsonBytes(const QJsonObject& object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

} // namespace

MockKanadeServer::MockKanadeServer(QObject* parent)
    : QTcpServer(parent)
    , m_userId(canonicalUuid(QByteArrayLiteral("kanade-https test user")))
{
}

bool MockKanadeServer::listenTls(const TestPki::Identity& identity, QString* error)
{
    m_identity = identity;
    // Loopback only, kernel-assigned port: nothing is reachable off-box.
    if (!listen(QHostAddress::LocalHost, 0)) {
        if (error != nullptr) {
            *error = QStringLiteral("could not listen on 127.0.0.1: %1").arg(errorString());
        }
        return false;
    }
    return true;
}

QUrl MockKanadeServer::origin() const
{
    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(QStringLiteral("127.0.0.1"));
    url.setPort(serverPort());
    return url;
}

quint16 MockKanadeServer::port() const
{
    return serverPort();
}

int MockKanadeServer::requestCountFor(const QByteArray& method, const QString& path) const
{
    int count = 0;
    for (const Request& request : m_requests) {
        if (request.method == method && request.path == path) {
            ++count;
        }
    }
    return count;
}

QByteArray MockKanadeServer::lastAuthorization() const
{
    return m_requests.isEmpty() ? QByteArray() : m_requests.last().authorization;
}

int MockKanadeServer::refreshCount() const
{
    return requestCountFor(QByteArrayLiteral("POST"), QStringLiteral("/v1/auth/refresh"));
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void MockKanadeServer::incomingConnection(qintptr descriptor)
{
    auto* socket = new QSslSocket(this);
    if (!socket->setSocketDescriptor(descriptor)) {
        delete socket;
        return;
    }
    ++m_handshakes;
    socket->setLocalCertificate(m_identity.certificate);
    socket->setPrivateKey(m_identity.key);
    // The fixture client presents no certificate, so there is nothing to verify
    // here.  This is a property of the TEST SERVER only: the client's own
    // certificate and hostname verification is never disabled in this lane, which
    // is the point of the untrusted-chain and wrong-host cases.
    socket->setPeerVerifyMode(QSslSocket::VerifyNone);

    auto buffer = std::make_shared<QByteArray>();
    auto handled = std::make_shared<bool>(false);
    connect(socket, &QSslSocket::readyRead, this,
            [this, socket, buffer, handled]() { readFrom(socket, buffer, handled); });
    connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
    connect(socket, &QSslSocket::errorOccurred, socket,
            [socket](QAbstractSocket::SocketError) { socket->deleteLater(); });
    connect(socket, &QSslSocket::encrypted, this, [this, socket, buffer, handled]() {
        // Record what was actually negotiated: the tests assert a real TLS
        // session rather than trusting that the socket object exists.
        m_protocol = socket->sessionProtocol();
        m_cipher = socket->sessionCipher().name();
        if (socket->bytesAvailable() > 0) {
            readFrom(socket, buffer, handled);
        }
    });
    socket->startServerEncryption();
}

void MockKanadeServer::readFrom(QSslSocket* socket, const std::shared_ptr<QByteArray>& buffer,
                                const std::shared_ptr<bool>& handled)
{
    if (*handled) {
        return;
    }
    *buffer += socket->readAll();

    const qsizetype headerEnd = buffer->indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        return;
    }
    const QList<QByteArray> lines = buffer->left(headerEnd).split('\n');

    int contentLength = 0;
    for (const QByteArray& rawLine : lines) {
        const QByteArray line = rawLine.trimmed();
        if (line.toLower().startsWith("content-length:")) {
            contentLength = line.mid(line.indexOf(':') + 1).trimmed().toInt();
        }
    }
    const qsizetype total = headerEnd + 4 + contentLength;
    if (buffer->size() < total) {
        return; // body still in flight
    }

    Request request;
    const QList<QByteArray> requestLine = lines.value(0).trimmed().split(' ');
    if (requestLine.size() < 2) {
        *handled = true;
        socket->disconnectFromHost();
        return;
    }
    request.method = requestLine.at(0);
    request.path = QString::fromUtf8(requestLine.at(1).split('?').first());

    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray line = lines.at(i).trimmed();
        if (line.toLower().startsWith("authorization:")) {
            request.authorization = line.mid(line.indexOf(':') + 1).trimmed();
        }
    }
    const QByteArray body = buffer->mid(headerEnd + 4, contentLength);
    if (!body.isEmpty()) {
        request.body = QJsonDocument::fromJson(body).object();
    }

    *handled = true; // one request per connection: never dispatch twice
    m_requests.append(request);

    int delay = 0;
    if (!m_delayPath.isEmpty() && m_delayPath == request.path) {
        delay = m_delayMs;
        m_delayPath.clear(); // one-shot: later requests answer immediately
        m_delayMs = 0;
    }
    respond(socket, dispatch(request), delay);
}

void MockKanadeServer::respond(QSslSocket* socket, const Reply& reply, int delayMs)
{
    const QByteArray body = reply.hasJsonBody ? jsonBytes(reply.json) : QByteArray();
    QByteArray head = "HTTP/1.1 " + QByteArray::number(reply.status) + " Status\r\n";
    head += "Content-Type: application/json\r\n";
    head += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    head += "Cache-Control: no-store\r\n";
    for (const auto& header : reply.extraHeaders) {
        head += header.first + ": " + header.second + "\r\n";
    }
    head += "Connection: close\r\n\r\n";
    const QByteArray payload = head + body;

    if (delayMs > 0) {
        // The reply is prepared now but written only after the deadline: this is
        // how the late-reply and total-timeout cases are produced deterministically.
        // The client aborts first; writing to a closed socket is harmless, and the
        // timer dies with the socket.
        QTimer::singleShot(delayMs, socket, [socket, payload]() {
            if (socket->state() == QAbstractSocket::ConnectedState) {
                socket->write(payload);
                socket->disconnectFromHost();
            }
        });
        return;
    }
    socket->write(payload);
    socket->disconnectFromHost();
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

MockKanadeServer::Reply MockKanadeServer::dispatch(const Request& request)
{
    // Injected one-shot expiry wins over any route, so a test can force the
    // 401 -> refresh -> retry path on exactly the request it expects.
    if (m_expireCountdown > 0 && !principalFor(request.authorization).isEmpty()) {
        --m_expireCountdown;
        return errorReply(401, QStringLiteral("token_expired"));
    }

    if (request.path == QLatin1String("/v1/auth/login")) {
        if (!m_redirectLoginTo.isEmpty()) {
            Reply redirect;
            redirect.status = 302;
            redirect.hasJsonBody = false;
            redirect.extraHeaders.append(
                {QByteArrayLiteral("Location"), m_redirectLoginTo.toUtf8()});
            m_redirectLoginTo.clear();
            return redirect;
        }
        return handleLogin(request);
    }
    if (request.path == QLatin1String("/v1/auth/me")) {
        return handleMe(request);
    }
    if (request.path == QLatin1String("/v1/installations/challenge")) {
        return handleInstallationChallenge(request);
    }
    if (request.path == QLatin1String("/v1/installations")) {
        return handleInstallations(request);
    }
    if (request.path == QLatin1String("/v1/auth/device-challenge")) {
        return handleDeviceChallenge(request);
    }
    if (request.path == QLatin1String("/v1/auth/device-token")) {
        return handleDeviceToken(request);
    }
    if (request.path == QLatin1String("/v1/auth/refresh")) {
        return handleRefresh(request);
    }
    if (request.path == QLatin1String("/v1/auth/logout")) {
        return handleLogout();
    }
    if (request.path == QLatin1String("/v1/devices")) {
        return handleDevices(request);
    }
    if (request.path == QLatin1String("/v1/pair-requests")) {
        return handleCreatePair(request);
    }

    static const QString kPairPrefix = QStringLiteral("/v1/pair-requests/");
    static const QString kCancelSuffix = QStringLiteral("/cancel");
    static const QString kGrantPrefix = QStringLiteral("/v1/grants/");

    if (request.method == QByteArrayLiteral("POST") && request.path.startsWith(kPairPrefix)
        && request.path.endsWith(kCancelSuffix)) {
        const qsizetype length =
            request.path.size() - kPairPrefix.size() - kCancelSuffix.size();
        return handleCancelPair(request, request.path.mid(kPairPrefix.size(), length));
    }
    if (request.method == QByteArrayLiteral("GET") && request.path.startsWith(kPairPrefix)) {
        return handlePairSnapshot(request, request.path.mid(kPairPrefix.size()));
    }
    if (request.method == QByteArrayLiteral("DELETE") && request.path.startsWith(kGrantPrefix)) {
        return handleRemoveGrant(request, request.path.mid(kGrantPrefix.size()));
    }

    return errorReply(404, QStringLiteral("not_found"));
}

MockKanadeServer::Reply MockKanadeServer::errorReply(int status, const QString& code)
{
    Reply reply;
    reply.status = status;
    reply.json = QJsonObject{
        {QStringLiteral("detail"), QJsonObject{{QStringLiteral("code"), code}}}};
    return reply;
}

// ---------------------------------------------------------------------------
// Token bookkeeping
// ---------------------------------------------------------------------------

QString MockKanadeServer::bearer(const QByteArray& authorization) const
{
    if (!authorization.startsWith("Bearer ")) {
        return QString();
    }
    return QString::fromUtf8(authorization.mid(7)).trimmed();
}

QString MockKanadeServer::principalFor(const QByteArray& authorization) const
{
    return m_accessTokens.value(bearer(authorization));
}

QString MockKanadeServer::issueAccessToken(const QString& principal)
{
    const QString token =
        QStringLiteral("kat_")
        + QString::fromLatin1(tokenBytes(
              QStringLiteral("%1/access/%2").arg(principal).arg(++m_counter).toUtf8(), 32));
    m_accessTokens.insert(token, principal);
    return token;
}

QString MockKanadeServer::issueRefreshToken(const QString& principal)
{
    const QString token =
        QStringLiteral("krt_")
        + QString::fromLatin1(tokenBytes(
              QStringLiteral("%1/refresh/%2").arg(principal).arg(++m_counter).toUtf8(), 48));
    m_refreshTokens.insert(token, principal);
    return token;
}

QString MockKanadeServer::nextId(const char* label)
{
    return canonicalUuid(QByteArray(label) + QByteArray::number(++m_counter));
}

QString MockKanadeServer::nextNonce(const char* label)
{
    return QString::fromLatin1(
        tokenBytes(QByteArray(label) + QByteArray::number(++m_counter), 32));
}

bool MockKanadeServer::verifyProof(const QByteArray& publicKeyB64, const QByteArray& message,
                                   const QByteArray& proofB64)
{
    const QByteArray rawKey = b64decode(publicKeyB64);
    const QByteArray rawSig = b64decode(proofB64);
    if (rawKey.size() != 32 || rawSig.size() != 64 || message.isEmpty()) {
        return false;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(rawKey.constData()), 32);
    if (pkey == nullptr) {
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx != nullptr && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(rawSig.constData()), 64,
                              reinterpret_cast<const unsigned char*>(message.constData()),
                              static_cast<size_t>(message.size()))
            == 1;
    }
    if (ctx != nullptr) {
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// Contract handlers
// ---------------------------------------------------------------------------

MockKanadeServer::Reply MockKanadeServer::handleLogin(const Request& request)
{
    const QString password = request.body.value(QStringLiteral("password")).toString();
    if (request.body.value(QStringLiteral("login")).toString().isEmpty()
        || password != m_loginPassword) {
        return errorReply(401, QStringLiteral("invalid_credentials"));
    }
    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("token_type"), QStringLiteral("Bearer")},
        {QStringLiteral("access_token"), issueAccessToken(QStringLiteral("account"))},
        {QStringLiteral("access_expires_at"),
         double(QDateTime::currentSecsSinceEpoch() + 900)},
        {QStringLiteral("refresh_token"), issueRefreshToken(QStringLiteral("account"))},
        // Account credential: no installation binding (auth.py contract).
        {QStringLiteral("installation"), QJsonValue(QJsonValue::Null)},
        {QStringLiteral("user_id"), m_userId},
    };
    if (m_loginPadding > 0) {
        reply.json.insert(QStringLiteral("padding"), QString(m_loginPadding, QLatin1Char('x')));
        m_loginPadding = 0;
    }
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleMe(const Request& request)
{
    const QString principal = principalFor(request.authorization);
    if (principal.isEmpty()) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    QJsonValue installation = QJsonValue(QJsonValue::Null);
    if (principal == QLatin1String("device")) {
        installation = QJsonObject{
            {QStringLiteral("id"), m_installationId},
            {QStringLiteral("role"), QStringLiteral("client")},
            {QStringLiteral("key_version"), 1},
        };
    }
    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("user"), QJsonObject{{QStringLiteral("id"), m_userId}}},
        {QStringLiteral("installation"), installation},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleInstallationChallenge(const Request& request)
{
    if (principalFor(request.authorization) != QLatin1String("account")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    const QByteArray publicKey =
        request.body.value(QStringLiteral("public_key")).toString().toLatin1();
    if (b64decode(publicKey).size() != 32) {
        return errorReply(422, QStringLiteral("invalid_request"));
    }

    Challenge challenge;
    challenge.id = nextId("challenge");
    challenge.nonce = nextNonce("nonce");
    challenge.expiresAt = QDateTime::currentSecsSinceEpoch() + 120;
    challenge.kind = QStringLiteral("enrollment");
    challenge.publicKey = publicKey;
    // Byte-exact with Kanade security/identity.py: sorted keys, compact
    // separators, "label":null, canonical padded base64 public key.
    challenge.canonicalMessage = QStringLiteral(
        "{\"aud\":\"kanade\",\"challenge_id\":\"%1\",\"expires_at\":%2,\"key_version\":1,"
        "\"label\":null,\"nonce\":\"%3\",\"public_key\":\"%4\",\"role\":\"client\","
        "\"type\":\"kanade.installation.enrollment\",\"user_id\":\"%5\",\"v\":1}")
        .arg(challenge.id)
        .arg(challenge.expiresAt)
        .arg(challenge.nonce, QString::fromLatin1(publicKey), m_userId);
    m_challenges.insert(challenge.id, challenge);

    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("challenge_id"), challenge.id},
        {QStringLiteral("nonce"), challenge.nonce},
        {QStringLiteral("expires_at"), double(challenge.expiresAt)},
        {QStringLiteral("canonical_message"), challenge.canonicalMessage},
        {QStringLiteral("purpose"), QStringLiteral("enrollment")},
        {QStringLiteral("role"), QStringLiteral("client")},
        {QStringLiteral("public_key"), QString::fromLatin1(publicKey)},
        {QStringLiteral("key_version"), 1},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleInstallations(const Request& request)
{
    if (principalFor(request.authorization) != QLatin1String("account")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    const QString challengeId = request.body.value(QStringLiteral("challenge_id")).toString();
    const auto it = m_challenges.constFind(challengeId);
    if (it == m_challenges.constEnd() || it->kind != QLatin1String("enrollment")) {
        return errorReply(409, QStringLiteral("request_conflict"));
    }
    const Challenge challenge = it.value();
    m_challenges.erase(m_challenges.find(challengeId));

    const QByteArray proof = request.body.value(QStringLiteral("proof")).toString().toLatin1();
    if (!verifyProof(challenge.publicKey, challenge.canonicalMessage.toUtf8(), proof)) {
        ++m_proofFailures;
        return errorReply(422, QStringLiteral("invalid_request"));
    }

    const bool firstEnrollment = m_installationId.isEmpty();
    if (firstEnrollment) {
        m_installationId = nextId("installation");
        m_publicKey = challenge.publicKey;
        ++m_enrollmentsCreated;
        m_enrolledKeys.append(QString::fromLatin1(challenge.publicKey));
    }
    else if (m_publicKey != challenge.publicKey) {
        // A second, different key must never replace the enrolled identity.
        return errorReply(409, QStringLiteral("request_conflict"));
    }

    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("installation"),
         QJsonObject{{QStringLiteral("id"), m_installationId},
                     {QStringLiteral("owner_id"), m_userId},
                     {QStringLiteral("role"), QStringLiteral("client")},
                     {QStringLiteral("public_key"), QString::fromLatin1(challenge.publicKey)},
                     {QStringLiteral("key_version"), 1}}},
        {QStringLiteral("created"), firstEnrollment},
        // tokens:null deliberately: the client must fall through to the
        // device-login exchange (the idempotent recovery path).
        {QStringLiteral("tokens"), QJsonValue(QJsonValue::Null)},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleDeviceChallenge(const Request& request)
{
    const QString installationId = request.body.value(QStringLiteral("installation_id")).toString();
    if (installationId != m_installationId || m_publicKey.isEmpty()) {
        return errorReply(404, QStringLiteral("installation_not_found"));
    }

    Challenge challenge;
    challenge.id = nextId("challenge");
    challenge.nonce = nextNonce("nonce");
    challenge.expiresAt = QDateTime::currentSecsSinceEpoch() + 120;
    challenge.kind = QStringLiteral("device_login");
    challenge.publicKey = m_publicKey;
    challenge.canonicalMessage = QStringLiteral(
        "{\"aud\":\"kanade\",\"challenge_id\":\"%1\",\"expires_at\":%2,\"installation_id\":\"%3\","
        "\"nonce\":\"%4\",\"role\":\"client\",\"type\":\"kanade.device.login\","
        "\"user_id\":\"%5\",\"v\":1}")
        .arg(challenge.id)
        .arg(challenge.expiresAt)
        .arg(m_installationId, challenge.nonce, m_userId);
    m_challenges.insert(challenge.id, challenge);

    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("challenge_id"), challenge.id},
        {QStringLiteral("nonce"), challenge.nonce},
        {QStringLiteral("expires_at"), double(challenge.expiresAt)},
        {QStringLiteral("canonical_message"), challenge.canonicalMessage},
        {QStringLiteral("purpose"), QStringLiteral("device_login")},
        {QStringLiteral("role"), QStringLiteral("client")},
        {QStringLiteral("installation_id"), m_installationId},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleDeviceToken(const Request& request)
{
    const QString challengeId = request.body.value(QStringLiteral("challenge_id")).toString();
    const auto it = m_challenges.constFind(challengeId);
    if (it == m_challenges.constEnd() || it->kind != QLatin1String("device_login")) {
        return errorReply(409, QStringLiteral("request_conflict"));
    }
    const Challenge challenge = it.value();
    m_challenges.erase(m_challenges.find(challengeId));

    const QByteArray proof = request.body.value(QStringLiteral("proof")).toString().toLatin1();
    if (!verifyProof(challenge.publicKey, challenge.canonicalMessage.toUtf8(), proof)) {
        ++m_proofFailures;
        return errorReply(422, QStringLiteral("invalid_request"));
    }

    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("token_type"), QStringLiteral("Bearer")},
        {QStringLiteral("access_token"), issueAccessToken(QStringLiteral("device"))},
        {QStringLiteral("access_expires_at"),
         double(QDateTime::currentSecsSinceEpoch() + 900)},
        {QStringLiteral("refresh_token"), issueRefreshToken(QStringLiteral("device"))},
        {QStringLiteral("installation"),
         QJsonObject{{QStringLiteral("id"), m_installationId},
                     {QStringLiteral("role"), QStringLiteral("client")}}},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleRefresh(const Request& request)
{
    const QString presented = request.body.value(QStringLiteral("refresh_token")).toString();
    const QString principal = m_refreshTokens.value(presented);
    if (principal.isEmpty() || m_failRefresh) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    // Rotation: a presented refresh token is single-use.
    m_refreshTokens.remove(presented);
    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("token_type"), QStringLiteral("Bearer")},
        {QStringLiteral("access_token"), issueAccessToken(principal)},
        {QStringLiteral("access_expires_at"),
         double(QDateTime::currentSecsSinceEpoch() + 900)},
        {QStringLiteral("refresh_token"), issueRefreshToken(principal)},
    };
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleLogout()
{
    Reply reply;
    reply.json = QJsonObject{{QStringLiteral("ok"), true}};
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleDevices(const Request& request)
{
    if (principalFor(request.authorization).isEmpty()) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    QJsonArray devices;
    for (const QJsonObject& grant : m_grants) {
        devices.append(grant);
    }
    Reply reply;
    reply.json = QJsonObject{
        {QStringLiteral("current_installation_id"), m_installationId},
        {QStringLiteral("devices"), devices},
        {QStringLiteral("hosts"), QJsonArray()},
    };
    return reply;
}

QJsonObject MockKanadeServer::snapshotFor(const PairState& pair) const
{
    return QJsonObject{
        {QStringLiteral("id"), pair.id},
        {QStringLiteral("state"), pair.state},
        {QStringLiteral("method"), pair.method},
        {QStringLiteral("device_code"), pair.deviceCode},
        {QStringLiteral("expires_at"), double(QDateTime::currentSecsSinceEpoch() + 120)},
    };
}

void MockKanadeServer::createGrant(const QString& deviceCode)
{
    m_grants.append(QJsonObject{
        {QStringLiteral("grant_id"), nextId("grant")},
        {QStringLiteral("client_installation_id"), m_installationId},
        {QStringLiteral("host_id"), nextId("host")},
        {QStringLiteral("host_display_name"), QStringLiteral("Synthetic host")},
        {QStringLiteral("connection_state"), QStringLiteral("unknown")},
        {QStringLiteral("native_pairing"), QStringLiteral("unknown")},
        {QStringLiteral("device_code"), deviceCode},
    });
}

MockKanadeServer::Reply MockKanadeServer::handleCreatePair(const Request& request)
{
    if (principalFor(request.authorization) != QLatin1String("device")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }

    const QString idempotencyKey =
        request.body.value(QStringLiteral("idempotency_key")).toString();
    // Replay the stored outcome for this key WITHOUT re-running the password
    // check, like the real service.  The client relies on this after an ambiguous
    // failure and must not mint a second request.
    const auto replay = m_idempotentReplies.constFind(idempotencyKey);
    if (!idempotencyKey.isEmpty() && replay != m_idempotentReplies.constEnd()) {
        ++m_idempotentReplays;
        Reply reply;
        reply.json = replay.value();
        return reply;
    }

    const QString method = request.body.value(QStringLiteral("method")).toString();
    const QString code = request.body.value(QStringLiteral("device_code")).toString();

    if (m_denyNextPair) {
        m_denyNextPair = false;
        return errorReply(403, QStringLiteral("pair_unavailable"));
    }
    if (method == QLatin1String("password")
        && request.body.value(QStringLiteral("password")).toString() != m_pairPassword) {
        return errorReply(403, QStringLiteral("pair_unavailable"));
    }
    if (method != QLatin1String("password") && method != QLatin1String("confirm")) {
        return errorReply(422, QStringLiteral("invalid_request"));
    }

    PairState pair;
    pair.id = nextId("pair");
    pair.method = method;
    pair.deviceCode = code;
    // "password" is approved by the password check itself, so the grant is issued
    // immediately; "confirm" waits for the host decision.
    pair.state = method == QLatin1String("password") ? QStringLiteral("approved")
                                                     : QStringLiteral("pending");
    m_pairs.insert(pair.id, pair);
    m_lastPairId = pair.id;
    if (pair.state == QLatin1String("approved")) {
        createGrant(code);
    }

    const QJsonObject snapshot = snapshotFor(pair);
    if (!idempotencyKey.isEmpty()) {
        m_idempotentReplies.insert(idempotencyKey, snapshot);
    }
    Reply reply;
    reply.json = snapshot;
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handlePairSnapshot(const Request& request,
                                                             const QString& requestId)
{
    if (principalFor(request.authorization) != QLatin1String("device")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    auto it = m_pairs.find(requestId);
    if (it == m_pairs.end()) {
        return errorReply(404, QStringLiteral("not_found"));
    }
    Reply reply;
    reply.json = snapshotFor(it.value());
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleCancelPair(const Request& request,
                                                           const QString& requestId)
{
    if (principalFor(request.authorization) != QLatin1String("device")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    auto it = m_pairs.find(requestId);
    if (it == m_pairs.end()) {
        return errorReply(404, QStringLiteral("not_found"));
    }
    if (it->state != QLatin1String("pending")) {
        // The host already decided; a cancel cannot undo it and must never be
        // reported as having succeeded.
        return errorReply(409, QStringLiteral("request_conflict"));
    }
    it->state = QStringLiteral("cancelled");
    Reply reply;
    reply.json = snapshotFor(it.value());
    return reply;
}

MockKanadeServer::Reply MockKanadeServer::handleRemoveGrant(const Request& request,
                                                            const QString& grantId)
{
    if (principalFor(request.authorization) != QLatin1String("device")) {
        return errorReply(401, QStringLiteral("token_invalid"));
    }
    for (int i = 0; i < m_grants.size(); ++i) {
        if (m_grants.at(i).value(QStringLiteral("grant_id")).toString() == grantId) {
            m_grants.removeAt(i);
            Reply reply;
            reply.json = QJsonObject{{QStringLiteral("ok"), true}};
            return reply;
        }
    }
    return errorReply(404, QStringLiteral("not_found"));
}

void MockKanadeServer::approvePendingPair()
{
    const auto it = m_pairs.find(m_lastPairId);
    if (it != m_pairs.end() && it->state == QLatin1String("pending")) {
        it->state = QStringLiteral("approved");
        createGrant(it->deviceCode);
    }
}

QJsonObject MockKanadeServer::lastPairSnapshot() const
{
    const auto it = m_pairs.constFind(m_lastPairId);
    return it == m_pairs.constEnd() ? QJsonObject() : snapshotFor(it.value());
}
