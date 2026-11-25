#pragma once

#ifndef KANADE_HTTPS_MOCKKANADESERVER_H
#define KANADE_HTTPS_MOCKKANADESERVER_H

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QSsl>
#include <QString>
#include <QStringList>
#include <QTcpServer>
#include <QUrl>

#include <memory>

#include "testpki.h"

class QSslSocket;

// A scripted, in-process Kanade control-plane server speaking real HTTPS over
// 127.0.0.1 on an ephemeral port.
//
// It implements only the P1 REST surface the client uses, with fixed synthetic
// identifiers and opaque tokens that satisfy the client's syntax checks.  It
// VERIFIES Ed25519 enrollment / device-login proofs server-side (OpenSSL), so a
// client that signs the wrong bytes is rejected instead of granted tokens.
// It also rotates refresh tokens and replays stored outcomes for a repeated
// idempotency key without re-checking the password, like the real service.
//
// Nothing here is a real account, host, certificate or service, and the server
// only ever binds 127.0.0.1 on a kernel-assigned port.
class MockKanadeServer : public QTcpServer
{
public:
    struct Request {
        QByteArray method;
        QString path;
        QByteArray authorization;
        QJsonObject body;
    };

    explicit MockKanadeServer(QObject* parent = nullptr);

    // Real TLS on 127.0.0.1 with the supplied fixture identity.  The server does
    // not request a client certificate (the client has none); that does not
    // relax the CLIENT's verification, which stays enabled.
    bool listenTls(const TestPki::Identity& identity, QString* error);

    QUrl origin() const;
    quint16 port() const;

    // ---- observations ----------------------------------------------------
    const QList<Request>& requests() const { return m_requests; }
    int requestCount() const { return int(m_requests.size()); }
    int requestCountFor(const QByteArray& method, const QString& path) const;
    QByteArray lastAuthorization() const;
    int handshakeCount() const { return m_handshakes; }
    int proofFailures() const { return m_proofFailures; }
    int enrollmentsCreated() const { return m_enrollmentsCreated; }
    int idempotentReplays() const { return m_idempotentReplays; }
    int refreshCount() const;
    QString installationId() const { return m_installationId; }
    QString userId() const { return m_userId; }
    int grantCount() const { return int(m_grants.size()); }
    QSsl::SslProtocol negotiatedProtocol() const { return m_protocol; }
    QString negotiatedCipher() const { return m_cipher; }
    QJsonObject lastPairSnapshot() const;

    // ---- synthetic server-side expectations ------------------------------
    void setLoginPassword(const QString& password) { m_loginPassword = password; }
    void setPairPassword(const QString& password) { m_pairPassword = password; }
    QString loginPassword() const { return m_loginPassword; }
    QString pairPassword() const { return m_pairPassword; }

    // ---- fault injection (each hook is one-shot where it matters) --------
    void redirectNextLoginTo(const QString& location) { m_redirectLoginTo = location; }
    void failRefresh() { m_failRefresh = true; }
    void delayPath(const QString& path, int milliseconds)
    {
        m_delayPath = path;
        m_delayMs = milliseconds;
    }
    void expireNextAuthenticatedRequest() { m_expireCountdown = 1; }
    void denyNextPair() { m_denyNextPair = true; }
    // Pads the JSON login reply with a large harmless string so the client's
    // body bound can be exercised without a second endpoint.
    void setLoginPadding(int bytes) { m_loginPadding = bytes; }
    // Completes a pending "confirm" pair out of band, so the next poll sees the
    // host decision without waiting for the model's poll counter.
    void approvePendingPair();

protected:
    void incomingConnection(qintptr descriptor) override;

private:
    struct Reply {
        int status = 200;
        QJsonObject json;
        bool hasJsonBody = true;
        QList<QPair<QByteArray, QByteArray>> extraHeaders;
    };

    struct PairState {
        QString id;
        QString method;
        QString deviceCode;
        QString state; // pending / approved / cancelled
    };

    struct Challenge {
        QString id;
        QString nonce;
        qint64 expiresAt = 0;
        QString kind; // enrollment / device_login
        QByteArray publicKey;
        QString canonicalMessage;
    };

    void readFrom(QSslSocket* socket, const std::shared_ptr<QByteArray>& buffer,
                  const std::shared_ptr<bool>& handled);
    void respond(QSslSocket* socket, const Reply& reply, int delayMs);
    Reply dispatch(const Request& request);
    static Reply errorReply(int status, const QString& code);

    Reply handleLogin(const Request& request);
    Reply handleMe(const Request& request);
    Reply handleInstallationChallenge(const Request& request);
    Reply handleInstallations(const Request& request);
    Reply handleDeviceChallenge(const Request& request);
    Reply handleDeviceToken(const Request& request);
    Reply handleRefresh(const Request& request);
    Reply handleLogout();
    Reply handleDevices(const Request& request);
    Reply handleCreatePair(const Request& request);
    Reply handlePairSnapshot(const Request& request, const QString& requestId);
    Reply handleCancelPair(const Request& request, const QString& requestId);
    Reply handleRemoveGrant(const Request& request, const QString& grantId);

    QString bearer(const QByteArray& authorization) const;
    QString principalFor(const QByteArray& authorization) const;
    QString issueAccessToken(const QString& principal);
    QString issueRefreshToken(const QString& principal);
    QString nextId(const char* label);
    QString nextNonce(const char* label);
    bool verifyProof(const QByteArray& publicKeyB64, const QByteArray& message,
                     const QByteArray& proofB64);

    QJsonObject snapshotFor(const PairState& pair) const;
    void createGrant(const QString& deviceCode);

    TestPki::Identity m_identity;
    QList<Request> m_requests;

    QHash<QString, QString> m_accessTokens;  // token -> principal
    QHash<QString, QString> m_refreshTokens; // token -> principal
    QString m_userId;
    QString m_installationId;
    QByteArray m_publicKey;
    QStringList m_enrolledKeys;

    QHash<QString, PairState> m_pairs;
    QHash<QString, QJsonObject> m_idempotentReplies; // key -> stored snapshot
    QList<QJsonObject> m_grants;
    QString m_lastPairId;
    QHash<QString, Challenge> m_challenges;

    QString m_loginPassword = QStringLiteral("correct horse battery staple");
    QString m_pairPassword = QStringLiteral("host-password");

    QString m_redirectLoginTo;
    bool m_failRefresh = false;
    QString m_delayPath;
    int m_delayMs = 0;
    int m_expireCountdown = 0;
    bool m_denyNextPair = false;
    int m_loginPadding = 0;

    int m_handshakes = 0;
    int m_proofFailures = 0;
    int m_enrollmentsCreated = 0;
    int m_idempotentReplays = 0;
    int m_counter = 0;
    QSsl::SslProtocol m_protocol = QSsl::UnknownProtocol;
    QString m_cipher;
};

#endif // KANADE_HTTPS_MOCKKANADESERVER_H
