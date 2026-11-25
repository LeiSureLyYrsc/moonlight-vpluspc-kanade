#pragma once

#include "identitymanager.h"
#include "nvcomputer.h"
#include "nvhttp.h"

#include "kanade/managednative.h"

#include <openssl/x509.h>
#include <openssl/evp.h>

#include <optional>

class NvPairingManager
{
public:
    enum PairState
    {
        PAIRED,
        PIN_WRONG,
        FAILED,
        ALREADY_IN_PROGRESS
    };

    explicit NvPairingManager(NvComputer* computer);

    // Managed (Kanade online) pairing.  The native PIN/certificate exchange is
    // reused unchanged: same TLS pinning in NvHTTP, same mutual signatures, same
    // wrong-PIN detection.  The difference is provenance and lifetime:
    //   * the endpoint is the pinned loopback pair from the policy, never a
    //     discovered or historical address;
    //   * every stage asks the shared ManagedNativeGate for PairCert/Pair
    //     permission, so a revoked/expired lease stops the exchange;
    //   * the returned certificate is EPHEMERAL - valid for this run only.  It
    //     is NOT written to QSettings, NOT merged into an NvComputer and must
    //     not be presented as a durable native pin until the installation
    //     isolation work lands;
    //   * no PIN, certificate dump or stage payload is logged.
    explicit NvPairingManager(const Kanade::ManagedNativePolicy& policy,
                              QSslCertificate serverCert);

    ~NvPairingManager();

    PairState
    pair(QString appVersion, QString pin, QSslCertificate& serverCert);

private:
    QByteArray
    generateRandomBytes(int length);

    QByteArray
    saltPin(const QByteArray& salt, QString pin);

    QByteArray
    encrypt(const QByteArray& plaintext, const QByteArray& key);

    QByteArray
    decrypt(const QByteArray& ciphertext, const QByteArray& key);

    QByteArray
    getSignatureFromCert(X509* cert);

    QByteArray
    getSignatureFromPemCert(const QByteArray& certificate);

    bool
    verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& serverCertificate);

    QByteArray
    signMessage(const QByteArray& message);

    // True when this instance was built for the managed path.
    bool isManaged() const { return m_Managed.has_value(); }
    // Refuses a stage whose managed permission is no longer valid.
    void requireManagedPairStage(bool fullExchange);

    NvHTTP m_Http;
    X509* m_Cert;
    EVP_PKEY* m_PrivateKey;
    NvComputer* m_Computer;
    // Engaged only for the managed constructor.  A managed instance never has
    // an NvComputer, so it can never read or write the LAN host store.
    std::optional<Kanade::ManagedNativePolicy> m_Managed;
};
