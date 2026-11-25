#include "testpki.h"

#include <QByteArray>

#include <memory>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

constexpr int kRsaBits = 2048;
constexpr long kNotBeforeOffsetSeconds = -3600; // tolerate clock skew
constexpr long kValiditySeconds = 24 * 60 * 60;

struct PkeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct X509Deleter {
    void operator()(X509* cert) const { X509_free(cert); }
};
struct ExtDeleter {
    void operator()(X509_EXTENSION* extension) const { X509_EXTENSION_free(extension); }
};
struct BioDeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};
struct CtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using ExtPtr = std::unique_ptr<X509_EXTENSION, ExtDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using KeygenCtxPtr = std::unique_ptr<EVP_PKEY_CTX, CtxDeleter>;

void setError(QString* error, const char* what)
{
    if (error != nullptr) {
        *error = QString::fromLatin1(what);
    }
}

// Adds one extension whose value is written in OpenSSL's config language (e.g.
// "critical,CA:FALSE"), scoped to this certificate.  No config file, no
// database, no environment lookups.
bool addExtension(X509* cert, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ExtPtr extension(X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value));
    if (!extension) {
        return false;
    }
    return X509_add_ext(cert, extension.get(), -1) == 1;
}

PkeyPtr generateRsaKey()
{
    KeygenCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        return PkeyPtr();
    }
    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) != 1
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), kRsaBits) != 1
        || EVP_PKEY_keygen(ctx.get(), &rawKey) != 1) {
        return PkeyPtr();
    }
    return PkeyPtr(rawKey);
}

// Builds and self-signs (authorities) or CA-signs (leaves) one certificate.
// `commonName` is only a label; leaf identity is decided by the SAN list, which
// is what OpenSSL/Qt actually verify.
X509Ptr makeCertificate(EVP_PKEY* subjectKey, const QString& commonName,
                        const QByteArray& subjectAltName, bool isAuthority,
                        X509* issuerCert, EVP_PKEY* issuerKey)
{
    X509Ptr cert(X509_new());
    if (!cert) {
        return X509Ptr();
    }
    // Deterministic serial derived from the label: reproducible fixtures without
    // a random source dependency.
    unsigned long serial = 1;
    for (const char byte : commonName.toUtf8()) {
        serial = serial * 131u + static_cast<unsigned char>(byte);
    }
    if (serial == 0) {
        serial = 1;
    }
    if (X509_set_version(cert.get(), 2) != 1) {
        return X509Ptr();
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(serial));
    if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), kNotBeforeOffsetSeconds) == nullptr
        || X509_gmtime_adj(X509_getm_notAfter(cert.get()), kValiditySeconds) == nullptr) {
        return X509Ptr();
    }
    if (X509_set_pubkey(cert.get(), subjectKey) != 1) {
        return X509Ptr();
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (subject == nullptr
        || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                      reinterpret_cast<const unsigned char*>(
                                          commonName.toUtf8().constData()),
                                      -1, -1, 0)
               != 1) {
        return X509Ptr();
    }
    if (issuerCert == nullptr) {
        if (X509_set_issuer_name(cert.get(), subject) != 1) {
            return X509Ptr();
        }
    }
    else if (X509_set_issuer_name(cert.get(), X509_get_subject_name(issuerCert)) != 1) {
        return X509Ptr();
    }

    if (!addExtension(cert.get(), NID_basic_constraints,
                      isAuthority ? "critical,CA:TRUE" : "critical,CA:FALSE")) {
        return X509Ptr();
    }
    // keyCertSign on authorities, digitalSignature on leaves; the latter is all
    // an RSA leaf needs with TLS 1.3 / ECDHE.  EKU serverAuth keeps the leaf
    // unambiguous.
    if (!addExtension(cert.get(), NID_key_usage,
                      isAuthority ? "critical,keyCertSign,cRLSign"
                                  : "critical,digitalSignature")) {
        return X509Ptr();
    }
    if (!isAuthority && !addExtension(cert.get(), NID_ext_key_usage, "serverAuth")) {
        return X509Ptr();
    }
    if (!subjectAltName.isEmpty()
        && !addExtension(cert.get(), NID_subject_alt_name, subjectAltName.constData())) {
        return X509Ptr();
    }
    if (!addExtension(cert.get(), NID_subject_key_identifier, "hash")) {
        return X509Ptr();
    }

    EVP_PKEY* signingKey = issuerKey != nullptr ? issuerKey : subjectKey;
    if (X509_sign(cert.get(), signingKey, EVP_sha256()) == 0) {
        return X509Ptr();
    }
    return cert;
}

QByteArray memoryPem(BIO* bio)
{
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    if (memory == nullptr || memory->data == nullptr) {
        return QByteArray();
    }
    return QByteArray(memory->data, static_cast<int>(memory->length));
}

// PEM text held ONLY in memory for the lifetime of this process.  It is never
// written to a file, never committed, and never installed as system trust.
// (The repo's checked-in fixture PEMs are deliberately not reused here.)
QByteArray certificatePem(X509* cert)
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) {
        return QByteArray();
    }
    return memoryPem(bio.get());
}

QSslCertificate toQtCertificate(X509* cert)
{
    const QByteArray pem = certificatePem(cert);
    return pem.isEmpty() ? QSslCertificate() : QSslCertificate(pem, QSsl::Pem);
}

QSslKey toQtKey(EVP_PKEY* key)
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio
        || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return QSslKey();
    }
    const QByteArray pem = memoryPem(bio.get());
    return pem.isEmpty() ? QSslKey() : QSslKey(pem, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
}

} // namespace

namespace TestPki {

bool generate(Material& material, QString* error)
{
    material = Material();
    if (OPENSSL_init_crypto(0, nullptr) != 1) {
        setError(error, "OpenSSL initialization failed");
        return false;
    }

    PkeyPtr trustedCaKey = generateRsaKey();
    PkeyPtr untrustedCaKey = generateRsaKey();
    PkeyPtr trustedLeafKey = generateRsaKey();
    PkeyPtr untrustedLeafKey = generateRsaKey();
    PkeyPtr wrongHostLeafKey = generateRsaKey();
    if (!trustedCaKey || !untrustedCaKey || !trustedLeafKey || !untrustedLeafKey
        || !wrongHostLeafKey) {
        setError(error, "could not generate RSA keys");
        return false;
    }

    X509Ptr trustedCa = makeCertificate(trustedCaKey.get(),
                                        QStringLiteral("kanade-https test trusted CA"),
                                        QByteArray(), /*isAuthority=*/true, nullptr, nullptr);
    X509Ptr untrustedCa = makeCertificate(untrustedCaKey.get(),
                                          QStringLiteral("kanade-https test untrusted CA"),
                                          QByteArray(), /*isAuthority=*/true, nullptr, nullptr);
    X509Ptr trustedLeaf = makeCertificate(trustedLeafKey.get(),
                                          QStringLiteral("kanade-https test server"),
                                          QByteArrayLiteral("IP:127.0.0.1"),
                                          /*isAuthority=*/false, trustedCa.get(),
                                          trustedCaKey.get());
    X509Ptr untrustedLeaf = makeCertificate(untrustedLeafKey.get(),
                                            QStringLiteral("kanade-https test server"),
                                            QByteArrayLiteral("IP:127.0.0.1"),
                                            /*isAuthority=*/false, untrustedCa.get(),
                                            untrustedCaKey.get());
    X509Ptr wrongHostLeaf = makeCertificate(wrongHostLeafKey.get(),
                                            QStringLiteral("kanade.invalid"),
                                            QByteArrayLiteral("DNS:kanade.invalid"),
                                            /*isAuthority=*/false, trustedCa.get(),
                                            trustedCaKey.get());
    if (!trustedCa || !untrustedCa || !trustedLeaf || !untrustedLeaf || !wrongHostLeaf) {
        setError(error, "could not build certificates");
        return false;
    }

    material.trustedAuthority = toQtCertificate(trustedCa.get());
    material.untrustedAuthority = toQtCertificate(untrustedCa.get());
    material.trustedServer =
        Identity{toQtCertificate(trustedLeaf.get()), toQtKey(trustedLeafKey.get())};
    material.untrustedServer =
        Identity{toQtCertificate(untrustedLeaf.get()), toQtKey(untrustedLeafKey.get())};
    material.wrongHostServer =
        Identity{toQtCertificate(wrongHostLeaf.get()), toQtKey(wrongHostLeafKey.get())};

    if (material.trustedAuthority.isNull() || material.untrustedAuthority.isNull()
        || material.trustedServer.certificate.isNull() || material.trustedServer.key.isNull()
        || material.untrustedServer.certificate.isNull() || material.untrustedServer.key.isNull()
        || material.wrongHostServer.certificate.isNull()
        || material.wrongHostServer.key.isNull()) {
        setError(error, "TLS material did not convert to Qt objects");
        return false;
    }
    return true;
}

} // namespace TestPki
