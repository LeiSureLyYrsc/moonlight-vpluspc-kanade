#pragma once

#ifndef KANADE_HTTPS_TESTPKI_H
#define KANADE_HTTPS_TESTPKI_H

#include <QByteArray>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>

// Throwaway TLS material for the kanade_https lane.
//
// Everything here is generated at RUN TIME and exists only in memory: no PEM
// file, no private key and no certificate is checked into the repository,
// written to disk, or installed into the OS trust store.  The client under test
// receives only `trustedAuthority` through an injected QSslConfiguration; the
// process-wide default configuration and the system store are never modified.
//
// The three leaf identities exist so the lane can prove both directions of
// certificate verification:
//   * trustedServer   - signed by trustedAuthority, SAN IP:127.0.0.1
//   * untrustedServer - signed by an authority the client does NOT trust
//   * wrongHostServer - signed by trustedAuthority but SAN DNS:kanade.invalid
//                       only, so connecting to 127.0.0.1 must fail the hostname
//                       check (verification is never disabled)
//
// Only the leaf is presented by the fixture server: the client already holds the
// issuing root as its sole CA, so chain building needs no intermediate.
namespace TestPki {

struct Identity {
    QSslCertificate certificate;
    QSslKey key;
};

struct Material {
    QSslCertificate trustedAuthority;
    QSslCertificate untrustedAuthority;
    Identity trustedServer;
    Identity untrustedServer;
    Identity wrongHostServer;
};

// Generates the two authorities and all three leaves.  Returns false and sets
// *error (fixed operator text, never key material) when any object cannot be
// built.
bool generate(Material& material, QString* error);

} // namespace TestPki

#endif // KANADE_HTTPS_TESTPKI_H
