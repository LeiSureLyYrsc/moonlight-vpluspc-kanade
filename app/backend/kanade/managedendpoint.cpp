#include "managedendpoint.h"

#include <QChar>
#include <QStringList>

// This translation unit validates and stores values only.  It reads no clock,
// performs no I/O, and never constructs a live streaming object.

namespace {

using Kanade::ValidationReason;
using Kanade::ValidationResult;

ValidationResult fail(ValidationReason reason, const char* detail)
{
    ValidationResult result;
    result.reason = reason;
    result.detail = QString::fromLatin1(detail);
    return result;
}

ValidationResult ok()
{
    return ValidationResult{};
}

// Returns the index of the first character that may terminate the authority
// component (path, query or fragment), or -1 when the whole string is
// authority.  Whitespace is rejected earlier, so this cannot split one.
int authorityEnd(const QString& rest)
{
    int cut = -1;
    const QChar markers[] = { QLatin1Char('/'), QLatin1Char('?'), QLatin1Char('#') };
    for (const QChar marker : markers) {
        const int index = rest.indexOf(marker);
        if (index >= 0 && (cut < 0 || index < cut)) {
            cut = index;
        }
    }
    return cut;
}

bool hasForbiddenSpaceOrControl(const QString& text)
{
    for (const QChar ch : text) {
        if (ch.isSpace() || ch.category() == QChar::Other_Control) {
            return true;
        }
    }
    return false;
}

// Strict dotted-quad IPv4.  Returns false for anything that looks numeric but
// is not exactly four 0..255 octets without leading zeros ("1.2.3", "1.2.3.4.5",
// "01.2.3.4", "1.2.3.256" all fail rather than being treated as DNS names).
bool isStrictIpv4Literal(const QString& host)
{
    const QStringList parts = host.split(QLatin1Char('.'));
    if (parts.size() != 4) {
        return false;
    }
    for (const QString& part : parts) {
        if (part.isEmpty() || part.size() > 3) {
            return false;
        }
        for (const QChar ch : part) {
            if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) {
                return false;
            }
        }
        if (part.size() > 1 && part.front() == QLatin1Char('0')) {
            return false;
        }
        bool numberOk = false;
        const int value = part.toInt(&numberOk);
        if (!numberOk || value < 0 || value > 255) {
            return false;
        }
    }
    return true;
}

bool looksNumeric(const QString& host)
{
    for (const QChar ch : host) {
        if (ch != QLatin1Char('.')
            && (ch < QLatin1Char('0') || ch > QLatin1Char('9'))) {
            return false;
        }
    }
    return !host.isEmpty();
}

// Lowercase DNS reg-name: dot-separated labels, each 1..63 chars of [a-z0-9-],
// no leading/trailing hyphen, no trailing dot, total length <= 253.  The
// caller has already lowercased the host, so uppercase input is normalized
// rather than rejected.
bool isDnsRegName(const QString& host)
{
    if (host.isEmpty() || host.size() > 253 || host.endsWith(QLatin1Char('.'))) {
        return false;
    }
    const QStringList labels = host.split(QLatin1Char('.'));
    for (const QString& label : labels) {
        if (label.isEmpty() || label.size() > 63) {
            return false;
        }
        if (label.front() == QLatin1Char('-') || label.back() == QLatin1Char('-')) {
            return false;
        }
        for (const QChar ch : label) {
            const bool alnum = (ch >= QLatin1Char('a') && ch <= QLatin1Char('z'))
                || (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'));
            if (!alnum && ch != QLatin1Char('-')) {
                return false;
            }
        }
    }
    return true;
}

// Splits a bare "host[:port]" (no brackets, no userinfo) in the strict
// canonical shape.  IPv6 literals are rejected: kanadeidentity.h scopes the
// DPAPI store by a canonical origin that cannot contain one, so accepting an
// IPv6 literal here would bind a context that can never authenticate.
ValidationReason splitHostPort(const QString& authority, QString* hostOut,
                               quint16* portOut, bool* hadPort)
{
    if (authority.isEmpty()) {
        return ValidationReason::OriginHostInvalid;
    }
    if (authority.startsWith(QLatin1Char('[')) || authority.contains(QLatin1Char(']'))) {
        return ValidationReason::OriginHostInvalid;
    }

    const int colon = authority.indexOf(QLatin1Char(':'));
    if (colon != authority.lastIndexOf(QLatin1Char(':'))) {
        return ValidationReason::OriginHostInvalid;
    }

    QString host = colon < 0 ? authority : authority.left(colon);
    bool portPresent = false;
    QString portText;
    if (colon >= 0) {
        portPresent = true;
        portText = authority.mid(colon + 1);
    }

    if (host.isEmpty() || host.contains(QLatin1Char('@'))) {
        return ValidationReason::OriginHostInvalid;
    }
    const QString lowered = host.toLower();
    if (looksNumeric(lowered)) {
        if (!isStrictIpv4Literal(lowered)) {
            return ValidationReason::OriginHostInvalid;
        }
    } else if (!isDnsRegName(lowered)) {
        return ValidationReason::OriginHostInvalid;
    }
    *hostOut = lowered;

    if (portPresent) {
        if (portText.isEmpty()) {
            return ValidationReason::OriginPortInvalid; // "host:" is not "no port"
        }
        quint16 port = 0;
        if (!Kanade::ManagedEndpointContext::parseStrictPort(portText, &port)) {
            return ValidationReason::OriginPortInvalid;
        }
        *portOut = port;
    } else {
        *portOut = 0;
    }
    *hadPort = portPresent;
    return ValidationReason::Ok;
}

} // namespace

namespace Kanade {

QString reasonToString(ValidationReason reason)
{
    switch (reason) {
    case ValidationReason::Ok: return QStringLiteral("ok");
    case ValidationReason::OriginEmpty: return QStringLiteral("origin_empty");
    case ValidationReason::OriginNotCanonical: return QStringLiteral("origin_not_canonical");
    case ValidationReason::OriginSchemeNotHttps: return QStringLiteral("origin_scheme_not_https");
    case ValidationReason::OriginUserInfoNotAllowed: return QStringLiteral("origin_userinfo_not_allowed");
    case ValidationReason::OriginHostInvalid: return QStringLiteral("origin_host_invalid");
    case ValidationReason::OriginPortInvalid: return QStringLiteral("origin_port_invalid");
    case ValidationReason::OriginPathNotAllowed: return QStringLiteral("origin_path_not_allowed");
    case ValidationReason::OriginQueryNotAllowed: return QStringLiteral("origin_query_not_allowed");
    case ValidationReason::OriginFragmentNotAllowed: return QStringLiteral("origin_fragment_not_allowed");
    case ValidationReason::HostIdInvalid: return QStringLiteral("host_id_invalid");
    case ValidationReason::GrantIdInvalid: return QStringLiteral("grant_id_invalid");
    case ValidationReason::SessionIdInvalid: return QStringLiteral("session_id_invalid");
    case ValidationReason::ClientInstallationIdInvalid: return QStringLiteral("client_installation_id_invalid");
    case ValidationReason::HostInstallationIdInvalid: return QStringLiteral("host_installation_id_invalid");
    case ValidationReason::ParticipantsNotDistinct: return QStringLiteral("participants_not_distinct");
    case ValidationReason::KeyVersionInvalid: return QStringLiteral("key_version_invalid");
    case ValidationReason::EndpointHostNotPinnedLoopback: return QStringLiteral("endpoint_host_not_pinned_loopback");
    case ValidationReason::EndpointPortNotPinned: return QStringLiteral("endpoint_port_not_pinned");
    case ValidationReason::RtspUrlNotCanonical: return QStringLiteral("rtsp_url_not_canonical");
    case ValidationReason::RtspSchemePlaintextNotAllowed: return QStringLiteral("rtsp_scheme_plaintext_not_allowed");
    case ValidationReason::RtspSchemeNotAllowed: return QStringLiteral("rtsp_scheme_not_allowed");
    case ValidationReason::RtspUserInfoNotAllowed: return QStringLiteral("rtsp_userinfo_not_allowed");
    case ValidationReason::RtspHostNotPinnedLoopback: return QStringLiteral("rtsp_host_not_pinned_loopback");
    case ValidationReason::RtspPortInvalid: return QStringLiteral("rtsp_port_invalid");
    case ValidationReason::RtspPortNotPinned: return QStringLiteral("rtsp_port_not_pinned");
    case ValidationReason::RtspPathNotAllowed: return QStringLiteral("rtsp_path_not_allowed");
    case ValidationReason::RtspQueryNotAllowed: return QStringLiteral("rtsp_query_not_allowed");
    case ValidationReason::RtspFragmentNotAllowed: return QStringLiteral("rtsp_fragment_not_allowed");
    case ValidationReason::LeaseDeadlineInvalid: return QStringLiteral("lease_deadline_invalid");
    case ValidationReason::LeaseClockInvalid: return QStringLiteral("lease_clock_invalid");
    case ValidationReason::LeaseExpired: return QStringLiteral("lease_expired");
    case ValidationReason::LeaseStaleRunGeneration: return QStringLiteral("lease_stale_run_generation");
    case ValidationReason::LeaseSessionMismatch: return QStringLiteral("lease_session_mismatch");
    case ValidationReason::RunGenerationInvalid: return QStringLiteral("run_generation_invalid");
    case ValidationReason::LeaseNotExtended: return QStringLiteral("lease_not_extended");
    }
    return QStringLiteral("unknown");
}

ManagedEndpointContext::ManagedEndpointContext(const QString& apiOrigin,
                                               const QString& hostId,
                                               const QString& grantId,
                                               const QString& sessionId,
                                               const QString& clientInstallationId,
                                               const QString& hostInstallationId,
                                               int clientKeyVersion,
                                               int hostKeyVersion,
                                               quint64 runGeneration,
                                               qint64 confirmedDeadlineMs)
    : m_apiOrigin(apiOrigin)
    , m_hostId(hostId)
    , m_grantId(grantId)
    , m_sessionId(sessionId)
    , m_clientInstallationId(clientInstallationId)
    , m_hostInstallationId(hostInstallationId)
    , m_clientKeyVersion(clientKeyVersion)
    , m_hostKeyVersion(hostKeyVersion)
    , m_runGeneration(runGeneration)
    , m_confirmedDeadlineMs(confirmedDeadlineMs)
{
}

const QString& ManagedEndpointContext::loopbackHost()
{
    static const QString host = QStringLiteral("127.0.0.1");
    return host;
}

const QString& ManagedEndpointContext::expectedRtspUrl()
{
    static const QString url = QStringLiteral("rtspenc://127.0.0.1:48010");
    return url;
}

bool ManagedEndpointContext::parseStrictPort(const QString& text, quint16* out)
{
    if (text.isEmpty() || text.size() > 5) {
        return false;
    }
    if (text.size() > 1 && text.front() == QLatin1Char('0')) {
        return false;
    }
    int value = 0;
    for (const QChar ch : text) {
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) {
            return false;
        }
        value = value * 10 + (ch.unicode() - '0');
        if (value > 65535) {
            return false;
        }
    }
    if (value < 1) {
        return false;
    }
    if (out) {
        *out = static_cast<quint16>(value);
    }
    return true;
}

bool ManagedEndpointContext::isCanonicalUuid4(const QString& id)
{
    if (id.size() != 36) {
        return false;
    }
    for (int i = 0; i < id.size(); ++i) {
        const QChar ch = id.at(i);
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (ch != QLatin1Char('-')) {
                return false;
            }
            continue;
        }
        const bool hex = (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
            || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f'));
        if (!hex) {
            return false;
        }
    }
    if (id.at(14) != QLatin1Char('4')) {
        return false;
    }
    const QChar variant = id.at(19);
    return variant == QLatin1Char('8') || variant == QLatin1Char('9')
        || variant == QLatin1Char('a') || variant == QLatin1Char('b');
}

ValidationResult ManagedEndpointContext::validateApiOrigin(const QString& text,
                                                           QString* canonicalOut)
{
    if (text.isEmpty()) {
        return fail(ValidationReason::OriginEmpty, "origin is empty");
    }
    if (hasForbiddenSpaceOrControl(text) || text.contains(QLatin1Char('%'))
        || text.contains(QLatin1Char('\\'))) {
        return fail(ValidationReason::OriginNotCanonical, "origin is not a literal spelling");
    }
    if (text.size() < 8 || text.left(5).compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0) {
        return fail(ValidationReason::OriginSchemeNotHttps, "origin scheme is not https");
    }
    if (text.mid(5, 3) != QStringLiteral("://")) {
        return fail(ValidationReason::OriginSchemeNotHttps, "origin has no https authority");
    }

    const QString rest = text.mid(8);
    const int cut = authorityEnd(rest);
    const QString authority = cut < 0 ? rest : rest.left(cut);
    const QString tail = cut < 0 ? QString() : rest.mid(cut);

    if (authority.contains(QLatin1Char('@'))) {
        return fail(ValidationReason::OriginUserInfoNotAllowed, "origin must not carry userinfo");
    }

    QString host;
    quint16 port = 0;
    bool hadPort = false;
    const ValidationReason split = splitHostPort(authority, &host, &port, &hadPort);
    if (split != ValidationReason::Ok) {
        return fail(split, split == ValidationReason::OriginPortInvalid
                              ? "origin port is not a strict 1..65535 decimal"
                              : "origin host is not a canonical reg-name or dotted-quad");
    }

    // Fixed order: path, then query, then fragment.
    if (!tail.isEmpty()) {
        if (tail.startsWith(QLatin1Char('/'))) {
            const QString afterSlash = tail.mid(1);
            if (!afterSlash.isEmpty() && !afterSlash.startsWith(QLatin1Char('?'))
                && !afterSlash.startsWith(QLatin1Char('#'))) {
                return fail(ValidationReason::OriginPathNotAllowed,
                            "origin must be bare (only '/' tolerated)");
            }
        } else if (!tail.startsWith(QLatin1Char('?')) && !tail.startsWith(QLatin1Char('#'))) {
            return fail(ValidationReason::OriginPathNotAllowed,
                        "origin must be bare (only '/' tolerated)");
        }
        if (tail.contains(QLatin1Char('?'))) {
            return fail(ValidationReason::OriginQueryNotAllowed, "origin must not carry a query");
        }
        if (tail.contains(QLatin1Char('#'))) {
            return fail(ValidationReason::OriginFragmentNotAllowed,
                        "origin must not carry a fragment");
        }
    }

    if (canonicalOut) {
        QString canonical = QStringLiteral("https://") + host;
        if (hadPort && port != 443) {
            canonical += QLatin1Char(':');
            canonical += QString::number(port);
        }
        *canonicalOut = canonical;
    }
    return ok();
}

ValidationResult ManagedEndpointContext::validateHttpEndpoint(const QString& host, quint16 port)
{
    if (host != loopbackHost()) {
        return fail(ValidationReason::EndpointHostNotPinnedLoopback,
                    "endpoint host is not the pinned loopback");
    }
    if (port != kManagedHttpPort) {
        return fail(ValidationReason::EndpointPortNotPinned,
                    "endpoint port is not the pinned HTTP port");
    }
    return ok();
}

ValidationResult ManagedEndpointContext::validateHttpsEndpoint(const QString& host, quint16 port)
{
    if (host != loopbackHost()) {
        return fail(ValidationReason::EndpointHostNotPinnedLoopback,
                    "endpoint host is not the pinned loopback");
    }
    if (port != kManagedHttpsPort) {
        return fail(ValidationReason::EndpointPortNotPinned,
                    "endpoint port is not the pinned HTTPS port");
    }
    return ok();
}

ValidationResult ManagedEndpointContext::validateRtspUrl(const QString& urlText)
{
    if (urlText.isEmpty() || hasForbiddenSpaceOrControl(urlText)
        || urlText.contains(QLatin1Char('%'))) {
        return fail(ValidationReason::RtspUrlNotCanonical, "rtsp url is not a literal spelling");
    }

    const int separator = urlText.indexOf(QStringLiteral("://"));
    if (separator <= 0) {
        return fail(ValidationReason::RtspUrlNotCanonical, "rtsp url has no scheme separator");
    }
    const QString scheme = urlText.left(separator);
    if (scheme.compare(QStringLiteral("rtsp"), Qt::CaseInsensitive) == 0) {
        return fail(ValidationReason::RtspSchemePlaintextNotAllowed,
                    "plaintext rtsp:// would disable RTSP encryption");
    }
    if (scheme != QStringLiteral("rtspenc")) {
        // Includes "RTSPENC"/"RtspEnc": any other spelling silently falls back
        // to plaintext in the locked common-c, so it is refused outright.
        return fail(ValidationReason::RtspSchemeNotAllowed, "rtsp scheme must be exactly rtspenc");
    }

    const QString rest = urlText.mid(separator + 3);
    const int cut = authorityEnd(rest);
    const QString authority = cut < 0 ? rest : rest.left(cut);
    const QString tail = cut < 0 ? QString() : rest.mid(cut);

    if (authority.contains(QLatin1Char('@'))) {
        return fail(ValidationReason::RtspUserInfoNotAllowed, "rtsp url must not carry userinfo");
    }
    if (authority.startsWith(QLatin1Char('[')) || authority.contains(QLatin1Char(']'))) {
        // IPv6 literal (or malformed bracket): never the pinned numeric IPv4.
        return fail(ValidationReason::RtspHostNotPinnedLoopback,
                    "rtsp host is not the pinned loopback");
    }

    QString host;
    quint16 port = 0;
    bool hadPort = false;
    const ValidationReason split = splitHostPort(authority, &host, &port, &hadPort);
    if (split == ValidationReason::OriginHostInvalid) {
        return fail(ValidationReason::RtspUrlNotCanonical, "rtsp host is not a canonical literal");
    }
    if (split == ValidationReason::OriginPortInvalid) {
        return fail(ValidationReason::RtspPortInvalid, "rtsp port is not a strict 1..65535 decimal");
    }
    if (host != loopbackHost()) {
        return fail(ValidationReason::RtspHostNotPinnedLoopback,
                    "rtsp host is not the pinned loopback");
    }
    if (!hadPort || port != kManagedRtspPort) {
        return fail(ValidationReason::RtspPortNotPinned, "rtsp port is not the pinned 48010");
    }

    if (!tail.isEmpty()) {
        // Exactly the bare URL: no path, no query, no fragment.  common-c
        // derives the RTSP port from the last ':' of the whole URL, so any
        // suffix would change that parse.
        if (tail.startsWith(QLatin1Char('?'))) {
            return fail(ValidationReason::RtspQueryNotAllowed, "rtsp url must not carry a query");
        }
        if (tail.startsWith(QLatin1Char('#'))) {
            return fail(ValidationReason::RtspFragmentNotAllowed,
                        "rtsp url must not carry a fragment");
        }
        return fail(ValidationReason::RtspPathNotAllowed, "rtsp url must not carry a path");
    }

    return ok();
}

std::optional<ManagedEndpointContext>
ManagedEndpointContext::create(const ManagedEndpointSpec& spec,
                               qint64 trustedMonotonicNowMs,
                               ValidationResult& reason)
{
    QString canonicalOrigin;
    reason = validateApiOrigin(spec.apiOrigin, &canonicalOrigin);
    if (!reason.ok()) {
        return std::nullopt;
    }

    if (!isCanonicalUuid4(spec.hostId)) {
        reason = fail(ValidationReason::HostIdInvalid, "host id is not a canonical uuid4");
        return std::nullopt;
    }
    if (!isCanonicalUuid4(spec.grantId)) {
        reason = fail(ValidationReason::GrantIdInvalid, "grant id is not a canonical uuid4");
        return std::nullopt;
    }
    if (!isCanonicalUuid4(spec.sessionId)) {
        reason = fail(ValidationReason::SessionIdInvalid, "session id is not a canonical uuid4");
        return std::nullopt;
    }
    if (!isCanonicalUuid4(spec.clientInstallationId)) {
        reason = fail(ValidationReason::ClientInstallationIdInvalid,
                      "client installation id is not a canonical uuid4");
        return std::nullopt;
    }
    if (!isCanonicalUuid4(spec.hostInstallationId)) {
        reason = fail(ValidationReason::HostInstallationIdInvalid,
                      "host installation id is not a canonical uuid4");
        return std::nullopt;
    }
    if (spec.clientInstallationId == spec.hostInstallationId) {
        reason = fail(ValidationReason::ParticipantsNotDistinct,
                      "client and host installation must be distinct installations");
        return std::nullopt;
    }
    if (spec.clientKeyVersion < 1 || spec.hostKeyVersion < 1) {
        reason = fail(ValidationReason::KeyVersionInvalid, "key versions must be >= 1");
        return std::nullopt;
    }
    if (spec.runGeneration == 0) {
        reason = fail(ValidationReason::RunGenerationInvalid, "run generation must be >= 1");
        return std::nullopt;
    }
    if (trustedMonotonicNowMs < 0) {
        reason = fail(ValidationReason::LeaseClockInvalid, "trusted monotonic clock is unusable");
        return std::nullopt;
    }
    if (spec.confirmedDeadlineMs <= trustedMonotonicNowMs) {
        reason = fail(ValidationReason::LeaseExpired,
                      "confirmed deadline is not strictly in the future");
        return std::nullopt;
    }
    if (spec.confirmedDeadlineMs - trustedMonotonicNowMs > kLeaseTtlCapMs) {
        reason = fail(ValidationReason::LeaseDeadlineInvalid,
                      "confirmed deadline exceeds the locally honoured lease span");
        return std::nullopt;
    }

    reason = ValidationResult{};
    return ManagedEndpointContext(canonicalOrigin, spec.hostId, spec.grantId, spec.sessionId,
                                  spec.clientInstallationId, spec.hostInstallationId,
                                  spec.clientKeyVersion, spec.hostKeyVersion,
                                  spec.runGeneration, spec.confirmedDeadlineMs);
}

ValidationResult
ManagedEndpointContext::checkLeaseGate(qint64 trustedMonotonicNowMs,
                                       quint64 currentRunGeneration) const
{
    if (trustedMonotonicNowMs < 0) {
        return fail(ValidationReason::LeaseClockInvalid, "trusted monotonic clock is unusable");
    }
    if (currentRunGeneration == 0) {
        return fail(ValidationReason::RunGenerationInvalid, "run generation must be >= 1");
    }
    if (currentRunGeneration != m_runGeneration) {
        return fail(ValidationReason::LeaseStaleRunGeneration,
                    "context belongs to a different run generation");
    }
    if (trustedMonotonicNowMs >= m_confirmedDeadlineMs) {
        return fail(ValidationReason::LeaseExpired, "lease deadline has been reached");
    }
    return ok();
}

std::optional<ManagedEndpointContext>
ManagedEndpointContext::renewed(qint64 newDeadlineMs,
                                qint64 trustedMonotonicNowMs,
                                const QString& expectedSessionId,
                                quint64 expectedRunGeneration,
                                ValidationResult& reason) const
{
    if (expectedSessionId != m_sessionId) {
        reason = fail(ValidationReason::LeaseSessionMismatch,
                      "renewal does not name this session");
        return std::nullopt;
    }
    if (expectedRunGeneration == 0) {
        reason = fail(ValidationReason::RunGenerationInvalid, "run generation must be >= 1");
        return std::nullopt;
    }
    if (expectedRunGeneration != m_runGeneration) {
        reason = fail(ValidationReason::LeaseStaleRunGeneration,
                      "renewal is from a different run generation");
        return std::nullopt;
    }
    if (trustedMonotonicNowMs < 0) {
        reason = fail(ValidationReason::LeaseClockInvalid, "trusted monotonic clock is unusable");
        return std::nullopt;
    }
    if (trustedMonotonicNowMs >= m_confirmedDeadlineMs) {
        // The context we would renew FROM has already elapsed locally: a
        // confirmation of any later deadline cannot revive a dead lease.
        reason = fail(ValidationReason::LeaseExpired,
                      "existing lease deadline was already reached");
        return std::nullopt;
    }
    if (newDeadlineMs <= trustedMonotonicNowMs) {
        reason = fail(ValidationReason::LeaseExpired,
                      "renewed deadline is not strictly in the future");
        return std::nullopt;
    }
    if (newDeadlineMs - trustedMonotonicNowMs > kLeaseTtlCapMs) {
        reason = fail(ValidationReason::LeaseDeadlineInvalid,
                      "renewed deadline exceeds the locally honoured lease span");
        return std::nullopt;
    }
    if (newDeadlineMs <= m_confirmedDeadlineMs) {
        // Equal or lower: a replay, an out-of-order reply, or clock confusion.
        // The gate never moves backwards or sideways.
        reason = fail(ValidationReason::LeaseNotExtended,
                      "renewal did not strictly advance the deadline");
        return std::nullopt;
    }

    reason = ValidationResult{};
    return ManagedEndpointContext(m_apiOrigin, m_hostId, m_grantId, m_sessionId,
                                  m_clientInstallationId, m_hostInstallationId,
                                  m_clientKeyVersion, m_hostKeyVersion,
                                  m_runGeneration, newDeadlineMs);
}

} // namespace Kanade
