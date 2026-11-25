#include "kanadehttptransport.h"

#include "kanadeapi.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QUrl>

// See the header for the rationale and the documented cancellation limitation.
// This adapter owns no transport of its own: it re-uses KanadeApi so the bearer
// token exists in exactly one object.
//
// Lifetime and ordering rules implemented here:
//   1. deliver() is ALWAYS queued to this object's thread, so no reply is ever
//      emitted from inside send() (before the session recorded its tag) and no
//      KanadeApi re-entrancy can reach the session mid-call.
//   2. The completion lambda holds a QPointer to this adapter; after
//      destruction the queued call is a no-op instead of a crash.
//   3. m_api is never dereferenced after abortAll()/destruction ordering
//      trouble: send() re-checks it through the same guarded path, and the
//      adapter is always destroyed BEFORE the KanadeApi it borrows (the
//      controller creates the API from a unique_ptr and the transport holds a
//      raw pointer it validates).
//   4. Cancellation records are removed only by their own result, never pruned
//      by tag distance: a stale mutation result must never be delivered.

namespace Kanade {

namespace {

KanadeHttpReply fromApiResult(const KanadeApi::Result& result)
{
    KanadeHttpReply reply;
    switch (result.kind) {
    case KanadeApi::ErrorKind::None:
        reply.error = KanadeHttpReply::Error::None;
        reply.httpStatus = result.httpStatus != 0 ? result.httpStatus : 200;
        if (!result.body.isEmpty()) {
            reply.body = QJsonDocument(result.body).toJson(QJsonDocument::Compact);
        }
        break;
    case KanadeApi::ErrorKind::Timeout:
        reply.error = KanadeHttpReply::Error::Timeout;
        break;
    case KanadeApi::ErrorKind::Tls:
        reply.error = KanadeHttpReply::Error::Tls;
        break;
    case KanadeApi::ErrorKind::Cancelled:
        reply.error = KanadeHttpReply::Error::Aborted;
        break;
    case KanadeApi::ErrorKind::HttpError:
        // A definitive HTTP refusal.  KanadeApi surfaces the parsed
        // detail.code (serverCode) and deliberately does NOT re-expose the raw
        // body, so the adapter rebuilds the ONLY shape the session parses:
        // {"detail":{"code":<code>}}.  No other body text is invented.
        reply.error = KanadeHttpReply::Error::None;
        reply.httpStatus = result.httpStatus;
        if (!result.serverCode.isEmpty()) {
            QJsonObject detail;
            detail.insert(QStringLiteral("code"), result.serverCode);
            QJsonObject root;
            root.insert(QStringLiteral("detail"), detail);
            reply.body = QJsonDocument(root).toJson(QJsonDocument::Compact);
        }
        break;
    default:
        reply.error = KanadeHttpReply::Error::Network;
        break;
    }
    return reply;
}

} // namespace

KanadeApiTransport::KanadeApiTransport(KanadeApi* api, QObject* parent)
    : KanadeHttpTransport(parent)
    , m_api(api)
{
}

void KanadeApiTransport::deliver(quint64 tag, const KanadeHttpReply& reply)
{
    if (m_cancelled.remove(tag)) {
        return;
    }
    if (!m_outstanding.remove(tag)) {
        return; // unknown/aborted tag: never surfaced
    }
    Q_EMIT finished(tag, reply);
}

quint64 KanadeApiTransport::send(const KanadeHttpRequest& request)
{
    const quint64 tag = ++m_nextTag;
    m_outstanding.insert(tag);
    auto refuse = [this, tag] {
        KanadeHttpReply failed;
        failed.error = KanadeHttpReply::Error::Network;
        // Queued: the session may not have recorded this tag yet.
        QMetaObject::invokeMethod(
            this, [this, tag, failed] {
                deliver(tag, failed);
            },
            Qt::QueuedConnection);
        return tag;
    };

    if (m_api == nullptr) {
        return refuse();
    }
    // Exact origin pinning: the attempt's origin must be the API's origin.  A
    // mismatch is refused outright rather than re-pointed, so a stale
    // generation can never send this installation's credential to a new
    // service.
    const QUrl requested(request.origin);
    if (!requested.isValid() || requested.scheme() != QLatin1String("https")
        || !request.path.startsWith(QLatin1String("/v1/")) || requested != m_api->origin()) {
        return refuse();
    }

    // The lambda captures a QPointer, not `this`: an API reply that outlives
    // this adapter resolves to nullptr and does nothing.
    QPointer<KanadeApiTransport> guard(this);
    auto completion = [guard, tag](const KanadeApi::Result& result) {
        const KanadeHttpReply reply = fromApiResult(result);
        if (!guard) {
            return;
        }
        // Always deliver on the adapter's own thread, never re-entrantly.
        QMetaObject::invokeMethod(
            guard.data(),
            [guard, tag, reply] {
                if (guard) {
                    guard->deliver(tag, reply);
                }
            },
            Qt::QueuedConnection);
    };

    // Per-request deadline: KanadeApi applies its own total timeout to every
    // request (kDefaultTimeoutMs = 20 s, or whatever setTimeouts() installed).
    // The session's request.timeoutMs is a caller hint and is NOT re-applied
    // here, so a shorter value would be silently ignored -- the documented
    // worst case is KanadeApi's own 20 s.  Tightening it means configuring the
    // single client, not this adapter.
    if (request.method == "GET") {
        m_api->get(request.path, completion);
    } else if (request.method == "POST") {
        m_api->post(request.path, request.body, /*authenticated=*/true, completion);
    } else if (request.method == "DELETE") {
        m_api->del(request.path, completion);
    } else {
        return refuse();
    }
    return tag;
}

void KanadeApiTransport::abort(quint64 tag)
{
    // Emulated per-tag cancellation: the shared client cannot drop one request
    // without dropping its siblings.  The tag is recorded so a late result is
    // discarded instead of delivered (never a fabricated reply).
    if (m_outstanding.contains(tag) || m_cancelled.contains(tag)) {
        m_cancelled.insert(tag);
        m_outstanding.remove(tag);
    }
}

void KanadeApiTransport::abortAll()
{
    // Mark every outstanding tag before the client aborts them, so no
    // Cancelled result escapes as a delivered reply.
    for (quint64 tag : qAsConst(m_outstanding)) {
        m_cancelled.insert(tag);
    }
    m_outstanding.clear();
    if (m_api != nullptr) {
        m_api->abortAll();
    }
}

} // namespace Kanade
