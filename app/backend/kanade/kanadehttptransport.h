#pragma once

#ifndef KANADEHTTPTRANSPORT_H
#define KANADEHTTPTRANSPORT_H

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QSet>

#include "kanadesession.h"

class KanadeApi;

// KanadeHttpTransport adapter over KanadeApi (control plane only).
//
// Rationale: the bearer token must live in exactly ONE place (KanadeApi), so
// this adapter never sees it -- it re-uses KanadeApi's hardened sender rather
// than opening a second network stack.  Consequences, stated explicitly:
//
//   * Origin pinning is enforced here: a request whose origin is not the
//     KanadeApi origin is REFUSED (delivered as a Network error for that tag)
//     and never re-pointed.  A stale attempt therefore cannot reach a new
//     origin.
//   * Redirect / cookie / TLS policy is KanadeApi's (never followed, never
//     stored, never relaxed).
//   * Every result is delivered through the event loop, never synchronously
//     from inside send().  KanadeApi can answer immediately (no token yet, bad
//     origin), and a synchronous signal would reach KanadeSession before it has
//     recorded the in-flight tag, i.e. the reply would be dropped and the
//     attempt would hang.  Queueing removes that whole class of race.
//   * Completion lambdas hold a QPointer to this adapter, so a late reply after
//     this object is gone is inert rather than a use-after-free.
//   * Per-tag cancellation is emulated: abort() records the tag so the eventual
//     result is discarded instead of delivered.  The underlying HTTP request may
//     still complete in the background; the session treats an aborted mutation
//     as an UNKNOWN outcome, never replays it, and classifies it with a scoped
//     read-only request.  A cancellation record is only ever cleared when its
//     own result arrives (or on destruction), never by guessing that old tags
//     are harmless: a dropped "old" mutation is exactly what must not happen.
namespace Kanade {

class KanadeApiTransport : public KanadeHttpTransport {
    Q_OBJECT
public:
    explicit KanadeApiTransport(KanadeApi* api, QObject* parent = nullptr);

    quint64 send(const KanadeHttpRequest& request) override;
    void abort(quint64 tag) override;

    // Drops every outstanding tag without delivering (used on logout / origin
    // switch).  The owning KanadeApi is asked to abort its own replies too.
    void abortAll();

private:
    void deliver(quint64 tag, const KanadeHttpReply& reply);

    KanadeApi* m_api;
    quint64 m_nextTag = 0;
    QSet<quint64> m_cancelled;
    QSet<quint64> m_outstanding;
};

} // namespace Kanade

#endif // KANADEHTTPTRANSPORT_H
