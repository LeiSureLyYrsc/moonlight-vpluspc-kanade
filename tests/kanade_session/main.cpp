#include "backend/kanade/kanadesession.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QtTest>

// Regression tests for the Kanade client session state machine.
//
// No network, no credentials, no live server: a fake transport records every
// request and replies synchronously.  The clocks are injected, so lease
// behaviour is deterministic.  The test's Harness plays the "controller"
// role and captures every request it would have sent.

namespace {

constexpr qint64 kServerTime = 1000000000;

void require(bool condition, const char* message)
{
    // A harness misconfiguration is a test bug, not a product failure.
    if (!condition) {
        qFatal("kanade_session test harness: %s", message);
    }
}

const QString kGrantA = QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
const QString kGrantB = QStringLiteral("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
const QString kHostId = QStringLiteral("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
const QString kOtherHostId = QStringLiteral("99999999-9999-4999-8999-999999999999");
const QString kSessionId = QStringLiteral("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
const QString kClientInst = QStringLiteral("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
const QString kHostInst = QStringLiteral("ffffffff-ffff-4fff-9fff-ffffffffffff");
const QString kOtherHostInst = QStringLiteral("12121212-1212-4212-8212-121212121212");
const QString kOrigin = QStringLiteral("https://kanade.example");

class FakeTransport : public Kanade::KanadeHttpTransport {
public:
    quint64 send(const Kanade::KanadeHttpRequest& request) override
    {
        requests.append(request);
        aborted.append(false);
        return ++m_nextTag;
    }

    void abort(quint64 tag) override
    {
        aborts.append(tag);
        if (tag >= 1 && tag <= static_cast<quint64>(aborted.size())) {
            aborted[int(tag) - 1] = true;
        }
    }

    void deliver(quint64 tag, const Kanade::KanadeHttpReply& reply)
    {
        Q_EMIT finished(tag, reply);
    }

    int countMethod(const QByteArray& method) const
    {
        int total = 0;
        for (const auto& request : requests) {
            if (request.method == method) {
                ++total;
            }
        }
        return total;
    }

    QList<Kanade::KanadeHttpRequest> requests;
    QList<bool> aborted;
    QList<quint64> aborts;
    quint64 m_nextTag = 0;
};

Kanade::KanadeHttpReply httpReply(int status, const QJsonObject& root)
{
    Kanade::KanadeHttpReply reply;
    reply.error = Kanade::KanadeHttpReply::Error::None;
    reply.httpStatus = status;
    reply.body = QJsonDocument(root).toJson(QJsonDocument::Compact);
    return reply;
}

Kanade::KanadeHttpReply networkError()
{
    Kanade::KanadeHttpReply reply;
    reply.error = Kanade::KanadeHttpReply::Error::Network;
    return reply;
}

struct SnapshotFields {
    QString grantId = kGrantA;
    QString hostId = kHostId;
    QString hostInstallationId = kHostInst;
    int hostKeyVersion = 2;
    int clientKeyVersion = 3;
};

QJsonObject snapshot(const QString& state, qint64 createdAt, qint64 offeredUntil,
                     qint64 leaseUntil, bool isOpen, const SnapshotFields& fields = {})
{
    QJsonObject object;
    object.insert(QStringLiteral("id"), kSessionId);
    object.insert(QStringLiteral("grant_id"), fields.grantId);
    object.insert(QStringLiteral("host_id"), fields.hostId);
    object.insert(QStringLiteral("host_installation_id"), fields.hostInstallationId);
    object.insert(QStringLiteral("client_installation_id"), kClientInst);
    object.insert(QStringLiteral("host_key_version"), fields.hostKeyVersion);
    object.insert(QStringLiteral("client_key_version"), fields.clientKeyVersion);
    object.insert(QStringLiteral("state"), state);
    object.insert(QStringLiteral("lease_until"),
                  leaseUntil > 0 ? QJsonValue(static_cast<double>(leaseUntil))
                                 : QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("closed_at"), QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("route_class"), QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("created_at"), static_cast<double>(createdAt));
    object.insert(QStringLiteral("offered_until"), static_cast<double>(offeredUntil));
    object.insert(QStringLiteral("accepted_at"), QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("closed_reason"), QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("is_open"), isOpen);
    return object;
}

QJsonObject offeredBody(qint64 serverTime, qint64 createdAt,
                        const SnapshotFields& fields = {})
{
    QJsonObject root;
    root.insert(QStringLiteral("session"),
                snapshot(QStringLiteral("offered"), createdAt, serverTime + 60, 0, true,
                         fields));
    root.insert(QStringLiteral("expires_at"), static_cast<double>(serverTime + 60));
    root.insert(QStringLiteral("server_time"), static_cast<double>(serverTime));
    return root;
}

QJsonObject activeBody(qint64 serverTime, qint64 leaseUntil, qint64 createdAt,
                       const SnapshotFields& fields = {})
{
    QJsonObject root;
    root.insert(QStringLiteral("session"),
                snapshot(QStringLiteral("active"), createdAt, serverTime + 60,
                         leaseUntil, true, fields));
    root.insert(QStringLiteral("role"), QStringLiteral("client"));
    root.insert(QStringLiteral("server_time"), static_cast<double>(serverTime));
    return root;
}

QJsonObject renewBody(qint64 serverTime, qint64 leaseUntil, qint64 createdAt,
                      const SnapshotFields& fields = {})
{
    QJsonObject root;
    root.insert(QStringLiteral("session"),
                snapshot(QStringLiteral("active"), createdAt, serverTime + 60,
                         leaseUntil, true, fields));
    root.insert(QStringLiteral("lease_until"), static_cast<double>(leaseUntil));
    root.insert(QStringLiteral("server_time"), static_cast<double>(serverTime));
    return root;
}

QJsonObject errorBody(const QString& code)
{
    QJsonObject detail;
    detail.insert(QStringLiteral("code"), code);
    detail.insert(QStringLiteral("message"), QStringLiteral("test"));
    QJsonObject root;
    root.insert(QStringLiteral("detail"), detail);
    return root;
}

} // namespace

class KanadeSessionTest : public QObject {
    Q_OBJECT

private:
    struct Harness {
        FakeTransport transport;
        Kanade::KanadeSession session{&transport};
        qint64 nowMs = 0;
        qint64 wallSecs = kServerTime;
        qint64 authorizedCount = 0;

        explicit Harness(int renewIntervalMs = 3600000, int offerPollMs = 3600000)
        {
            Kanade::KanadeSession::Timing timing;
            timing.renewIntervalMs = renewIntervalMs;
            timing.offerPollIntervalMs = offerPollMs;
            timing.watchdogIntervalMs = 3600000;
            timing.requestTimeoutMs = 1000;
            require(session.setTiming(timing), "timing");
            session.setClockForTesting([this] { return nowMs; },
                                       [this] { return wallSecs; });
            require(session.setServerOrigin(QUrl(kOrigin)), "origin");
            require(session.setInstallationId(kClientInst), "installation");
            require(session.setAccessToken(QStringLiteral("memory-only-token")), "token");

            Kanade::KanadeSession::ExpectedTarget target;
            target.hostId = kHostId;
            target.hostInstallationId = kHostInst;
            target.hostKeyVersion = 2;
            target.clientKeyVersion = 3;
            require(session.setExpectedTarget(target), "target");

            QObject::connect(&session, &Kanade::KanadeSession::authorized,
                             [this] { ++authorizedCount; });
        }
    };

    // Helper: bring a harness to Active with a 90 s lease.
    static void activate(Harness& h)
    {
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, activeBody(kServerTime, kServerTime + 90,
                                                         kServerTime)));
    }

    // Seed an "activation" block into a reply body.  `clientActivated` is this
    // process's own side; `hostActivated` is the peer's.
    static QJsonObject withActivation(QJsonObject body, bool hostActivated,
                                      bool clientActivated)
    {
        QJsonObject host;
        host.insert(QStringLiteral("activated"), hostActivated);
        host.insert(QStringLiteral("activated_at"), QJsonValue(QJsonValue::Null));
        QJsonObject client;
        client.insert(QStringLiteral("activated"), clientActivated);
        client.insert(QStringLiteral("activated_at"), QJsonValue(QJsonValue::Null));
        QJsonObject activation;
        activation.insert(QStringLiteral("host"), host);
        activation.insert(QStringLiteral("client"), client);
        activation.insert(QStringLiteral("both_activated"),
                          hostActivated && clientActivated);
        body.insert(QStringLiteral("activation"), activation);
        return body;
    }

    static QJsonObject ticketBody(qint64 expiresAt)
    {
        QJsonObject body;
        body.insert(QStringLiteral("ticket"), QStringLiteral("tkt_") + QString(43, QLatin1Char('B')));
        body.insert(QStringLiteral("role"), QStringLiteral("client"));
        body.insert(QStringLiteral("expires_at"), static_cast<double>(expiresAt));
        body.insert(QStringLiteral("session_id"), kSessionId);
        return body;
    }

private slots:
    void configurationIsValidatedAndFrozen()
    {
        Harness h;

        // Bad values are refused and change nothing.
        QVERIFY(!h.session.setServerOrigin(QUrl(QStringLiteral("http://kanade.example"))));
        QVERIFY(!h.session.setServerOrigin(QUrl(QStringLiteral("https://kanade.example/v1"))));
        QVERIFY(!h.session.setInstallationId(kClientInst.toUpper()));
        QVERIFY(!h.session.setAccessToken(QString()));

        Kanade::KanadeSession::ExpectedTarget bad;
        bad.hostId = kHostId;
        bad.hostInstallationId = kHostInst;
        bad.hostKeyVersion = 0;
        bad.clientKeyVersion = 1;
        QVERIFY(!h.session.setExpectedTarget(bad));

        QCOMPARE(h.session.origin(), QString(kOrigin));
        QVERIFY(h.session.setServerOrigin(QUrl(QStringLiteral("HTTPS://Kanade.Example/"))));
        QCOMPARE(h.session.origin(), QString(kOrigin));

        // A live attempt freezes every configuration setter.
        h.session.start(kGrantA);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Creating));
        QVERIFY(!h.session.setServerOrigin(QUrl(QStringLiteral("https://other.example"))));
        QVERIFY(!h.session.setInstallationId(kHostInst));
        QVERIFY(!h.session.setAccessToken(QStringLiteral("other")));
        Kanade::KanadeSession::Timing timing;
        timing.renewIntervalMs = 1234;
        QVERIFY(!h.session.setTiming(timing));
        QVERIFY(!h.session.setExpectedTarget(Kanade::KanadeSession::ExpectedTarget{}));
        QCOMPARE(h.session.origin(), QString(kOrigin));
        QCOMPARE(h.transport.requests.size(), 1);
        QCOMPARE(h.transport.requests.at(0).origin, QString(kOrigin));
    }

    void ambiguousCreateIsClassifiedOnceAndNeverAdopted()
    {
        Harness h;
        h.session.start(kGrantA);
        QCOMPARE(h.transport.requests.size(), 1);
        QCOMPARE(h.transport.requests.at(0).method, QByteArray("POST"));
        QCOMPARE(h.transport.requests.at(0).path, QStringLiteral("/v1/sessions"));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Creating));

        h.transport.deliver(1, networkError());
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Diagnosing));
        QCOMPARE(h.transport.requests.size(), 2);
        QCOMPARE(h.transport.requests.at(1).method, QByteArray("GET"));
        QCOMPARE(h.transport.requests.at(1).path, QStringLiteral("/v1/sessions/current"));

        // The diagnostic proves the POST never took effect.  No retry, no
        // delete, no adoption.
        QJsonObject root;
        root.insert(QStringLiteral("session"), QJsonValue(QJsonValue::Null));
        root.insert(QStringLiteral("role"), QJsonValue(QJsonValue::Null));
        root.insert(QStringLiteral("server_time"), static_cast<double>(kServerTime));
        h.transport.deliver(2, httpReply(200, root));

        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::CreateNotApplied));
        QCOMPARE(h.transport.requests.size(), 2);
        QCOMPARE(h.transport.countMethod("POST"), 1);
        QCOMPARE(h.transport.countMethod("DELETE"), 0);
        QCOMPARE(h.authorizedCount, qint64(0));
        QVERIFY(!h.session.hasValidLease());
    }

    void diagnosticSnapshotIsNeverAdopted()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, networkError());

        // A plausible offer exists for our own grant/installation, but the
        // create reply was lost: the read cannot attribute it to this
        // attempt, so it must not be adopted and must not be deleted.
        QJsonObject root;
        root.insert(QStringLiteral("session"),
                    snapshot(QStringLiteral("offered"), kServerTime - 5,
                             kServerTime + 60, 0, true));
        root.insert(QStringLiteral("role"), QStringLiteral("client"));
        root.insert(QStringLiteral("server_time"), static_cast<double>(kServerTime));
        h.transport.deliver(2, httpReply(200, root));

        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::CreateUnverified));
        QCOMPARE(h.authorizedCount, qint64(0));
        QCOMPARE(h.transport.requests.size(), 2); // no poll, no delete
        QCOMPARE(h.transport.countMethod("DELETE"), 0);
        QVERIFY(h.session.sessionId().isEmpty());
    }

    void createOfferThenHostAcceptOpensLease()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));

        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Offering));
        QCOMPARE(h.session.sessionId(), kSessionId);
        QCOMPARE(h.authorizedCount, qint64(0));
        QCOMPARE(h.transport.requests.size(), 2);
        QCOMPARE(h.transport.requests.at(1).path,
                 QStringLiteral("/v1/sessions/") + kSessionId);

        h.transport.deliver(2, httpReply(200, activeBody(kServerTime, kServerTime + 90,
                                                         kServerTime - 3)));

        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        QCOMPARE(h.authorizedCount, qint64(1));
        // Absolute deadline anchored on the request-start instant, minus one
        // second for server clock quantization: 89 000 ms from t=0.
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));
        QCOMPARE(h.session.leaseRemainingMs(), qint64(89000));
        QVERIFY(h.session.hasValidLease());

        h.nowMs = 88999;
        QVERIFY(h.session.hasValidLease());
        // At the deadline itself the lease is ALREADY gone.
        h.nowMs = 89000;
        QVERIFY(!h.session.hasValidLease());
        QCOMPARE(h.session.leaseRemainingMs(), qint64(0));
    }

    void responsesForAnotherHostOrKeyVersionFailClosed()
    {
        struct Case {
            const char* what;
            SnapshotFields fields;
        };
        const Case cases[] = {
            { "other host", { kGrantA, kOtherHostId, kHostInst, 2, 3 } },
            { "other host installation", { kGrantA, kHostId, kOtherHostInst, 2, 3 } },
            { "other host key", { kGrantA, kHostId, kHostInst, 9, 3 } },
            { "other client key", { kGrantA, kHostId, kHostInst, 2, 9 } },
        };
        for (const Case& test : cases) {
            Harness h;
            h.session.start(kGrantA);
            h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3,
                                                             test.fields)));
            QVERIFY2(int(h.session.state()) == int(Kanade::KanadeSession::State::Failed),
                     test.what);
            QCOMPARE(int(h.session.stopReason()),
                     int(Kanade::KanadeSession::StopReason::ProtocolError));
            QVERIFY2(h.session.sessionId().isEmpty(), test.what);
            QCOMPARE(h.transport.countMethod("DELETE"), 0);
            QCOMPARE(h.authorizedCount, qint64(0));
        }
    }

    void pollReplyForAnotherHostFailsClosed()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Offering));

        SnapshotFields swapped;
        swapped.hostId = kOtherHostId;
        h.transport.deliver(2, httpReply(200, activeBody(kServerTime, kServerTime + 90,
                                                         kServerTime - 3, swapped)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ProtocolError));
        QCOMPARE(h.authorizedCount, qint64(0));
    }

    void renewReplyForAnotherHostFailsClosed()
    {
        Harness h(1000);
        activate(h);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        QTRY_VERIFY(h.transport.requests.size() >= 2);

        SnapshotFields swapped;
        swapped.hostInstallationId = kOtherHostInst;
        h.transport.deliver(2, httpReply(200, renewBody(kServerTime, kServerTime + 180,
                                                        kServerTime, swapped)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ProtocolError));
        QVERIFY(!h.session.hasValidLease());
    }

    void staleRenewConfirmationCannotExtendLease()
    {
        Harness h(1000);
        activate(h);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));

        // Let the renew timer fire once, then answer with the SAME lease_until
        // (a replay / delayed confirmation).
        QTRY_VERIFY(h.transport.requests.size() >= 2);
        QCOMPARE(h.transport.requests.at(1).method, QByteArray("POST"));
        QVERIFY(h.transport.requests.at(1).path.endsWith(QStringLiteral("/renew")));

        h.transport.deliver(2, httpReply(200, renewBody(kServerTime, kServerTime + 90,
                                                        kServerTime)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        QCOMPARE(h.authorizedCount, qint64(1)); // never re-announced

        // The duplicate reply must not move the stored absolute deadline.
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));
        h.nowMs = 88999;
        QVERIFY(h.session.hasValidLease());
        h.nowMs = 89000;
        QVERIFY(!h.session.hasValidLease());
    }

    void advancingRenewExtendsLease()
    {
        Harness h(1000);
        activate(h);

        // Advance the injected monotonic clock so the renew request starts at
        // a known offset; the new deadline anchors to that request's start.
        h.nowMs = 1000;
        QTRY_VERIFY(h.transport.requests.size() >= 2);

        h.transport.deliver(2, httpReply(200, renewBody(kServerTime + 1, kServerTime + 91,
                                                        kServerTime)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));

        // 91 - 1 - 1 = 89 s of remaining, anchored on the request start (1000),
        // so the stored absolute deadline is 90 000 ms.
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(90000));
        h.nowMs = 89999;
        QVERIFY(h.session.hasValidLease());
        h.nowMs = 90000;
        QVERIFY(!h.session.hasValidLease());
    }

    // A late reply must never revive an already-expired local gate, even when
    // it carries a later absolute deadline (suspend/resume, delayed delivery).
    void expiredGateIsNeverRevivedByALateConfirmation()
    {
        Harness h(1000);
        activate(h);
        QCOMPARE(h.session.state(), Kanade::KanadeSession::State::Active);

        h.nowMs = 89000; // deadline reached exactly
        QVERIFY(!h.session.hasValidLease());
        h.session.setClockForTesting([&h] { return h.nowMs; }, [&h] { return h.wallSecs; });
        // A scoped read with a fresh, larger lease arrives now.
        h.transport.deliver(2, httpReply(200, activeBody(kServerTime + 89,
                                                         kServerTime + 179,
                                                         kServerTime - 3)));
        // The gate may only be reopened by the session's own accept transition,
        // so the read cannot resurrect it; the session stops instead.
        QVERIFY(!h.session.hasValidLease());
    }

    // A server window larger than the 90 s TTL was not minted by this contract
    // and is refused rather than clamped.
    void oversizedServerLeaseWindowIsRefused()
    {
        Harness h(1000);
        activate(h);
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));
        QTRY_VERIFY(h.transport.requests.size() >= 2);

        // 900 s of lease: absurd, must be refused and leave the gate untouched.
        h.transport.deliver(2, httpReply(200, renewBody(kServerTime, kServerTime + 900,
                                                        kServerTime)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));
    }

    void renewGrantRevocationStopsImmediately()
    {
        Harness h(1000);
        activate(h);
        QTRY_VERIFY(h.transport.requests.size() >= 2);

        h.transport.deliver(2, httpReply(403, errorBody(QStringLiteral("grant_revoked"))));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::GrantRevoked));
        QVERIFY(!h.session.hasValidLease());
        QCOMPARE(h.transport.countMethod("DELETE"), 0);
    }

    void createReplyForDifferentGrantFailsClosed()
    {
        Harness h;
        h.session.start(kGrantB);
        // The snapshot inside names kGrantA.
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ProtocolError));
        QVERIFY(h.session.sessionId().isEmpty());
        QCOMPARE(h.authorizedCount, qint64(0));
        QCOMPARE(h.transport.requests.size(), 1);
    }

    void expiredCreateOfferIsRejected()
    {
        Harness h;
        h.session.start(kGrantA);
        // created_at far in the past: an old session must never be adopted.
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3600)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ProtocolError));
        QVERIFY(h.session.sessionId().isEmpty());
    }

    void cancelWithKnownIdDeletesExactlyOnce()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Offering));

        h.session.cancel();
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closing));
        QVERIFY(!h.session.hasValidLease());
        QCOMPARE(h.transport.countMethod("DELETE"), 1);
        const auto& close = h.transport.requests.last();
        QCOMPARE(close.path, QStringLiteral("/v1/sessions/") + kSessionId);
        QCOMPARE(close.origin, QString(kOrigin));

        h.transport.deliver(3, httpReply(200, QJsonObject()));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::UserCancelled));
        QCOMPARE(h.transport.countMethod("DELETE"), 1);
    }

    void cancelWithUnknownIdNeverDeletesByAge()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, networkError());
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Diagnosing));

        h.session.cancel(); // diagnostic still in flight; nothing is attributable
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closed));
        QCOMPARE(h.transport.countMethod("DELETE"), 0);
        QCOMPARE(h.transport.countMethod("GET"), 1); // only the aborted diagnostic
        QVERIFY(!h.transport.aborts.isEmpty());
    }

    void cancelIsIdempotentAndDropsLateReplies()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));

        h.session.cancel();
        h.session.cancel();
        h.session.cancel();
        QCOMPARE(h.transport.countMethod("DELETE"), 1);

        // A late poll reply from the previous generation must be dropped.
        h.transport.deliver(2, httpReply(200, activeBody(kServerTime, kServerTime + 90,
                                                         kServerTime - 3)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closing));

        h.transport.deliver(3, httpReply(200, QJsonObject()));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closed));
    }

    void logoutClearsTokenAndStops()
    {
        Harness h;
        activate(h);
        h.session.logout();
        h.transport.deliver(2, httpReply(200, QJsonObject()));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::Logout));

        // A fresh start after logout must fail closed on the dropped token.
        h.transport.requests.clear();
        h.session.start(kGrantA);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(h.transport.requests.size(), 0);
    }

    void incompleteConfigurationSendsNothing()
    {
        FakeTransport transport;
        Kanade::KanadeSession session(&transport);
        session.start(kGrantA);
        QCOMPARE(int(session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ProtocolError));
        QCOMPARE(transport.requests.size(), 0);

        Harness h;
        h.session.start(QStringLiteral("not-a-uuid"));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(h.transport.requests.size(), 0);
    }

    void createConflictIsTerminal()
    {
        Harness h;
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(409,
                                         errorBody(QStringLiteral("session_already_open"))));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::CreateConflict));
        QCOMPARE(h.transport.countMethod("DELETE"), 0);
        QCOMPARE(h.transport.countMethod("GET"), 0);
    }

    // --- Activation -------------------------------------------------------

    void activationIsRefusedBeforeActive()
    {
        Harness h;
        const QByteArray binding(32, 'x');
        QVERIFY(!h.session.beginActivation(
            binding, [](const QString&, const QByteArray&) { return QByteArray(); }));
        QCOMPARE(h.transport.requests.size(), 0);

        // Offering is not enough either.
        h.session.start(kGrantA);
        h.transport.deliver(1, httpReply(201, offeredBody(kServerTime, kServerTime - 3)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Offering));
        QVERIFY(!h.session.beginActivation(
            binding, [](const QString&, const QByteArray&) { return QByteArray(); }));
    }

    void activationRefusesNonCanonicalBinding()
    {
        Harness h;
        activate(h);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        const int before = h.transport.requests.size();

        QVERIFY(!h.session.beginActivation(
            QByteArray(31, 'x'), [](const QString&, const QByteArray&) {
                return QByteArray();
            }));
        QVERIFY(!h.session.beginActivation(
            QByteArray(), [](const QString&, const QByteArray&) { return QByteArray(); }));
        QCOMPARE(h.transport.requests.size(), before);
        QVERIFY(!h.session.activationConfirmed());
    }

    void activationRoundTripConfirmsBothSides()
    {
        Harness h;
        activate(h);
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Active));
        QSignalSpy confirmed(&h.session, &Kanade::KanadeSession::bothParticipantsActivated);
        QSignalSpy recorded(&h.session, &Kanade::KanadeSession::activationRecorded);

        // The signer receives the ticket the server minted and the canonical
        // message; it returns a canonical padded 64-byte Base64 proof.
        QString ticketSeen;
        QByteArray messageSeen;
        const QByteArray proof = QByteArray(64, 'p').toBase64();
        QVERIFY(h.session.beginActivation(
            QByteArray(32, 'e'), [&](const QString& ticket, const QByteArray& message) {
                ticketSeen = ticket;
                messageSeen = message;
                return proof;
            }));

        // One POST /tickets follows; nothing else is sent yet.
        const int ticketIndex = h.transport.requests.size() - 1;
        QCOMPARE(h.transport.requests.at(ticketIndex).method, QByteArray("POST"));
        QVERIFY(h.transport.requests.at(ticketIndex).path.endsWith(QStringLiteral("/tickets")));
        QCOMPARE(h.transport.countMethod("DELETE"), 0);

        h.transport.deliver(h.transport.requests.size(),
                            httpReply(200, ticketBody(kServerTime + 30)));

        QVERIFY(!ticketSeen.isEmpty());
        QVERIFY(!messageSeen.isEmpty());
        QVERIFY(messageSeen.startsWith("kanade.session-activation.v1\n"));
        QVERIFY(messageSeen.contains("\"role\":\"client\""));

        // The activate POST carries exactly version/ticket/channel_binding/proof.
        const int activateIndex = h.transport.requests.size() - 1;
        QCOMPARE(h.transport.requests.at(activateIndex).method, QByteArray("POST"));
        QVERIFY(h.transport.requests.at(activateIndex).path.endsWith(
            QStringLiteral("/activate")));
        const QJsonObject body = h.transport.requests.at(activateIndex).body;
        QCOMPARE(body.size(), 4);
        QCOMPARE(body.value(QStringLiteral("version")).toInt(), 1);
        QCOMPARE(body.value(QStringLiteral("proof")).toString(), QString::fromLatin1(proof));
        const QString wireBinding = body.value(QStringLiteral("channel_binding")).toString();
        QCOMPARE(wireBinding.size(), 43);
        QVERIFY(!wireBinding.contains(QLatin1Char('=')));

        // Only our own side was recorded so far: a record, not a confirmation.
        h.transport.deliver(h.transport.requests.size(),
                            httpReply(200, withActivation(activeBody(kServerTime,
                                                                     kServerTime + 90,
                                                                     kServerTime),
                                                           /*hostActivated=*/false,
                                                           /*clientActivated=*/true)));
        QCOMPARE(recorded.count(), 1);
        QCOMPARE(confirmed.count(), 0);
        QVERIFY(!h.session.activationConfirmed());
        // The READ never extended the lease: it only replayed the same deadline.
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));

        // A later scoped read reports both sides: confirmation, no new request
        // is emitted for a read and the lease is not extended.
        h.session.pollActivationForTesting();
        QCOMPARE(h.transport.requests.last().path, QStringLiteral("/v1/sessions/current"));
        h.transport.deliver(h.transport.requests.size(),
                            httpReply(200, withActivation(activeBody(kServerTime,
                                                                     kServerTime + 90,
                                                                     kServerTime),
                                                           true, true)));
        QCOMPARE(confirmed.count(), 1);
        QVERIFY(h.session.activationConfirmed());
        QCOMPARE(h.session.leaseDeadlineMonotonicMs(), qint64(89000));
    }

    void activationIsNeverReplayedAfterAnAmbiguousOutcome()
    {
        Harness h;
        activate(h);
        QVERIFY(h.session.beginActivation(
            QByteArray(32, 'e'), [](const QString&, const QByteArray&) {
                return QByteArray(64, 'p').toBase64();
            }));
        const int ticketIndex = h.transport.requests.size() - 1;

        // Unknown outcome on the ticket POST: one activation attempt per run
        // means the session stops; it must not retry.
        h.transport.deliver(ticketIndex + 1, networkError());
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ActivationFailed));
        QCOMPARE(h.transport.countMethod("POST"), 2); // create + one ticket attempt
        QVERIFY(!h.session.activationConfirmed());
    }

    void activationRefusesInvalidProofFromSigner()
    {
        Harness h;
        activate(h);
        QVERIFY(h.session.beginActivation(
            QByteArray(32, 'e'), [](const QString&, const QByteArray&) {
                return QByteArray("not-base64!!");
            }));
        h.transport.deliver(h.transport.requests.size(),
                            httpReply(200, ticketBody(kServerTime + 30)));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Failed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ActivationFailed));
        // No activate POST was sent with an unusable proof.
        QVERIFY(!h.transport.requests.last().path.endsWith(QStringLiteral("/activate")));
    }

    void activationMismatchClosesAndStops()
    {
        Harness h;
        activate(h);
        QVERIFY(h.session.beginActivation(
            QByteArray(32, 'e'), [](const QString&, const QByteArray&) {
                return QByteArray(64, 'p').toBase64();
            }));
        h.transport.deliver(h.transport.requests.size(),
                            httpReply(200, ticketBody(kServerTime + 30)));
        h.transport.deliver(h.transport.requests.size(),
                            httpReply(409, errorBody(QStringLiteral("activation_mismatch"))));
        QCOMPARE(int(h.session.state()), int(Kanade::KanadeSession::State::Closed));
        QCOMPARE(int(h.session.stopReason()),
                 int(Kanade::KanadeSession::StopReason::ServerClosed));
        QVERIFY(!h.session.activationConfirmed());
        QVERIFY(!h.session.hasValidLease());
    }
};

QTEST_GUILESS_MAIN(KanadeSessionTest)
#include "main.moc"
