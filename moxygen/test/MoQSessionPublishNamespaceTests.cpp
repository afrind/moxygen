/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/mlog/MLogger.h"
#include "moxygen/test/MoQSessionTestCommon.h"

using namespace moxygen;
using namespace moxygen::test;
using testing::_;

// === PUBLISH_NAMESPACE tests ===

CO_TEST_P_X(MoQSessionTest, PublishNamespace) {
  co_await setupMoQSession();

  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          testing::Invoke(
              [](auto ann, auto /* publishNamespaceCallback */)
                  -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
                co_return makePublishNamespaceOkResult(ann);
              }));

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*clientPublisherStatsCallback_, recordPublishNamespaceLatency(_));
  auto publishNamespaceResult =
      co_await clientSession_->publishNamespace(getPublishNamespace());
  EXPECT_FALSE(publishNamespaceResult.hasError());
  co_await folly::coro::co_reschedule_on_current_executor;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, PublishNamespaceDone) {
  co_await setupMoQSession();

  std::shared_ptr<MockPublishNamespaceHandle> mockPublishNamespaceHandle;
  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          testing::Invoke(
              [&mockPublishNamespaceHandle](
                  auto ann, auto /* publishNamespaceCallback */)
                  -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
                mockPublishNamespaceHandle =
                    std::make_shared<MockPublishNamespaceHandle>(
                        PublishNamespaceOk(
                            {.requestID = ann.requestID,
                             .requestSpecificParams = {}}));
                Subscriber::PublishNamespaceResult publishNamespaceResult(
                    mockPublishNamespaceHandle);
                co_return publishNamespaceResult;
              }));

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceSuccess());
  auto publishNamespaceResult =
      co_await clientSession_->publishNamespace(getPublishNamespace());
  EXPECT_FALSE(publishNamespaceResult.hasError());
  auto publishNamespaceHandle = publishNamespaceResult.value();
  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceDone());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceDone());

  folly::coro::Baton barricade;
  EXPECT_CALL(*mockPublishNamespaceHandle, publishNamespaceDone())
      .WillOnce(testing::Invoke([&barricade]() { barricade.post(); }));
  publishNamespaceHandle->publishNamespaceDone();
  co_await barricade;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, PublishNamespaceCancel) {
  co_await setupMoQSession();

  std::shared_ptr<MockPublishNamespaceHandle> mockPublishNamespaceHandle;
  std::shared_ptr<moxygen::Subscriber::PublishNamespaceCallback>
      publishNamespaceCallback;
  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          testing::Invoke(
              [&mockPublishNamespaceHandle, &publishNamespaceCallback](
                  auto ann, auto publishNamespaceCallbackIn)
                  -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
                publishNamespaceCallback = publishNamespaceCallbackIn;
                mockPublishNamespaceHandle =
                    std::make_shared<MockPublishNamespaceHandle>(
                        PublishNamespaceOk(
                            {.requestID = ann.requestID,
                             .requestSpecificParams = {}}));
                Subscriber::PublishNamespaceResult publishNamespaceResult(
                    mockPublishNamespaceHandle);
                co_return publishNamespaceResult;
              }));

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceSuccess());
  auto mockPublishNamespaceCallback =
      std::make_shared<MockPublishNamespaceCallback>();
  auto publishNamespaceResult = co_await clientSession_->publishNamespace(
      getPublishNamespace(), mockPublishNamespaceCallback);
  EXPECT_FALSE(publishNamespaceResult.hasError());
  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceCancel());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceCancel());

  folly::coro::Baton barricade;
  EXPECT_CALL(*mockPublishNamespaceCallback, publishNamespaceCancel(_, _))
      .WillOnce(
          testing::Invoke(
              [&barricade](moxygen::PublishNamespaceErrorCode, std::string) {
                barricade.post();
                return;
              }));
  publishNamespaceCallback->publishNamespaceCancel(
      PublishNamespaceErrorCode::UNINTERESTED, "Not interested!");

  co_await barricade;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
// Draft 18+ subscriber-initiated withdrawal: subscriber tears down the
// PUBLISH_NAMESPACE bidi, the peer's read loop synthesizes
// onPublishNamespaceDone. Mirror of the publisher-initiated path above.
CO_TEST_P_X(Draft18Test, SubscriberCancelsPublishNamespace) {
  co_await setupMoQSession();

  std::shared_ptr<MockPublishNamespaceHandle> mockPublishNamespaceHandle;
  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          [&mockPublishNamespaceHandle](
              auto ann, auto /* publishNamespaceCallback */)
              -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
            mockPublishNamespaceHandle =
                std::make_shared<MockPublishNamespaceHandle>(PublishNamespaceOk(
                    {.requestID = ann.requestID, .requestSpecificParams = {}}));
            co_return Subscriber::PublishNamespaceResult(
                mockPublishNamespaceHandle);
          });

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceSuccess());
  auto publishNamespaceResult =
      co_await clientSession_->publishNamespace(getPublishNamespace());
  EXPECT_FALSE(publishNamespaceResult.hasError());

  // STOP_SENDING the bidi read half → server fires its close callback,
  // synthesizing onPublishNamespaceDone.
  folly::coro::Baton doneBaton;
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceDone());
  EXPECT_CALL(*mockPublishNamespaceHandle, publishNamespaceDone())
      .WillOnce([&] { doneBaton.post(); });
  serverWt_->readHandles.at(0)->stopSending(
      folly::to_underlying(ResetStreamErrorCode::CANCELLED));
  co_await doneBaton;

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

CO_TEST_P_X(MoQSessionTest, PublishNamespaceError) {
  co_await setupMoQSession();

  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          testing::Invoke(
              [](auto ann, auto /* publishNamespaceCallback */)
                  -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
                co_return folly::makeUnexpected(
                    PublishNamespaceError{
                        ann.requestID,
                        PublishNamespaceErrorCode::UNAUTHORIZED,
                        "Unauthorized"});
              }));

  EXPECT_CALL(
      *clientPublisherStatsCallback_,
      onPublishNamespaceError(PublishNamespaceErrorCode::UNAUTHORIZED));
  EXPECT_CALL(
      *serverSubscriberStatsCallback_,
      onPublishNamespaceError(PublishNamespaceErrorCode::UNAUTHORIZED));

  auto publishNamespaceResult =
      co_await clientSession_->publishNamespace(getPublishNamespace());
  EXPECT_TRUE(publishNamespaceResult.hasError());
  EXPECT_EQ(
      publishNamespaceResult.error().errorCode,
      PublishNamespaceErrorCode::UNAUTHORIZED);

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Sender: peer FINs the PUBLISH_NAMESPACE bidi before REQUEST_OK/ERROR —
// publishNamespace must fail rather than strand.
CO_TEST_P_X(Draft18Test, PublishNamespaceFailsOnPeerFinWithoutReply) {
  co_await setupMoQSession();

  folly::coro::Baton serverSawAnn;
  folly::coro::Baton releaseHandler;
  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          [&](auto ann, auto /*cb*/)
              -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
            serverSawAnn.post();
            co_await releaseHandler;
            co_return makePublishNamespaceOkResult(ann);
          });

  std::optional<PublishNamespaceErrorCode> errorCode;
  folly::coro::Baton done;
  folly::coro::co_withExecutor(
      MoQExecutor_.get(),
      folly::coro::co_invoke([&]() -> folly::coro::Task<void> {
        auto result =
            co_await clientSession_->publishNamespace(getPublishNamespace());
        if (result.hasError()) {
          errorCode = result.error().errorCode;
        }
        done.post();
      }))
      .start();

  co_await serverSawAnn;
  // PUBLISH_NAMESPACE bidi is the client-initiated stream id 0.
  serverWt_->writeHandles.at(0)->writeStreamData(
      nullptr, /*fin=*/true, nullptr);

  co_await done;
  EXPECT_TRUE(errorCode.has_value());

  releaseHandler.post();
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// === MLOG RECORD DUPLICATION ===
//
// MLogger is a MoQSessionObserver now, so a call site that both notifies
// observers and still calls logger_->logXXX directly emits the same qlog
// record twice. Nothing else catches that: the stats mocks only see the
// observer path, and the mlog tests cover FileMLogger's sink rather than what
// a session records. This did happen, in publishNamespaceCancel and
// onPublishNamespaceDone.
namespace {
class RecordingMLogger : public MLogger {
 public:
  explicit RecordingMLogger(VantagePoint vp) : MLogger(vp) {}
  void outputLogs() override {}

  // Number of control-message records emitted for a given message type, e.g.
  // "publish_namespace_cancel".
  size_t countControlMessages(const std::string& type) const {
    size_t count = 0;
    for (const auto& event : logs_) {
      const MOQTBaseControlMessage* msg = nullptr;
      if (const auto* created =
              std::get_if<MOQTControlMessageCreated>(&event.data_)) {
        msg = created->message.get();
      } else if (const auto* parsed =
                     std::get_if<MOQTControlMessageParsed>(&event.data_)) {
        msg = parsed->message.get();
      }
      if (msg && msg->type == type) {
        count++;
      }
    }
    return count;
  }
};
} // namespace

CO_TEST_P_X(MoQSessionTest, MLogRecordsControlMessagesExactlyOnce) {
  auto clientLogger =
      std::make_shared<RecordingMLogger>(VantagePoint::CLIENT);
  auto serverLogger =
      std::make_shared<RecordingMLogger>(VantagePoint::SERVER);

  co_await setupMoQSession();
  clientSession_->setLogger(clientLogger);
  serverSession_->setLogger(serverLogger);

  std::shared_ptr<MockPublishNamespaceHandle> mockPublishNamespaceHandle;
  std::shared_ptr<moxygen::Subscriber::PublishNamespaceCallback>
      publishNamespaceCallback;
  EXPECT_CALL(*serverSubscriber, publishNamespace(_, _))
      .WillOnce(
          testing::Invoke(
              [&mockPublishNamespaceHandle, &publishNamespaceCallback](
                  auto ann, auto publishNamespaceCallbackIn)
                  -> folly::coro::Task<Subscriber::PublishNamespaceResult> {
                publishNamespaceCallback = publishNamespaceCallbackIn;
                mockPublishNamespaceHandle =
                    std::make_shared<MockPublishNamespaceHandle>(
                        PublishNamespaceOk(
                            {.requestID = ann.requestID,
                             .requestSpecificParams = {}}));
                co_return Subscriber::PublishNamespaceResult(
                    mockPublishNamespaceHandle);
              }));

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceSuccess());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceSuccess());
  auto mockPublishNamespaceCallback =
      std::make_shared<MockPublishNamespaceCallback>();
  auto publishNamespaceResult = co_await clientSession_->publishNamespace(
      getPublishNamespace(), mockPublishNamespaceCallback);
  EXPECT_FALSE(publishNamespaceResult.hasError());

  EXPECT_CALL(*clientPublisherStatsCallback_, onPublishNamespaceCancel());
  EXPECT_CALL(*serverSubscriberStatsCallback_, onPublishNamespaceCancel());
  folly::coro::Baton barricade;
  EXPECT_CALL(*mockPublishNamespaceCallback, publishNamespaceCancel(_, _))
      .WillOnce(
          testing::Invoke(
              [&barricade](moxygen::PublishNamespaceErrorCode, std::string) {
                barricade.post();
              }));
  publishNamespaceCallback->publishNamespaceCancel(
      PublishNamespaceErrorCode::UNINTERESTED, "Not interested!");
  co_await barricade;

  // One record per message per side, never two. The publisher sends
  // PUBLISH_NAMESPACE and the subscriber cancels it, so each side records its
  // own half exactly once.
  // Note the type strings really are camelCase here while the neighbouring
  // ones in MLogTypes.h are snake_case ("publishNamespace" vs "subscribe").
  // Getting these wrong makes the assertions vacuous rather than failing,
  // which is exactly what happened the first time this test was written.
  EXPECT_EQ(clientLogger->countControlMessages("publishNamespace"), 1u);
  EXPECT_EQ(serverLogger->countControlMessages("publishNamespace"), 1u);
  EXPECT_EQ(
      clientLogger->countControlMessages("publishNamespace_cancel"), 1u);
  EXPECT_EQ(
      serverLogger->countControlMessages("publishNamespace_cancel"), 1u);

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
