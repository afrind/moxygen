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

namespace moxygen { namespace test {

// Implementation of object validation test helper
folly::coro::Task<void> MoQSessionTest::publishValidationTest(
    TestLogicFn testLogic,
    TrackConsumer::BeginSubgroupOptions beginOptions) {
  co_await setupMoQSession();
  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  expectSubscribe(
      [this, testLogic, sg1, beginOptions](
          auto sub, auto pub) -> TaskSubscribeResult {
        EXPECT_CALL(
            *serverPublisherStatsCallback_, onSubscriptionStreamOpened());
        EXPECT_CALL(
            *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
        auto sgp = pub->beginSubgroup(0, 0, 0, beginOptions).value();
        eventBase_.add([testLogic, sub, pub, sgp, sg1]() {
          testLogic(sub, pub, sgp, sg1);
        });
        co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
      });

  folly::coro::Baton resetBaton;
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, reset(ResetStreamErrorCode::INTERNAL_ERROR))
      .WillOnce([&](auto) { resetBaton.post(); });
  // Send side reports the reset it issues; the client reports the reset it
  // observes over the wire.
  EXPECT_CALL(
      *serverPublisherStatsCallback_,
      onSubgroupReset(ResetStreamErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(
      *clientSubscriberStatsCallback_,
      onSubgroupReset(ResetStreamErrorCode::INTERNAL_ERROR));
  expectPublishDone();
  EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamClosed());
  EXPECT_CALL(*clientSubscriberStatsCallback_, onSubscriptionStreamClosed());
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  co_await resetBaton;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

}} // namespace moxygen::test

// === OBJECT DELIVERY tests ===

CO_TEST_P_X(MoQSessionTest, DoubleBeginObject) {
  co_await publishValidationTest([](auto sub, auto pub, auto sgp, auto sgc) {
    EXPECT_CALL(*sgc, beginObject(1, 100, _, _))
        .WillOnce(
            testing::Return(
                folly::Expected<folly::Unit, MoQPublishError>(folly::unit)));
    EXPECT_TRUE(sgp->beginObject(1, 100, test::makeBuf(10)));
    EXPECT_EQ(
        sgp->beginObject(2, 100, test::makeBuf(10)).error().code,
        MoQPublishError::API_ERROR);
    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
  });
}
CO_TEST_P_X(MoQSessionTest, ObjectPayloadTooLong) {
  co_await publishValidationTest([](auto sub, auto pub, auto sgp, auto sgc) {
    EXPECT_CALL(*sgc, beginObject(1, 100, _, _))
        .WillOnce(
            testing::Return(
                folly::Expected<folly::Unit, MoQPublishError>(folly::unit)));
    EXPECT_TRUE(sgp->beginObject(1, 100, test::makeBuf(10)).hasValue());
    auto payloadFail =
        sgp->objectPayload(folly::IOBuf::copyBuffer(std::string(200, 'x')));
    EXPECT_EQ(payloadFail.error().code, MoQPublishError::API_ERROR);
    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
  });
}
CO_TEST_P_X(MoQSessionTest, ObjectPayloadEarlyFin) {
  co_await publishValidationTest([](auto sub, auto pub, auto sgp, auto sgc) {
    EXPECT_CALL(*sgc, beginObject(1, 100, _, _))
        .WillOnce(
            testing::Return(
                folly::Expected<folly::Unit, MoQPublishError>(folly::unit)));
    EXPECT_TRUE(sgp->beginObject(1, 100, test::makeBuf(10)).hasValue());

    // Attempt to send an object payload with length 20 and fin=true, which
    // should fail
    auto payloadFinFail = sgp->objectPayload(
        folly::IOBuf::copyBuffer(std::string(20, 'x')), true);
    EXPECT_EQ(payloadFinFail.error().code, MoQPublishError::API_ERROR);

    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
  });
}
CO_TEST_P_X(MoQSessionTest, ExtensionsOnSubgroupWithoutExtensions) {
  // Publishing an object with extensions on a subgroup opened with
  // includeExtensions=false is an API error.
  TrackConsumer::BeginSubgroupOptions beginOptions;
  beginOptions.includeExtensions = false;
  co_await publishValidationTest(
      [](auto sub, auto pub, auto sgp, auto sgc) {
        EXPECT_CALL(*sgc, object(0, _, _, false))
            .WillOnce(testing::Return(folly::unit));
        EXPECT_TRUE(sgp->object(0, test::makeBuf(10)).hasValue());

        Extensions extensions;
        extensions.insertMutableExtension(Extension(0, 42));
        EXPECT_EQ(
            sgp->object(1, test::makeBuf(10), std::move(extensions))
                .error()
                .code,
            MoQPublishError::API_ERROR);

        pub->publishDone(getTrackEndedPublishDone(sub.requestID));
      },
      beginOptions);
}
CO_TEST_P_X(MoQSessionTest, PublisherResetAfterBeginObject) {
  co_await publishValidationTest([](auto sub, auto pub, auto sgp, auto sgc) {
    EXPECT_CALL(*sgc, beginObject(1, 100, _, _))
        .WillOnce(
            testing::Return(
                folly::Expected<folly::Unit, MoQPublishError>(folly::unit)));
    EXPECT_TRUE(sgp->beginObject(1, 100, test::makeBuf(10)));

    // Call reset after beginObject
    sgp->reset(ResetStreamErrorCode::INTERNAL_ERROR);

    // Attempt to send an object payload after reset, which should fail
    auto payloadFail =
        sgp->objectPayload(folly::IOBuf::copyBuffer(std::string(20, 'x')));
    EXPECT_EQ(payloadFail.error().code, MoQPublishError::CANCELLED);

    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
  });
}
CO_TEST_P_X(MoQSessionTest, ObjectStatus) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;
  expectSubscribe(
      [this, &trackConsumer](auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub] {
          auto sgp1 = pub->beginSubgroup(0, 0, 0).value();
          sgp1->object(0, moxygen::test::makeBuf(10));
          sgp1->object(2, moxygen::test::makeBuf(11));
          sgp1->endOfGroup(3);
          auto sgp2 = pub->beginSubgroup(2, 0, 0).value();
          sgp2->object(0, moxygen::test::makeBuf(10));
          sgp2->endOfTrackAndGroup(2);
        });
        co_return makeSubscribeOkResult(sub);
      });
  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, object(2, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, endOfGroup(3)).WillOnce(testing::Return(folly::unit));

  auto sg3 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(2, 0, 0, _))
      .WillOnce(testing::Return(sg3));
  EXPECT_CALL(*sg3, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  folly::coro::Baton endOfTrackAndGroupBaton;
  EXPECT_CALL(*sg3, endOfTrackAndGroup(2)).WillOnce(testing::Invoke([&]() {
    endOfTrackAndGroupBaton.post();
    return folly::unit;
  }));
  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);
  co_await endOfTrackAndGroupBaton;
  expectPublishDone();
  trackConsumer->publishDone(
      getTrackEndedPublishDone(subscribeRequest.requestID));
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, Datagrams) {
  co_await setupMoQSession();
  expectSubscribe([](auto sub, auto pub) -> TaskSubscribeResult {
    pub->datagram(
        ObjectHeader(0, 0, 1, 0, 11), folly::IOBuf::copyBuffer("hello world"));
    pub->datagram(
        ObjectHeader(0, 0, 2, 0, ObjectStatus::END_OF_TRACK), nullptr);
    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });
  {
    testing::InSequence enforceOrder;
    EXPECT_CALL(*subscribeCallback_, datagram(_, _, _))
        .WillOnce([&](const auto& header, auto, bool) {
          EXPECT_EQ(header.length, 11);
          return folly::unit;
        });
    EXPECT_CALL(*subscribeCallback_, datagram(_, _, _))
        .WillOnce([&](const auto& header, auto, bool) {
          EXPECT_EQ(header.status, ObjectStatus::END_OF_TRACK);
          return folly::unit;
        });
  }
  expectPublishDone();
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, SubgroupWireFormatHintsRoundTrip) {
  // Publisher selects the SubgroupID::Zero + no-extensions stream variant;
  // the subscribe-side BeginSubgroupOptions must reflect that variant rather
  // than the historical Present + extensions defaults.
  co_await setupMoQSession();
  expectSubscribe(
      [this](auto sub, auto pub) -> TaskSubscribeResult {
        eventBase_.add([pub, sub] {
          TrackConsumer::BeginSubgroupOptions options;
          options.subgroupIDFormat = SubgroupIDFormat::Zero;
          options.includeExtensions = false;
          auto sgp = pub->beginSubgroup(0, 0, 0, options).value();
          sgp->object(0, moxygen::test::makeBuf(10), noExtensions(), true);
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        co_return makeSubscribeOkResult(sub);
      },
      MoQControlCodec::Direction::CLIENT);

  auto sg = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, _, _))
      .WillOnce([&sg](
                    uint64_t,
                    uint64_t,
                    uint8_t,
                    const TrackConsumer::BeginSubgroupOptions& opts) {
        EXPECT_EQ(opts.subgroupIDFormat, SubgroupIDFormat::Zero);
        EXPECT_FALSE(opts.includeExtensions);
        return folly::
            makeExpected<MoQPublishError, std::shared_ptr<SubgroupConsumer>>(
                sg);
      });
  EXPECT_CALL(*sg, object(0, _, _, true))
      .WillOnce(testing::Return(folly::unit));

  expectPublishDone(MoQControlCodec::Direction::SERVER);
  auto res = co_await serverSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  serverSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, MixSubgroupsAndDatagrams) {
  // Test that subgroups and datagrams can be mixed on the same track
  co_await setupMoQSession();
  expectSubscribe(
      [this](auto sub, auto pub) -> TaskSubscribeResult {
        eventBase_.add([pub, sub] {
          auto sgp = pub->beginSubgroup(0, 0, 0).value();
          sgp->object(0, moxygen::test::makeBuf(10));
          sgp->object(1, moxygen::test::makeBuf(10), noExtensions(), true);

          // Send a datagram after the subgroup
          pub->datagram(
              ObjectHeader(1, 0, 0, 0, 11),
              folly::IOBuf::copyBuffer("hello world"));

          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        co_return makeSubscribeOkResult(sub);
      },
      MoQControlCodec::Direction::CLIENT);

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, object(1, _, _, true))
      .WillOnce(testing::Return(folly::unit));

  EXPECT_CALL(*subscribeCallback_, datagram(_, _, _))
      .WillOnce(
          [](const auto& header,
             auto,
             bool) -> folly::Expected<folly::Unit, MoQPublishError> {
            EXPECT_EQ(header.group, 1);
            EXPECT_EQ(header.length, 11);
            return folly::unit;
          });

  expectPublishDone(MoQControlCodec::Direction::SERVER);
  auto res = co_await serverSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  serverSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, DatagramBeforeSessionSetup) {
  clientSession_->start();
  EXPECT_FALSE(clientWt_->isSessionClosed());
  clientSession_->onDatagram(folly::IOBuf::copyBuffer("hello world"));
  EXPECT_TRUE(clientWt_->isSessionClosed());
  co_return;
}
CO_TEST_P_X(MoQSessionTest, TooFarBehindOneSubgroup) {
  co_await setupMoQSession();

  MoQSettings moqSettings;
  moqSettings.bufferingThresholds.perSubscription = 100;
  serverSession_->setMoqSettings(moqSettings);

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    auto objStreamId = serverObjectStreamId();
    eventBase_.add([this,
                    pub,
                    sub,
                    serverWt = serverWt_.get(),
                    eventBase = &eventBase_,
                    objStreamId] {
      EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamOpened());
      EXPECT_CALL(
          *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
      auto sgp = pub->beginSubgroup(0, 0, 0).value();
      auto objectResult = sgp->object(0, moxygen::test::makeBuf(10));
      EXPECT_TRUE(objectResult.hasValue());

      // Run this stuff later on, otherwise the test will hang because of
      // the discrepancy in the stream count because the stream would have
      // been reset before the subgroup header got across.
      eventBase->add([pub, sub, serverWt, sgp, objStreamId] {
        // Start buffering data
        serverWt->writeHandles[objStreamId]->setImmediateDelivery(false);
        auto objectResult2 = sgp->object(1, moxygen::test::makeBuf(101));
        EXPECT_TRUE(objectResult2.hasError());
      });
    });
    co_return makeSubscribeOkResult(sub);
  });

  EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamClosed());
  EXPECT_CALL(*clientSubscriberStatsCallback_, onSubscriptionStreamClosed());
  expectPublishDone();
  auto mockSubgroupConsumer =
      std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(mockSubgroupConsumer));
  EXPECT_CALL(*mockSubgroupConsumer, object(0, _, _, _))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*mockSubgroupConsumer, reset(_));
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, FreeUpBufferSpaceOneSubgroup) {
  co_await setupMoQSession();

  MoQSettings moqSettings;
  moqSettings.bufferingThresholds.perSubscription = 100;
  serverSession_->setMoqSettings(moqSettings);

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    auto objStreamId = serverObjectStreamId();
    eventBase_.add([this, pub, sub, serverWt = serverWt_.get(), objStreamId] {
      EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamOpened());
      EXPECT_CALL(
          *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
      auto sgp = pub->beginSubgroup(0, 0, 0).value();
      auto objectResult = sgp->object(0, moxygen::test::makeBuf(10));
      EXPECT_TRUE(objectResult.hasValue());

      // Start buffering data
      serverWt->writeHandles[objStreamId]->setImmediateDelivery(false);
      for (uint32_t i = 0; i < 10; i++) {
        // Run this stuff later on, otherwise the test will hang because of
        // the discrepancy in the stream count because the stream would have
        // been reset before the subgroup header got across.
        objectResult = sgp->object(i + 1, moxygen::test::makeBuf(50));
        serverWt->writeHandles[objStreamId]->deliverInflightData();
        EXPECT_FALSE(objectResult.hasError());
      }
      pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    });
    co_return makeSubscribeOkResult(sub);
  });

  EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamClosed());
  EXPECT_CALL(*clientSubscriberStatsCallback_, onSubscriptionStreamClosed());
  expectPublishDone();
  auto mockSubgroupConsumer =
      std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(mockSubgroupConsumer));
  EXPECT_CALL(*mockSubgroupConsumer, object(_, _, _, _))
      .WillRepeatedly(testing::Return(folly::unit));
  EXPECT_CALL(*mockSubgroupConsumer, reset(_));
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, TooFarBehindMultipleSubgroups) {
  co_await setupMoQSession();

  MoQSettings moqSettings;
  moqSettings.bufferingThresholds.perSubscription = 100;
  serverSession_->setMoqSettings(moqSettings);

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    auto objStreamId0 = serverObjectStreamId(0);
    eventBase_.add([this,
                    pub,
                    sub,
                    serverWt = serverWt_.get(),
                    eventBase = &eventBase_,
                    objStreamId0] {
      std::vector<std::shared_ptr<SubgroupConsumer>> subgroupConsumers;

      EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamOpened())
          .Times(3);
      EXPECT_CALL(*clientSubscriberStatsCallback_, onSubscriptionStreamOpened())
          .Times(3);
      for (uint32_t subgroupId = 0; subgroupId < 3; subgroupId++) {
        subgroupConsumers.push_back(
            pub->beginSubgroup(0, subgroupId, 0).value());
        auto objectResult = subgroupConsumers[subgroupId]->object(
            0, moxygen::test::makeBuf(10));
        EXPECT_TRUE(objectResult.hasValue());
      }

      EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamClosed())
          .Times(3);
      EXPECT_CALL(*clientSubscriberStatsCallback_, onSubscriptionStreamClosed())
          .Times(3);

      // Run this stuff later on, otherwise the test will hang because of
      // the discrepancy in the stream count because the stream would have
      // been reset before the subgroup header got across.
      eventBase->add([pub, sub, serverWt, subgroupConsumers, objStreamId0] {
        for (uint32_t subgroupId = 0; subgroupId < 2; subgroupId++) {
          serverWt->writeHandles[objStreamId0 + subgroupId * 4]
              ->setImmediateDelivery(false);
          auto objectResult = subgroupConsumers[subgroupId]->object(
              1, moxygen::test::makeBuf(30));
          EXPECT_TRUE(objectResult.hasValue());
        }

        serverWt->writeHandles[objStreamId0 + 2 * 4]->setImmediateDelivery(
            false);
        auto objectResult =
            subgroupConsumers[2]->object(1, moxygen::test::makeBuf(40));
        EXPECT_TRUE(objectResult.hasError());
      });
    });
    co_return makeSubscribeOkResult(sub);
  });

  expectPublishDone();
  auto mockSubgroupConsumer =
      std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(_, _, _, _))
      .WillRepeatedly(testing::Return(mockSubgroupConsumer));
  EXPECT_CALL(*mockSubgroupConsumer, object(_, _, _, _))
      .WillRepeatedly(testing::Return(folly::unit));
  EXPECT_CALL(*mockSubgroupConsumer, reset(_)).Times(3);
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, PublisherAliveUntilAllBytesDelivered) {
  co_await setupMoQSession();
  folly::coro::Baton barricade;
  std::shared_ptr<SubgroupConsumer> subgroupConsumer = nullptr;
  expectSubscribe(
      [this, &subgroupConsumer](auto sub, auto pub) -> TaskSubscribeResult {
        eventBase_.add([this, pub, sub, &subgroupConsumer] {
          EXPECT_CALL(
              *serverPublisherStatsCallback_, onSubscriptionStreamOpened());
          EXPECT_CALL(
              *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
          auto sgp = pub->beginSubgroup(0, 0, 0).value();
          sgp->object(0, moxygen::test::makeBuf(10), Extensions(), false);
          subgroupConsumer = sgp;
        });
        co_return makeSubscribeOkResult(sub);
      });
  auto sg = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Invoke([&] {
        eventBase_.add([&] {
          serverWt_->writeHandles[serverObjectStreamId()]->setImmediateDelivery(
              false);
          EXPECT_CALL(
              *serverPublisherStatsCallback_, onSubscriptionStreamClosed());
          EXPECT_CALL(
              *clientSubscriberStatsCallback_, onSubscriptionStreamClosed());
          subgroupConsumer->object(
              1, moxygen::test::makeBuf(10), Extensions(), true);
          barricade.post();
        });
        return sg;
      }));
  EXPECT_CALL(*sg, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg, object(1, _, _, true)).WillOnce(testing::Invoke([&] {
    barricade.post();
    return folly::unit;
  }));
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await barricade;
  barricade.reset();
  serverWt_->writeHandles[serverObjectStreamId()]->deliverInflightData();

  EXPECT_CALL(*subscribeCallback_, publishDone(_))
      .WillOnce(testing::Return(folly::unit));
  co_await barricade;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, TestOnObjectPayload) {
  co_await setupMoQSession();

  std::shared_ptr<SubgroupConsumer> subgroupPublisher = nullptr;
  std::shared_ptr<TrackConsumer> trackConsumer = nullptr;
  expectSubscribe([&](auto sub, auto pub) -> TaskSubscribeResult {
    auto sgp = pub->beginSubgroup(0, 0, 0).value();
    subgroupPublisher = sgp;
    trackConsumer = pub;
    sgp->beginObject(0, 100, test::makeBuf(10)).hasValue();
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  auto sg = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg));

  folly::coro::Baton receivedBeginObject;
  EXPECT_CALL(*sg, beginObject(0, _, _, _))
      .WillOnce(testing::Invoke([&receivedBeginObject]() {
        receivedBeginObject.post();
        return folly::unit;
      }));

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto subscribeRes =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await receivedBeginObject;

  auto payloadSendResult = subgroupPublisher->objectPayload(
      folly::IOBuf::copyBuffer(std::string(90, 'x')), true);
  EXPECT_TRUE(payloadSendResult.hasValue());
  folly::coro::Baton receivedObjectPayload;
  EXPECT_CALL(*sg, objectPayload(_, _))
      .WillOnce(testing::Invoke([&receivedObjectPayload]() {
        receivedObjectPayload.post();
        return ObjectPublishStatus::DONE;
      }));
  EXPECT_CALL(*sg, endOfSubgroup());
  co_await receivedObjectPayload;

  expectPublishDone();
  trackConsumer->publishDone(
      getTrackEndedPublishDone(subscribeRequest.requestID));
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Mock delivery callback for testing
class MockDeliveryCallback : public DeliveryCallback {
 public:
  MOCK_METHOD(
      void,
      onDelivered,
      (const std::optional<TrackAlias>&,
       uint64_t groupId,
       uint64_t subgroupId,
       uint64_t objectId),
      (override));

  MOCK_METHOD(
      void,
      onDeliveryCancelled,
      (const std::optional<TrackAlias>&,
       uint64_t groupId,
       uint64_t subgroupId,
       uint64_t objectId),
      (override));
};

CO_TEST_P_X(MoQSessionTest, DeliveryCallbackBasic) {
  co_await setupMoQSession();
  auto deliveryCallback =
      std::make_shared<testing::StrictMock<MockDeliveryCallback>>();

  expectSubscribe(
      [this, deliveryCallback](auto sub, auto pub) -> TaskSubscribeResult {
        // Set the delivery callback
        pub->setDeliveryCallback(deliveryCallback);

        auto objStreamId = serverObjectStreamId();
        eventBase_.add([this,
                        pub,
                        sub,
                        serverWt = serverWt_.get(),
                        deliveryCallback,
                        objStreamId] {
          EXPECT_CALL(
              *serverPublisherStatsCallback_, onSubscriptionStreamOpened());
          EXPECT_CALL(
              *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
          auto sgp = pub->beginSubgroup(0, 0, 0).value();

          // Buffer data to control delivery timing
          serverWt->writeHandles[objStreamId]->setImmediateDelivery(false);
          auto objectResult = sgp->object(0, moxygen::test::makeBuf(10));
          EXPECT_TRUE(objectResult.hasValue());

          // Manually trigger delivery - this should invoke the callback
          // Expect the delivery callback to be invoked for the object
          EXPECT_CALL(*deliveryCallback, onDelivered(_, 0, 0, 0))
              .WillOnce(testing::Return());
          serverWt->writeHandles[objStreamId]->deliverInflightData();

          sgp->endOfSubgroup();
          serverWt->writeHandles[objStreamId]->deliverInflightData();
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        co_return makeSubscribeOkResult(sub);
      });

  auto sg = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg));
  EXPECT_CALL(*sg, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));
  expectPublishDone();

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, ObjectAckLatencyReported) {
  co_await setupMoQSession();
  // No delivery callback is set: ack-latency tracking relies on the publisher
  // stats callback alone gating pendingDeliveries_.
  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    auto objStreamId = serverObjectStreamId();
    eventBase_.add([this, pub, sub, serverWt = serverWt_.get(), objStreamId] {
      EXPECT_CALL(*serverPublisherStatsCallback_, onSubscriptionStreamOpened());
      EXPECT_CALL(
          *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
      auto sgp = pub->beginSubgroup(0, 0, 0).value();

      serverWt->writeHandles[objStreamId]->setImmediateDelivery(false);
      auto objectResult = sgp->object(0, moxygen::test::makeBuf(10));
      EXPECT_TRUE(objectResult.hasValue());

      // The ack (byte event) for this object records one latency sample.
      EXPECT_CALL(*serverPublisherStatsCallback_, recordObjectAckLatency(_))
          .Times(1);
      serverWt->writeHandles[objStreamId]->deliverInflightData();

      sgp->endOfSubgroup();
      serverWt->writeHandles[objStreamId]->deliverInflightData();
      pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    });
    co_return makeSubscribeOkResult(sub);
  });

  auto sg = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg));
  EXPECT_CALL(*sg, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));
  expectPublishDone();

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, DeliveryCallbackObjectSplitInTwo) {
  co_await setupMoQSession();
  auto deliveryCallback =
      std::make_shared<testing::StrictMock<MockDeliveryCallback>>();

  expectSubscribe(
      [this, deliveryCallback](auto sub, auto pub) -> TaskSubscribeResult {
        // Set the delivery callback
        pub->setDeliveryCallback(deliveryCallback);

        auto objStreamId = serverObjectStreamId();
        eventBase_.add([this,
                        pub,
                        sub,
                        serverWt = serverWt_.get(),
                        deliveryCallback,
                        objStreamId] {
          EXPECT_CALL(
              *serverPublisherStatsCallback_, onSubscriptionStreamOpened());
          EXPECT_CALL(
              *clientSubscriberStatsCallback_, onSubscriptionStreamOpened());
          auto sgp = pub->beginSubgroup(0, 0, 0).value();

          serverWt->writeHandles[objStreamId]->setImmediateDelivery(false);

          // Begin object with initial payload (5 bytes) out of total 10
          // bytes
          auto beginObjectResult =
              sgp->beginObject(0, 10, moxygen::test::makeBuf(5));
          EXPECT_TRUE(beginObjectResult.hasValue());

          serverWt->writeHandles[objStreamId]->deliverInflightData();

          // Expect the delivery callback to be invoked for the object
          EXPECT_CALL(*deliveryCallback, onDelivered(_, 0, 0, 0)).Times(1);

          // Send remaining payload (5 bytes) to complete the object
          auto payloadResult = sgp->objectPayload(moxygen::test::makeBuf(5));
          EXPECT_TRUE(payloadResult.hasValue());

          serverWt->writeHandles[objStreamId]->deliverInflightData();

          sgp->endOfSubgroup();
          serverWt->writeHandles[objStreamId]->deliverInflightData();
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        co_return makeSubscribeOkResult(sub);
      });

  auto sg = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg));
  EXPECT_CALL(*sg, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));
  expectPublishDone();

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(MoQSessionTest, DeliveryCallbackMultipleStreams) {
  co_await setupMoQSession();
  auto deliveryCallback =
      std::make_shared<testing::StrictMock<MockDeliveryCallback>>();

  expectSubscribe(
      [this, deliveryCallback, serverWt = serverWt_.get()](
          auto sub, auto pub) -> TaskSubscribeResult {
        // Set the delivery callback
        pub->setDeliveryCallback(deliveryCallback);

        eventBase_.add([this, pub, sub, deliveryCallback] {
          EXPECT_CALL(
              *serverPublisherStatsCallback_, onSubscriptionStreamOpened())
              .Times(testing::AtLeast(1));
          EXPECT_CALL(
              *clientSubscriberStatsCallback_, onSubscriptionStreamOpened())
              .Times(testing::AtLeast(1));

          // Create multiple subgroups and objects across different streams
          // Stream 1: Group 0, Subgroup 0
          auto sgp1 = pub->beginSubgroup(0, 0, 0).value();
          auto objectResult1 = sgp1->object(0, moxygen::test::makeBuf(10));
          EXPECT_TRUE(objectResult1.hasValue());
          auto objectResult2 = sgp1->object(1, moxygen::test::makeBuf(20));
          EXPECT_TRUE(objectResult2.hasValue());
          sgp1->endOfSubgroup();

          // Stream 2: Group 0, Subgroup 1
          auto sgp2 = pub->beginSubgroup(0, 1, 0).value();
          auto objectResult3 = sgp2->object(0, moxygen::test::makeBuf(15));
          EXPECT_TRUE(objectResult3.hasValue());
          sgp2->endOfSubgroup();

          // Stream 3: Group 1, Subgroup 0
          auto sgp3 = pub->beginSubgroup(1, 0, 0).value();
          auto objectResult4 = sgp3->object(0, moxygen::test::makeBuf(25));
          EXPECT_TRUE(objectResult4.hasValue());
          sgp3->endOfSubgroup();

          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        co_return makeSubscribeOkResult(sub);
      });

  // Set up mock subgroup consumers for each subgroup
  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  auto sg2 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  auto sg3 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, object(1, _, _, _)).WillOnce(testing::Return(folly::unit));

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 1, 0, _))
      .WillOnce(testing::Return(sg2));
  EXPECT_CALL(*sg2, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(1, 0, 0, _))
      .WillOnce(testing::Return(sg3));
  EXPECT_CALL(*sg3, object(0, _, _, _)).WillOnce(testing::Return(folly::unit));

  expectPublishDone();

  EXPECT_CALL(*deliveryCallback, onDelivered(_, 0, 0, 0));
  EXPECT_CALL(*deliveryCallback, onDelivered(_, 0, 0, 1));
  EXPECT_CALL(*deliveryCallback, onDelivered(_, 0, 1, 0));
  EXPECT_CALL(*deliveryCallback, onDelivered(_, 1, 0, 0));

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);

  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
using V15PlusTests = MoQSessionTest;

INSTANTIATE_TEST_SUITE_P(
    V15PlusTests,
    V15PlusTests,
    testing::Values(
        VersionParams{{kVersionDraft15}, kVersionDraft15},
        VersionParams{{kVersionDraft18}, kVersionDraft18}));
CO_TEST_P_X(V15PlusTests, SubgroupPriorityFallback) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;

  // Set publisher priority to 64 (non-default value)
  constexpr uint8_t kPublisherPriority = 64;

  expectSubscribe(
      [this, &trackConsumer, kPublisherPriority](
          auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub] {
          // Begin subgroup with default priority (128)
          // This will be sent on wire WITH a priority field because the
          // PUBLISHER updated the default value to 64.
          auto sgp = pub->beginSubgroup(0, 0, kDefaultPriority).value();
          sgp->object(0, moxygen::test::makeBuf(10));
          sgp->endOfTrackAndGroup(1);
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        // Return SubscribeOk with PUBLISHER_PRIORITY (param at v15, extension
        // at v16+).
        co_return makeSubscribeOkResult(
            sub,
            std::nullopt,
            kPublisherPriority,
            getDraftMajorVersion(getServerSelectedVersion()));
      });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton endOfTrackReceived;
  // Subgroup has kDefaultPriority (128)
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, kDefaultPriority, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, endOfTrackAndGroup(1)).WillOnce(testing::Invoke([&]() {
    endOfTrackReceived.post();
    return folly::unit;
  }));
  expectPublishDone();

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await endOfTrackReceived;
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(V15PlusTests, SubgroupExplicitPriority) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;

  const uint8_t kObjectPriority = 32;

  expectSubscribe(
      [this, &trackConsumer, kObjectPriority](
          auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub, kObjectPriority] {
          // Begin subgroup with explicit priority
          auto sgp = pub->beginSubgroup(0, 0, kObjectPriority).value();
          sgp->object(0, moxygen::test::makeBuf(10));
          sgp->endOfTrackAndGroup(1);
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        // Return SubscribeOk with PUBLISHER_PRIORITY (param at v15, extension
        // at v16+).
        constexpr uint8_t kPublisherPriority = 64;
        co_return makeSubscribeOkResult(
            sub,
            std::nullopt,
            kPublisherPriority,
            getDraftMajorVersion(getServerSelectedVersion()));
      });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton endOfTrackReceived;
  // When object has explicit priority, it should use that (32) not publisher
  // priority
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, kObjectPriority, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, endOfTrackAndGroup(1)).WillOnce(testing::Invoke([&]() {
    endOfTrackReceived.post();
    return folly::unit;
  }));
  expectPublishDone();

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await endOfTrackReceived;
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(V15PlusTests, ObjectStatusPriorityFallback) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;

  constexpr uint8_t kPublisherPriority = 64;

  expectSubscribe(
      [this, &trackConsumer, kPublisherPriority](
          auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub] {
          // Send endOfTrackAndGroup with default priority
          auto sgp = pub->beginSubgroup(0, 0, kDefaultPriority).value();
          sgp->endOfTrackAndGroup(0);
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        // Return SubscribeOk with PUBLISHER_PRIORITY (param at v15, extension
        // at v16+).
        co_return makeSubscribeOkResult(
            sub,
            std::nullopt,
            kPublisherPriority,
            getDraftMajorVersion(getServerSelectedVersion()));
      });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton endOfTrackReceived;
  // Object status with no explicit priority should use publisher priority
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, kDefaultPriority, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, endOfTrackAndGroup(0)).WillOnce(testing::Invoke([&]() {
    endOfTrackReceived.post();
    return folly::unit;
  }));
  expectPublishDone();

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await endOfTrackReceived;
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}
CO_TEST_P_X(V15PlusTests, PublisherPriorityDefaultValue) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;

  expectSubscribe(
      [this, &trackConsumer](auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub] {
          // Begin subgroup with default priority
          auto sgp = pub->beginSubgroup(0, 0, kDefaultPriority).value();
          sgp->object(0, moxygen::test::makeBuf(10));
          sgp->endOfTrackAndGroup(1);
          pub->publishDone(getTrackEndedPublishDone(sub.requestID));
        });
        // Return SubscribeOk WITHOUT PUBLISHER_PRIORITY parameter
        // Should default to 128
        co_return makeSubscribeOkResult(sub);
      });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton endOfTrackReceived;
  // Without PUBLISHER_PRIORITY param, should default to kDefaultPriority (128)
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, kDefaultPriority, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, endOfTrackAndGroup(1)).WillOnce(testing::Invoke([&]() {
    endOfTrackReceived.post();
    return folly::unit;
  }));
  expectPublishDone();

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await endOfTrackReceived;
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Test that when a subscriber's object callback returns an error,
// the stream is terminated and no further callbacks are invoked
CO_TEST_P_X(MoQSessionTest, SubscriberCallbackErrorTerminatesStream) {
  co_await setupMoQSession();
  std::shared_ptr<TrackConsumer> trackConsumer;

  expectSubscribe(
      [this, &trackConsumer](auto sub, auto pub) -> TaskSubscribeResult {
        trackConsumer = pub;
        eventBase_.add([pub, sub] {
          auto sgp1 = pub->beginSubgroup(0, 0, 0).value();
          // Send first object - should succeed
          sgp1->object(0, moxygen::test::makeBuf(10));
          // Send second object - should succeed
          sgp1->object(1, moxygen::test::makeBuf(10));
          // Send third object - consumer will error on this, stream should
          // terminate
          sgp1->object(2, moxygen::test::makeBuf(10));
          // Send fourth object - should not be delivered due to stream
          // termination
          sgp1->object(3, moxygen::test::makeBuf(10));
        });
        co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
      });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*subscribeCallback_, publishDone(testing::_))
      .WillOnce(testing::Return(folly::unit));

  {
    testing::InSequence enforceOrder;
    // First object succeeds
    EXPECT_CALL(*sg1, object(0, _, _, false))
        .WillOnce(testing::Return(folly::unit));
    // Second object succeeds
    EXPECT_CALL(*sg1, object(1, _, _, false))
        .WillOnce(testing::Return(folly::unit));
    // Third object returns error
    EXPECT_CALL(*sg1, object(2, _, _, false))
        .WillOnce(
            testing::Return(
                folly::makeUnexpected(MoQPublishError(
                    MoQPublishError::CANCELLED, "test error"))));
    // Fourth object should NOT be delivered
    EXPECT_CALL(*sg1, object(3, _, _, false)).Times(0);
  }
  // The ERROR_TERMINATE from the object error triggers reset on the
  // SubgroupConsumer to properly clean up the subgroup state.
  EXPECT_CALL(*sg1, reset(_)).Times(1);

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await folly::coro::co_reschedule_on_current_executor;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Regression test: When a subscriber's SubgroupConsumer returns an error from
// beginObject (e.g., due to a cache payload mismatch in the relay), the
// session's dataStreamReadLoop gets ERROR_TERMINATE from codec.onIngress.
// Without the fix, the read loop just breaks without calling dcb.reset(),
// leaving the SubgroupConsumer in a zombie state. The SubgroupForwarder
// retains open downstream subgroups that are never cleaned up.
// Fix: call dcb.reset() on the ERROR_TERMINATE path so the SubgroupConsumer
// properly cleans up.
CO_TEST_P_X(MoQSessionTest, ObjectCallbackErrorResetsSubgroupConsumer) {
  co_await setupMoQSession();

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    eventBase_.add([pub, sub] {
      auto sgp = pub->beginSubgroup(0, 0, 0).value();
      // Send an object that the subscriber will reject.
      sgp->object(0, moxygen::test::makeBuf(100));
      pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    });
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton resetBaton;

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));

  // object() returns an error, triggering ERROR_TERMINATE in the read loop
  EXPECT_CALL(*sg1, object(0, _, _, false))
      .WillOnce(
          testing::Return(
              folly::makeUnexpected(MoQPublishError(
                  MoQPublishError::API_ERROR, "payload mismatch"))));

  // After ERROR_TERMINATE, reset should be called to clean up the subgroup.
  // Without the fix, this expectation fails (reset is never called).
  EXPECT_CALL(*sg1, reset(_)).WillOnce([&](auto) { resetBaton.post(); });

  expectPublishDone();

  auto subscribeRequest = getSubscribe(kTestTrackName);
  auto res =
      co_await clientSession_->subscribe(subscribeRequest, subscribeCallback_);

  co_await resetBaton;
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Cleanup must reset an open subgroup. The session is closed with a subgroup
// still open; cleanup() cancels the subscribe state, and isCancelled() must not
// then suppress reset() on the open subgroup consumer. Reverting the
// isCancelled() change hangs this test on resetBaton.
//
// Note: FakeSharedWebTransport's close also resets the peer's streams, so the
// read loop here can wake via that error too; this exercises the cleanup/reset
// contract but does not isolate the rh-token-cancel-without-error wake.
CO_TEST_P_X(MoQSessionTest, OpenSubgroupResetDuringSessionCleanup) {
  co_await setupMoQSession();

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    eventBase_.add([pub, sub] {
      auto sgp = pub->beginSubgroup(0, 0, 0).value();
      // Leave the subgroup OPEN: no endOfSubgroup, no publishDone.
      sgp->object(0, moxygen::test::makeBuf(10));
    });
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();
  folly::coro::Baton objectReceived;
  folly::coro::Baton resetBaton;

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, false)).WillOnce([&](auto...) {
    objectReceived.post();
    return folly::unit;
  });
  // cleanup() delivers PUBLISH_DONE before cancelling the loop.
  EXPECT_CALL(*subscribeCallback_, publishDone(_))
      .WillOnce(testing::Return(folly::unit));
  EXPECT_CALL(*sg1, reset(_)).WillOnce([&](auto) {
    resetBaton.post();
    return folly::unit;
  });

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());

  // Subgroup is open and the read loop is parked on readStreamData().
  co_await objectReceived;

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);

  co_await resetBaton;
}

// When two objects arrive in the same ingress and the app calls
// unsubscribe() from the first object's callback, the second object must
// NOT be delivered. obj0 is sent normally to fire beginSubgroup; obj1+obj2
// are then batched into a single onIngress via setImmediateDelivery(false)
// + deliverInflightData(). Does NOT assert reset() fires: on this path it
// reaches sg1 via the parser's ERROR_TERMINATE branch regardless of the
// fix, so the assertion would not differentiate.
CO_TEST_P_X(MoQSessionTest, UnsubscribeInObjectCallbackSuppressesNextObject) {
  co_await setupMoQSession();

  std::shared_ptr<SubgroupConsumer> sgConsumer;
  std::shared_ptr<MockSubscriptionHandle> mockHandle;
  expectSubscribe([&](auto sub, auto pub) -> TaskSubscribeResult {
    sgConsumer = pub->beginSubgroup(0, 0, 0).value();
    sgConsumer->object(0, moxygen::test::makeBuf(10));
    mockHandle = makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
    co_return mockHandle;
  });

  auto sg1 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  folly::coro::Baton obj0Delivered;
  folly::coro::Baton obj1Done;
  bool obj2Delivered = false;
  std::shared_ptr<Subscriber::SubscriptionHandle> subHandle;

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, _)).WillOnce([&](auto...) {
    obj0Delivered.post();
    return folly::unit;
  });
  EXPECT_CALL(*sg1, object(1, _, _, _)).WillOnce([&](auto...) {
    subHandle->unsubscribe();
    obj1Done.post();
    return folly::unit;
  });
  EXPECT_CALL(*sg1, object(2, _, _, _)).WillRepeatedly([&](auto...) {
    obj2Delivered = true;
    return folly::unit;
  });

  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());
  subHandle = res.value();

  EXPECT_CALL(*mockHandle, unsubscribe()).WillRepeatedly(testing::Return());

  // After obj0, the data stream's write handle exists in
  // serverWt_->writeHandles; pause delivery, write obj1+obj2, flush as one
  // buffer so the subscriber's onIngress sees both objects in a single call.
  co_await obj0Delivered;
  eventBase_.runInEventBaseThread([sgConsumer, this] {
    auto dataWh = serverWt_->writeHandles.rbegin()->second;
    dataWh->setImmediateDelivery(false);
    sgConsumer->object(1, moxygen::test::makeBuf(10));
    sgConsumer->object(2, moxygen::test::makeBuf(10));
    dataWh->deliverInflightData();
  });

  // Yield after obj1's callback so the read loop can attempt obj2.
  co_await obj1Done;
  for (int i = 0; i < 20; ++i) {
    co_await folly::coro::co_reschedule_on_current_executor;
  }

  EXPECT_FALSE(obj2Delivered)
      << "object 2 must not be delivered after unsubscribe()";

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

namespace {
class NullLogger : public MLogger {
 public:
  NullLogger() : MLogger(VantagePoint::SERVER) {}
  void outputLogs() override {}
};
} // namespace

// Test: publishing an object with null payload when a logger is set must not
// crash. objectImpl calls payload->clone() inside the logger block without
// checking for null.
CO_TEST_P_X(MoQSessionTest, NullPayloadWithLogger) {
  co_await setupMoQSession();
  // Set a logger on the server session so the logging code path is exercised
  serverSession_->setLogger(std::make_shared<NullLogger>());

  auto sg1 = std::make_shared<testing::StrictMock<MockSubgroupConsumer>>();

  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    eventBase_.add([pub, sub] {
      auto sgp = pub->beginSubgroup(0, 0, 0).value();
      // Publish object with null payload — crashes in objectImpl logging
      sgp->object(0, nullptr, noExtensions(), true);
      pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    });
    co_return makeSubscribeOkResult(sub);
  });

  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(sg1));
  EXPECT_CALL(*sg1, object(0, _, _, true))
      .WillOnce(testing::Return(folly::unit));
  expectPublishDone();
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  co_await publishDone_;
  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// === SUBSCRIPTION COUNTERS ===
//
// The per-subscription delivery totals are the one piece of instrumentation
// that is new rather than relocated, so they get their own coverage: nothing
// in moxygen tracked per-subscription object/byte/group totals before.

// Objects published across two groups on the subgroup path must arrive at
// onSubscriptionEnd as a single rollup, with groups counted once per group
// rather than once per subgroup.
CO_TEST_P_X(MoQSessionTest, SubscriptionCountersRollUpAtEnd) {
  co_await setupMoQSession();

  auto observer = std::make_shared<testing::NiceMock<MockMoQSessionObserver>>(
      MoQSessionObserver::kSubscription);
  serverSession_->addObserver(observer);

  MoQSessionObserver::SubscriptionCounters seen;
  bool sawEnd = false;
  EXPECT_CALL(*observer, onSubscriptionEnd(_, _))
      .WillOnce(testing::Invoke(
          [&](const MoQSessionObserver::SubscriptionInfo& info,
              const MoQSessionObserver::SubscriptionCounters& counters) {
            EXPECT_EQ(info.role, MoQSessionObserver::Role::Publisher);
            EXPECT_EQ(info.fullTrackName.trackName, kTestTrackName.trackName);
            seen = counters;
            sawEnd = true;
          }));

  expectSubscribe([](auto sub, auto pub) -> TaskSubscribeResult {
    // Group 0 carries two objects across two subgroups; group 1 carries one.
    // Six bytes, then five, then four: 15 bytes over 3 objects and 2 groups.
    auto sg0 = pub->beginSubgroup(0, 0, 0).value();
    sg0->object(0, folly::IOBuf::copyBuffer("abcdef"), noExtensions(), false);
    auto sg1 = pub->beginSubgroup(0, 1, 0).value();
    sg1->object(1, folly::IOBuf::copyBuffer("abcde"), noExtensions(), true);
    auto sg2 = pub->beginSubgroup(1, 0, 0).value();
    sg2->object(0, folly::IOBuf::copyBuffer("abcd"), noExtensions(), true);
    sg0->endOfSubgroup();
    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  // The receiving side is a StrictMock, so the inbound subgroups need
  // expectations even though this test is about the sender's counters.
  auto rsg0 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  auto rsg1 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  auto rsg2 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(rsg0));
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 1, 0, _))
      .WillOnce(testing::Return(rsg1));
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(1, 0, 0, _))
      .WillOnce(testing::Return(rsg2));

  expectPublishDone();
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());
  co_await publishDone_;

  EXPECT_TRUE(sawEnd);
  EXPECT_EQ(seen.objects, 3u);
  EXPECT_EQ(seen.bytes, 15u);
  // Two distinct groups, three subgroups: the group counter must not follow
  // the subgroup count.
  EXPECT_EQ(seen.groups, 2u);
  EXPECT_TRUE(seen.endReason.has_value());
  if (seen.endReason) {
    EXPECT_EQ(*seen.endReason, PublishDoneStatusCode::TRACK_ENDED);
  }

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

// Datagrams bypass the subgroup path entirely, so they are counted separately.
CO_TEST_P_X(MoQSessionTest, SubscriptionCountersCountDatagrams) {
  co_await setupMoQSession();

  auto observer = std::make_shared<testing::NiceMock<MockMoQSessionObserver>>(
      MoQSessionObserver::kSubscription);
  serverSession_->addObserver(observer);

  MoQSessionObserver::SubscriptionCounters seen;
  bool sawEnd = false;
  EXPECT_CALL(*observer, onSubscriptionEnd(_, _))
      .WillOnce(testing::Invoke(
          [&](const MoQSessionObserver::SubscriptionInfo&,
              const MoQSessionObserver::SubscriptionCounters& counters) {
            seen = counters;
            sawEnd = true;
          }));

  expectSubscribe([](auto sub, auto pub) -> TaskSubscribeResult {
    pub->datagram(
        ObjectHeader(0, 0, 1, 0, 11), folly::IOBuf::copyBuffer("hello world"));
    pub->datagram(
        ObjectHeader(1, 0, 1, 0, 5), folly::IOBuf::copyBuffer("hello"));
    pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  EXPECT_CALL(*subscribeCallback_, datagram(_, _, _))
      .Times(2)
      .WillRepeatedly(testing::Return(folly::unit));
  expectPublishDone();
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());
  co_await publishDone_;

  EXPECT_TRUE(sawEnd);
  EXPECT_EQ(seen.objects, 2u);
  EXPECT_EQ(seen.bytes, 16u);
  EXPECT_EQ(seen.groups, 2u);

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

namespace {
// Collects the object-tier mlog records so the observer migration of the data
// plane has a regression signal. The control-plane equivalent lives in
// MoQSessionPublishNamespaceTests.
class ObjectRecordingMLogger : public MLogger {
 public:
  explicit ObjectRecordingMLogger(VantagePoint vp) : MLogger(vp) {}
  void outputLogs() override {}

  struct Counts {
    size_t subgroupHeadersCreated{0};
    size_t subgroupHeadersParsed{0};
    size_t subgroupObjectsCreated{0};
    size_t subgroupObjectsParsed{0};
    size_t datagramsParsed{0};
    size_t streamTypesSet{0};
  };

  Counts counts() const {
    Counts c;
    for (const auto& event : logs_) {
      if (std::get_if<MOQTSubgroupHeaderCreated>(&event.data_)) {
        c.subgroupHeadersCreated++;
      } else if (std::get_if<MOQTSubgroupHeaderParsed>(&event.data_)) {
        c.subgroupHeadersParsed++;
      } else if (std::get_if<MOQTSubgroupObjectCreated>(&event.data_)) {
        c.subgroupObjectsCreated++;
      } else if (std::get_if<MOQTSubgroupObjectParsed>(&event.data_)) {
        c.subgroupObjectsParsed++;
      } else if (std::get_if<MOQTObjectDatagramParsed>(&event.data_)) {
        c.datagramsParsed++;
      } else if (std::get_if<MOQTStreamTypeSet>(&event.data_)) {
        c.streamTypesSet++;
      }
    }
    return c;
  }

  // Payload of the Nth parsed subgroup object, so the migration cannot
  // silently start logging an empty or aliased buffer.
  std::string parsedObjectPayload(size_t index) const {
    size_t seen = 0;
    for (const auto& event : logs_) {
      if (const auto* parsed =
              std::get_if<MOQTSubgroupObjectParsed>(&event.data_)) {
        if (seen++ == index) {
          return parsed->objectPayload
              ? parsed->objectPayload->clone()->moveToFbString().toStdString()
              : std::string();
        }
      }
    }
    return std::string();
  }
};
} // namespace

CO_TEST_P_X(MoQSessionTest, MLogRecordsObjectTier) {
  auto clientLogger =
      std::make_shared<ObjectRecordingMLogger>(VantagePoint::CLIENT);
  auto serverLogger =
      std::make_shared<ObjectRecordingMLogger>(VantagePoint::SERVER);

  co_await setupMoQSession();
  clientSession_->setLogger(clientLogger);
  serverSession_->setLogger(serverLogger);

  // Two subgroups in one group. The second object is begun with only half its
  // payload and finished from a later turn of the loop, so the receiver parses
  // it across two frames -- the path that stashes the header at object begin
  // and reports once the final frame lands.
  expectSubscribe([this](auto sub, auto pub) -> TaskSubscribeResult {
    auto sg0 = pub->beginSubgroup(0, 0, 0).value();
    sg0->object(0, folly::IOBuf::copyBuffer("abcdef"), noExtensions(), false);
    auto sg1 = pub->beginSubgroup(0, 1, 0).value();
    sg1->beginObject(0, 6, folly::IOBuf::copyBuffer("abc"), noExtensions());
    eventBase_.add([sub, pub, sg0, sg1] {
      sg1->objectPayload(folly::IOBuf::copyBuffer("def"), true);
      sg0->endOfSubgroup();
      pub->publishDone(getTrackEndedPublishDone(sub.requestID));
    });
    co_return makeSubscribeOkResult(sub, AbsoluteLocation{0, 0});
  });

  auto rsg0 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  auto rsg1 = std::make_shared<testing::NiceMock<MockSubgroupConsumer>>();
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 0, 0, _))
      .WillOnce(testing::Return(rsg0));
  EXPECT_CALL(*subscribeCallback_, beginSubgroup(0, 1, 0, _))
      .WillOnce(testing::Return(rsg1));

  expectPublishDone();
  auto res = co_await clientSession_->subscribe(
      getSubscribe(kTestTrackName), subscribeCallback_);
  EXPECT_FALSE(res.hasError());
  co_await publishDone_;

  auto sent = serverLogger->counts();
  auto received = clientLogger->counts();

  // The publisher records each subgroup header it writes; the subscriber
  // records each one it parses.
  EXPECT_EQ(sent.subgroupHeadersCreated, 2u);
  EXPECT_EQ(received.subgroupHeadersParsed, 2u);
  // Only the whole-in-one-frame object is reported. The split object is
  // parsed and delivered to the application, but never recorded: onObjectBegin
  // stashes its header expecting onObjectPayload to report it, and that report
  // does not happen. This is pre-existing -- the same assertion fails
  // identically against the code before the observer migration -- so it is
  // pinned here rather than fixed, to keep the migration behaviour-neutral and
  // to make the gap visible.
  // TODO: report the split object and change this to 2.
  EXPECT_EQ(received.subgroupObjectsParsed, 1u);
  EXPECT_EQ(received.datagramsParsed, 0u);
  // Each subgroup stream gets a stream type, on both sides.
  EXPECT_EQ(sent.streamTypesSet, 2u);
  EXPECT_EQ(received.streamTypesSet, 2u);
  // Payload survives the clone-inside-the-observer change: MLogger now clones
  // in its override rather than every call site cloning unconditionally.
  EXPECT_EQ(clientLogger->parsedObjectPayload(0), "abcdef");

  clientSession_->close(SessionCloseErrorCode::NO_ERROR);
}

