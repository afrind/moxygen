/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <moxygen/stats/MoQSessionObserver.h>
#include <moxygen/test/Mocks.h>

using namespace moxygen;
using namespace testing;

using Direction = MoQSessionObserver::Direction;
using Interest = MoQSessionObserver::Interest;

namespace {

std::shared_ptr<StrictMock<MockMoQSessionObserver>> makeObserver(
    uint32_t interests) {
  return std::make_shared<StrictMock<MockMoQSessionObserver>>(interests);
}

} // namespace

TEST(MoQSessionObserverTest, EmptyListIsInertAndCheap) {
  MoQSessionObserverList list;
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.interests(), 0u);
  EXPECT_FALSE(list.interested(Interest::kControl));
  EXPECT_FALSE(list.interested(Interest::kObject));

  // Notifying an empty list must not crash or invoke anything.
  SubscribeOk ok;
  MOQ_OBSERVE_CONTROL(list, onSubscribeOk(Direction::Sent, ok));
}

TEST(MoQSessionObserverTest, AddNullObserverIsIgnored) {
  MoQSessionObserverList list;
  list.add(nullptr);
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.interests(), 0u);
}

TEST(MoQSessionObserverTest, InterestsAreTheUnionOfObservers) {
  MoQSessionObserverList list;
  auto control = makeObserver(Interest::kControl);
  auto object = makeObserver(Interest::kObject);

  list.add(control);
  EXPECT_EQ(list.interests(), uint32_t(Interest::kControl));

  list.add(object);
  EXPECT_EQ(
      list.interests(), uint32_t(Interest::kControl | Interest::kObject));
  EXPECT_FALSE(list.interested(Interest::kSubscription));
}

TEST(MoQSessionObserverTest, RemoveRecomputesInterests) {
  MoQSessionObserverList list;
  auto control = makeObserver(Interest::kControl);
  auto object = makeObserver(Interest::kObject);
  list.add(control);
  list.add(object);

  list.remove(object);
  EXPECT_EQ(list.interests(), uint32_t(Interest::kControl));
  EXPECT_FALSE(list.interested(Interest::kObject));

  list.remove(control);
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.interests(), 0u);

  // Removing something that was never added is a no-op, not a crash.
  list.remove(control);
  EXPECT_TRUE(list.empty());
}

TEST(MoQSessionObserverTest, InterestsMaskGatesTheObjectTier) {
  MoQSessionObserverList list;
  // Deliberately does NOT ask for kObject: this is the access-log shape.
  auto quiet = makeObserver(Interest::kControl | Interest::kSubscription);
  auto tracer = makeObserver(Interest::kObject);
  list.add(quiet);
  list.add(tracer);

  ObjectHeader header;
  Payload payload;
  // Only the tracer may be notified, even though both are registered.
  EXPECT_CALL(*tracer, onSubgroupObject(Direction::Sent, 4, _, _, _)).Times(1);
  MOQ_OBSERVE_OBJECT(
      list,
      onSubgroupObject(Direction::Sent, 4, TrackAlias(9), header, payload));

  // And symmetrically, a control event must not reach the object-only tracer.
  SubscribeOk ok;
  ok.requestID = RequestID(3);
  EXPECT_CALL(*quiet, onSubscribeOk(Direction::Received, _)).Times(1);
  MOQ_OBSERVE_CONTROL(list, onSubscribeOk(Direction::Received, ok));
}

TEST(MoQSessionObserverTest, ObserversAreNotifiedInRegistrationOrder) {
  MoQSessionObserverList list;
  auto first = makeObserver(Interest::kControl);
  auto second = makeObserver(Interest::kControl);
  list.add(first);
  list.add(second);

  InSequence seq;
  EXPECT_CALL(*first, onGoaway(Direction::Sent, _));
  EXPECT_CALL(*second, onGoaway(Direction::Sent, _));

  Goaway goaway;
  MOQ_OBSERVE_CONTROL(list, onGoaway(Direction::Sent, goaway));
}

TEST(MoQSessionObserverTest, DirectionIsForwardedVerbatim) {
  MoQSessionObserverList list;
  auto observer = makeObserver(Interest::kControl);
  list.add(observer);

  EXPECT_CALL(*observer, onSubscribe(Direction::Sent, _)).Times(1);
  EXPECT_CALL(*observer, onSubscribe(Direction::Received, _)).Times(1);

  SubscribeRequest req;
  MOQ_OBSERVE_CONTROL(list, onSubscribe(Direction::Sent, req));
  MOQ_OBSERVE_CONTROL(list, onSubscribe(Direction::Received, req));
}

TEST(MoQSessionObserverTest, SubscriptionCountersArriveAtEnd) {
  MoQSessionObserverList list;
  auto observer = makeObserver(Interest::kSubscription);
  list.add(observer);

  MoQSessionObserver::SubscriptionInfo info;
  info.requestID = RequestID(11);
  info.fullTrackName = FullTrackName{TrackNamespace({"ns"}), "track"};
  info.trackAlias = TrackAlias(5);
  info.role = MoQSessionObserver::Role::Publisher;

  MoQSessionObserver::SubscriptionCounters counters;
  counters.objects = 42;
  counters.bytes = 4096;
  counters.groups = 3;
  counters.endReason = PublishDoneStatusCode::SUBSCRIPTION_ENDED;

  EXPECT_CALL(*observer, onSubscriptionBegin(_))
      .WillOnce(Invoke([](const MoQSessionObserver::SubscriptionInfo& i) {
        EXPECT_EQ(i.requestID, RequestID(11));
        EXPECT_EQ(i.trackAlias, TrackAlias(5));
      }));
  EXPECT_CALL(*observer, onSubscriptionEnd(_, _))
      .WillOnce(Invoke([](const MoQSessionObserver::SubscriptionInfo& i,
                          const MoQSessionObserver::SubscriptionCounters& c) {
        EXPECT_EQ(i.requestID, RequestID(11));
        EXPECT_EQ(c.objects, 42u);
        EXPECT_EQ(c.bytes, 4096u);
        EXPECT_EQ(c.groups, 3u);
        ASSERT_TRUE(c.endReason.has_value());
        EXPECT_EQ(*c.endReason, PublishDoneStatusCode::SUBSCRIPTION_ENDED);
      }));

  MOQ_OBSERVE_SUBSCRIPTION(list, onSubscriptionBegin(info));
  MOQ_OBSERVE_SUBSCRIPTION(list, onSubscriptionEnd(info, counters));
}

TEST(MoQSessionObserverTest, NullListPointerIsANoOp) {
  std::shared_ptr<MoQSessionObserverList> list;
  SubscribeOk ok;
  // Helper objects can outlive/predate observer attachment; this must be safe.
  MOQ_OBSERVE_CONTROL(list, onSubscribeOk(Direction::Sent, ok));

  const MoQSessionObserverList* raw = nullptr;
  MOQ_OBSERVE_CONTROL(raw, onSubscribeOk(Direction::Sent, ok));
}

TEST(MoQSessionObserverTest, SharedPointerAndReferenceFormsBothWork) {
  auto list = std::make_shared<MoQSessionObserverList>();
  auto observer = makeObserver(Interest::kControl);
  list->add(observer);

  EXPECT_CALL(*observer, onMaxRequestID(Direction::Sent, 17u)).Times(2);
  MOQ_OBSERVE_CONTROL(list, onMaxRequestID(Direction::Sent, 17));
  MOQ_OBSERVE_CONTROL(*list, onMaxRequestID(Direction::Sent, 17));
}

TEST(MoQSessionObserverTest, DefaultObserverWantsNothing) {
  // A bare observer must opt in explicitly, so a partially-implemented
  // observer cannot accidentally land on the object hot path.
  class Bare : public MoQSessionObserver {};
  Bare bare;
  EXPECT_EQ(bare.interests(), 0u);

  MoQSessionObserverList list;
  list.add(std::make_shared<Bare>());
  EXPECT_EQ(list.interests(), 0u);
  EXPECT_FALSE(list.empty());

  // Registered but uninterested: nothing is dispatched to it.
  SubscribeOk ok;
  MOQ_OBSERVE_CONTROL(list, onSubscribeOk(Direction::Sent, ok));
}
