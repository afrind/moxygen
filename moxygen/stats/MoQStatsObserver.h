/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>
#include <utility>

#include <moxygen/stats/MoQSessionObserver.h>
#include <moxygen/stats/MoQStats.h>

namespace moxygen {

/*
 * Adapters that present the existing MoQStatsCallback interfaces as
 * MoQSessionObservers, so MoQSession notifies a single observer list and the
 * counters keep working unchanged.
 *
 * MoQStatsCallback splits into a publisher and a subscriber interface because
 * the same event name means different things depending on which role this
 * endpoint plays. The observer interface instead carries a Direction, and the
 * role is fixed when the callback is installed -- setPublisherStatsCallback
 * versus setSubscriberStatsCallback. So each adapter knows its own role and
 * only fires on the direction that role cares about:
 *
 *   - The publisher is the side that serves tracks. It receives SUBSCRIBE and
 *     sends SUBSCRIBE_OK, so subscribe events fire on Direction::Sent.
 *   - The subscriber is the side that requests tracks, so the same subscribe
 *     events fire on Direction::Received.
 *   - Namespace operations invert this: the publisher is the announcer, so it
 *     sends PUBLISH_NAMESPACE and receives PUBLISH_NAMESPACE_OK.
 *
 * That inversion is exactly what MoQStats.h documents per method, and it is
 * why direction alone cannot decide the role -- the message family matters too.
 */
class MoQPublisherStatsObserver : public MoQSessionObserver {
 public:
  explicit MoQPublisherStatsObserver(
      std::shared_ptr<MoQPublisherStatsCallback> callback)
      : callback_(std::move(callback)) {}

  uint32_t interests() const override {
    return kControl | kSubscription;
  }

  // Publisher receives SUBSCRIBE, sends the reply.
  void onSubscribeOk(Direction dir, const SubscribeOk&) override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeSuccess();
    }
  }
  void onSubscribeError(Direction dir, const SubscribeError& err) override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeError(err.errorCode);
    }
  }
  void onFetchOk(Direction dir, const FetchOk&) override {
    if (dir == Direction::Sent) {
      callback_->onFetchSuccess();
    }
  }
  void onFetchError(Direction dir, const FetchError& err) override {
    if (dir == Direction::Sent) {
      callback_->onFetchError(err.errorCode);
    }
  }
  void onTrackStatus(Direction dir, const TrackStatus&) override {
    if (dir == Direction::Received) {
      callback_->onTrackStatus();
    }
  }
  void onUnsubscribe(Direction dir, const Unsubscribe&) override {
    if (dir == Direction::Received) {
      callback_->onUnsubscribe();
    }
  }
  void onRequestUpdate(Direction dir, const RequestUpdate&) override {
    if (dir == Direction::Received) {
      callback_->onRequestUpdate();
    }
  }
  void onPublishDone(Direction dir, const PublishDone& done) override {
    if (dir == Direction::Sent) {
      callback_->onPublishDone(done.statusCode);
    }
  }

  // Namespace operations: the publisher is the announcer, so it sends the
  // request and receives the reply.
  void onPublishNamespaceOk(Direction dir, const PublishNamespaceOk&) override {
    if (dir == Direction::Received) {
      callback_->onPublishNamespaceSuccess();
    }
  }
  void onPublishNamespaceError(
      Direction dir,
      const PublishNamespaceError& err) override {
    if (dir == Direction::Received) {
      callback_->onPublishNamespaceError(err.errorCode);
    }
  }
  void onPublishNamespaceDone(Direction dir, const PublishNamespaceDone&)
      override {
    if (dir == Direction::Sent) {
      callback_->onPublishNamespaceDone();
    }
  }
  void onPublishNamespaceCancel(Direction dir, const PublishNamespaceCancel&)
      override {
    if (dir == Direction::Received) {
      callback_->onPublishNamespaceCancel();
    }
  }
  void onSubscribeNamespaceOk(Direction dir, const SubscribeNamespaceOk&)
      override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeNamespaceSuccess();
    }
  }
  void onSubscribeNamespaceError(
      Direction dir,
      const SubscribeNamespaceError& err) override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeNamespaceError(err.errorCode);
    }
  }
  void onUnsubscribeNamespace(Direction dir, const UnsubscribeNamespace&)
      override {
    if (dir == Direction::Received) {
      callback_->onUnsubscribeNamespace();
    }
  }
  void onSubscribeTracksOk(Direction dir, const SubscribeTracksOk&) override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeTracksSuccess();
    }
  }
  void onSubscribeTracksError(
      Direction dir,
      const SubscribeTracksError& err) override {
    if (dir == Direction::Sent) {
      callback_->onSubscribeTracksError(err.errorCode);
    }
  }

  // PUBLISH is sent by the publisher, so the reply comes back to it.
  void onPublishOk(Direction dir, const PublishOk&) override {
    if (dir == Direction::Received) {
      callback_->onPublishSuccess();
    }
  }
  void onPublishError(Direction dir, const PublishError& err) override {
    if (dir == Direction::Received) {
      callback_->onPublishError(err.errorCode);
    }
  }

  void onSubscriptionBegin(const SubscriptionInfo& info) override {
    if (info.role == Role::Publisher) {
      callback_->onSubscriptionBegin();
    }
  }
  void onSubscriptionEnd(
      const SubscriptionInfo& info,
      const SubscriptionCounters&) override {
    if (info.role == Role::Publisher) {
      callback_->onSubscriptionEnd();
    }
  }
  void onSubscriptionStreamOpened(Direction dir) override {
    if (dir == Direction::Sent) {
      callback_->onSubscriptionStreamOpened();
    }
  }
  void onSubscriptionStreamClosed(Direction dir) override {
    if (dir == Direction::Sent) {
      callback_->onSubscriptionStreamClosed();
    }
  }
  void onSubgroupReset(Direction dir, ResetStreamErrorCode code) override {
    if (dir == Direction::Sent) {
      callback_->onSubgroupReset(code);
    }
  }

  // A request we refused before sending still counts as that request failing,
  // which is what the counter meant before these paths were distinguished from
  // errors that actually came back from the peer.
  void onRequestFailedLocally(FrameType type, const RequestError& err)
      override {
    switch (type) {
      case FrameType::PUBLISH_ERROR:
        callback_->onPublishError(err.errorCode);
        break;
      case FrameType::PUBLISH_NAMESPACE_ERROR:
        callback_->onPublishNamespaceError(err.errorCode);
        break;
      case FrameType::SUBSCRIBE_NAMESPACE_ERROR:
        callback_->onSubscribeNamespaceError(err.errorCode);
        break;
      case FrameType::SUBSCRIBE_ERROR:
        callback_->onSubscribeError(err.errorCode);
        break;
      case FrameType::FETCH_ERROR:
        callback_->onFetchError(err.errorCode);
        break;
      default:
        break;
    }
  }

  void onObjectAckLatency(std::chrono::microseconds latency) override {
    callback_->recordObjectAckLatency(uint64_t(latency.count()));
  }
  void onPublishLatency(std::chrono::milliseconds latency) override {
    callback_->recordPublishLatency(uint64_t(latency.count()));
  }
  void onPublishNamespaceLatency(std::chrono::milliseconds latency) override {
    callback_->recordPublishNamespaceLatency(uint64_t(latency.count()));
  }

 private:
  std::shared_ptr<MoQPublisherStatsCallback> callback_;
};

class MoQSubscriberStatsObserver : public MoQSessionObserver {
 public:
  explicit MoQSubscriberStatsObserver(
      std::shared_ptr<MoQSubscriberStatsCallback> callback)
      : callback_(std::move(callback)) {}

  uint32_t interests() const override {
    return kControl | kSubscription;
  }

  // Subscriber sends SUBSCRIBE and receives the reply -- the mirror of the
  // publisher adapter above.
  void onSubscribeOk(Direction dir, const SubscribeOk&) override {
    if (dir == Direction::Received) {
      callback_->onSubscribeSuccess();
    }
  }
  void onSubscribeError(Direction dir, const SubscribeError& err) override {
    if (dir == Direction::Received) {
      callback_->onSubscribeError(err.errorCode);
    }
  }
  void onFetchOk(Direction dir, const FetchOk&) override {
    if (dir == Direction::Received) {
      callback_->onFetchSuccess();
    }
  }
  void onFetchError(Direction dir, const FetchError& err) override {
    if (dir == Direction::Received) {
      callback_->onFetchError(err.errorCode);
    }
  }
  void onTrackStatus(Direction dir, const TrackStatus&) override {
    if (dir == Direction::Sent) {
      callback_->onTrackStatus();
    }
  }
  void onUnsubscribe(Direction dir, const Unsubscribe&) override {
    if (dir == Direction::Sent) {
      callback_->onUnsubscribe();
    }
  }
  void onRequestUpdate(Direction dir, const RequestUpdate&) override {
    if (dir == Direction::Sent) {
      callback_->onRequestUpdate();
    }
  }
  void onPublishDone(Direction dir, const PublishDone& done) override {
    if (dir == Direction::Received) {
      callback_->onPublishDone(done.statusCode);
    }
  }

  void onPublishNamespaceOk(Direction dir, const PublishNamespaceOk&) override {
    if (dir == Direction::Sent) {
      callback_->onPublishNamespaceSuccess();
    }
  }
  void onPublishNamespaceError(
      Direction dir,
      const PublishNamespaceError& err) override {
    if (dir == Direction::Sent) {
      callback_->onPublishNamespaceError(err.errorCode);
    }
  }
  void onPublishNamespaceDone(Direction dir, const PublishNamespaceDone&)
      override {
    if (dir == Direction::Received) {
      callback_->onPublishNamespaceDone();
    }
  }
  void onPublishNamespaceCancel(Direction dir, const PublishNamespaceCancel&)
      override {
    if (dir == Direction::Sent) {
      callback_->onPublishNamespaceCancel();
    }
  }
  void onSubscribeNamespaceOk(Direction dir, const SubscribeNamespaceOk&)
      override {
    if (dir == Direction::Received) {
      callback_->onSubscribeNamespaceSuccess();
    }
  }
  void onSubscribeNamespaceError(
      Direction dir,
      const SubscribeNamespaceError& err) override {
    if (dir == Direction::Received) {
      callback_->onSubscribeNamespaceError(err.errorCode);
    }
  }
  void onUnsubscribeNamespace(Direction dir, const UnsubscribeNamespace&)
      override {
    if (dir == Direction::Sent) {
      callback_->onUnsubscribeNamespace();
    }
  }
  void onSubscribeTracksOk(Direction dir, const SubscribeTracksOk&) override {
    if (dir == Direction::Received) {
      callback_->onSubscribeTracksSuccess();
    }
  }
  void onSubscribeTracksError(
      Direction dir,
      const SubscribeTracksError& err) override {
    if (dir == Direction::Received) {
      callback_->onSubscribeTracksError(err.errorCode);
    }
  }

  // PUBLISH arrives at the subscriber, which sends the reply.
  void onPublish(Direction dir, const PublishRequest&) override {
    if (dir == Direction::Received) {
      callback_->onPublish();
    }
  }
  void onPublishOk(Direction dir, const PublishOk&) override {
    if (dir == Direction::Sent) {
      callback_->onPublishOk();
    }
  }
  void onPublishError(Direction dir, const PublishError& err) override {
    if (dir == Direction::Sent) {
      callback_->onPublishError(err.errorCode);
    }
  }

  void onSubscriptionBegin(const SubscriptionInfo& info) override {
    if (info.role == Role::Subscriber) {
      callback_->onSubscriptionBegin();
    }
  }
  void onSubscriptionEnd(
      const SubscriptionInfo& info,
      const SubscriptionCounters&) override {
    if (info.role == Role::Subscriber) {
      callback_->onSubscriptionEnd();
    }
  }
  void onSubscriptionStreamOpened(Direction dir) override {
    if (dir == Direction::Received) {
      callback_->onSubscriptionStreamOpened();
    }
  }
  void onSubscriptionStreamClosed(Direction dir) override {
    if (dir == Direction::Received) {
      callback_->onSubscriptionStreamClosed();
    }
  }
  void onSubgroupReset(Direction dir, ResetStreamErrorCode code) override {
    if (dir == Direction::Received) {
      callback_->onSubgroupReset(code);
    }
  }

  // See the publisher adapter: a locally-refused request still increments the
  // same failure counter it did before.
  void onRequestFailedLocally(FrameType type, const RequestError& err)
      override {
    switch (type) {
      case FrameType::SUBSCRIBE_ERROR:
        callback_->onSubscribeError(err.errorCode);
        break;
      case FrameType::FETCH_ERROR:
        callback_->onFetchError(err.errorCode);
        break;
      case FrameType::SUBSCRIBE_NAMESPACE_ERROR:
        callback_->onSubscribeNamespaceError(err.errorCode);
        break;
      case FrameType::PUBLISH_NAMESPACE_ERROR:
        callback_->onPublishNamespaceError(err.errorCode);
        break;
      case FrameType::PUBLISH_ERROR:
        callback_->onPublishError(err.errorCode);
        break;
      default:
        break;
    }
  }

  void onSubscribeLatency(std::chrono::milliseconds latency) override {
    callback_->recordSubscribeLatency(uint64_t(latency.count()));
  }
  void onFetchLatency(std::chrono::milliseconds latency) override {
    callback_->recordFetchLatency(uint64_t(latency.count()));
  }

 private:
  std::shared_ptr<MoQSubscriberStatsCallback> callback_;
};

} // namespace moxygen
