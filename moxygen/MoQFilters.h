#pragma once

#include <moxygen/MoQConsumers.h>
#include <moxygen/events/MoQExecutor.h>

namespace moxygen {

// Filter that dispatches SubgroupConsumer calls to a specific executor.
// Returns success immediately; errors mark the consumer for removal.
class ExecutorSubgroupConsumerFilter
    : public SubgroupConsumer,
      public std::enable_shared_from_this<ExecutorSubgroupConsumerFilter> {
 public:
  explicit ExecutorSubgroupConsumerFilter(std::shared_ptr<MoQExecutor> exec)
      : exec_(std::move(exec)) {}

  bool failed() const {
    return failed_;
  }

  // Set by ExecutorTrackConsumerFilter after beginSubgroup completes
  std::shared_ptr<SubgroupConsumer> downstream_;

  folly::Expected<folly::Unit, MoQPublishError> object(
      uint64_t objectID,
      Payload payload,
      Extensions extensions,
      bool finSubgroup) override {
    return dispatch([=, payload = std::move(payload)]() mutable {
      return downstream_->object(
          objectID, std::move(payload), extensions, finSubgroup);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> objectNotExists(
      uint64_t objectID,
      bool finSubgroup) override {
    return dispatch(
        [=]() { return downstream_->objectNotExists(objectID, finSubgroup); });
  }

  folly::Expected<folly::Unit, MoQPublishError> beginObject(
      uint64_t objectID,
      uint64_t length,
      Payload initialPayload,
      Extensions extensions) override {
    auto payloadLength =
        initialPayload ? initialPayload->computeChainDataLength() : 0;
    auto res = lengthTracker_.beginObject(length, payloadLength);
    if (res.hasError()) {
      return res;
    }
    return dispatch([=, initialPayload = std::move(initialPayload)]() mutable {
      return downstream_->beginObject(
          objectID, length, std::move(initialPayload), extensions);
    });
  }

  folly::Expected<ObjectPublishStatus, MoQPublishError> objectPayload(
      Payload payload,
      bool finSubgroup) override {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto payloadLength = payload ? payload->computeChainDataLength() : 0;
    auto status = lengthTracker_.objectPayload(payloadLength);
    if (status.hasError()) {
      return status;
    }
    auto self = shared_from_this();
    exec_->add([self, payload = std::move(payload), finSubgroup]() mutable {
      if (!self->downstream_) {
        self->failed_ = true;
        return;
      }
      auto res =
          self->downstream_->objectPayload(std::move(payload), finSubgroup);
      if (res.hasError()) {
        self->failed_ = true;
      }
    });
    return status;
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfGroup(
      uint64_t endOfGroupObjectID) override {
    return dispatch(
        [=]() { return downstream_->endOfGroup(endOfGroupObjectID); });
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfTrackAndGroup(
      uint64_t endOfTrackObjectID) override {
    return dispatch(
        [=]() { return downstream_->endOfTrackAndGroup(endOfTrackObjectID); });
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfSubgroup() override {
    return dispatch([=]() { return downstream_->endOfSubgroup(); });
  }

  void reset(ResetStreamErrorCode error) override {
    failed_ = true;
    lengthTracker_.reset();
    auto self = shared_from_this();
    exec_->add([self, error]() {
      if (self->downstream_) {
        self->downstream_->reset(error);
      }
    });
  }

  friend class ExecutorTrackConsumerFilter;

 private:
  template <typename Fn>
  folly::Expected<folly::Unit, MoQPublishError> dispatch(Fn&& fn) {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto self = shared_from_this();
    exec_->add([self, fn = std::forward<Fn>(fn)]() mutable {
      if (!self->downstream_) {
        self->failed_ = true;
        return;
      }
      auto res = fn();
      if (res.hasError()) {
        self->failed_ = true;
      }
    });
    return folly::unit;
  }

  std::shared_ptr<MoQExecutor> exec_;
  std::atomic<bool> failed_{false};
  ObjectLengthTracker lengthTracker_;
};

// Filter that dispatches TrackConsumer calls to a specific executor.
// Returns success immediately; errors mark the consumer for removal.
class ExecutorTrackConsumerFilter
    : public TrackConsumer,
      public std::enable_shared_from_this<ExecutorTrackConsumerFilter> {
 public:
  explicit ExecutorTrackConsumerFilter(std::shared_ptr<MoQExecutor> exec)
      : exec_(std::move(exec)) {}

  ExecutorTrackConsumerFilter(
      std::shared_ptr<MoQExecutor> exec,
      std::shared_ptr<TrackConsumer> downstream)
      : exec_(std::move(exec)), downstream_(std::move(downstream)) {}

  bool failed() const {
    return failed_;
  }

  // Set after construction (e.g., by reply Task in publish)
  std::shared_ptr<TrackConsumer> downstream_;

  folly::Expected<folly::Unit, MoQPublishError> setTrackAlias(
      TrackAlias alias) override {
    return dispatch([=]() { return downstream_->setTrackAlias(alias); });
  }

  folly::Expected<std::shared_ptr<SubgroupConsumer>, MoQPublishError>
  beginSubgroup(uint64_t groupID, uint64_t subgroupID, Priority priority)
      override {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto filter = std::make_shared<ExecutorSubgroupConsumerFilter>(exec_);
    auto self = shared_from_this();
    exec_->add([self, filter, groupID, subgroupID, priority]() {
      auto res =
          self->downstream_->beginSubgroup(groupID, subgroupID, priority);
      if (res.hasError()) {
        self->failed_ = true;
        filter->failed_ = true;
      } else {
        filter->downstream_ = std::move(res.value());
      }
    });
    return filter;
  }

  folly::Expected<folly::SemiFuture<folly::Unit>, MoQPublishError>
  awaitStreamCredit() override {
    return folly::makeSemiFuture();
  }

  folly::Expected<folly::Unit, MoQPublishError> objectStream(
      const ObjectHeader& header,
      Payload payload) override {
    return dispatch([=, payload = std::move(payload)]() mutable {
      return downstream_->objectStream(header, std::move(payload));
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> datagram(
      const ObjectHeader& header,
      Payload payload) override {
    return dispatch([=, payload = std::move(payload)]() mutable {
      return downstream_->datagram(header, std::move(payload));
    });
  }

  folly::Expected<folly::Unit, MoQPublishError>
  groupNotExists(uint64_t groupID, uint64_t subgroup, Priority pri) override {
    return dispatch(
        [=]() { return downstream_->groupNotExists(groupID, subgroup, pri); });
  }

  folly::Expected<folly::Unit, MoQPublishError> subscribeDone(
      SubscribeDone subDone) override {
    return dispatch([=, subDone = std::move(subDone)]() mutable {
      return downstream_->subscribeDone(std::move(subDone));
    });
  }

  void setDeliveryCallback(
      std::shared_ptr<DeliveryCallback> callback) override {
    auto self = shared_from_this();
    exec_->add([self, callback = std::move(callback)]() mutable {
      self->downstream_->setDeliveryCallback(std::move(callback));
    });
  }

 private:
  template <typename Fn>
  folly::Expected<folly::Unit, MoQPublishError> dispatch(Fn&& fn) {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto self = shared_from_this();
    exec_->add([self, fn = std::forward<Fn>(fn)]() mutable {
      if (!self->downstream_) {
        self->failed_ = true;
        return;
      }
      auto res = fn();
      if (res.hasError()) {
        self->failed_ = true;
      }
    });
    return folly::unit;
  }

  std::shared_ptr<MoQExecutor> exec_;
  std::atomic<bool> failed_{false};
};

// Filter that dispatches FetchConsumer calls to a specific executor.
// Returns success immediately; errors mark the consumer for removal.
class ExecutorFetchConsumerFilter
    : public FetchConsumer,
      public std::enable_shared_from_this<ExecutorFetchConsumerFilter> {
 public:
  ExecutorFetchConsumerFilter(
      std::shared_ptr<MoQExecutor> exec,
      std::shared_ptr<FetchConsumer> downstream)
      : exec_(std::move(exec)), downstream_(std::move(downstream)) {}

  bool failed() const {
    return failed_;
  }

  folly::Expected<folly::Unit, MoQPublishError> object(
      uint64_t groupID,
      uint64_t subgroupID,
      uint64_t objectID,
      Payload payload,
      Extensions extensions,
      bool finFetch) override {
    return dispatch([=, payload = std::move(payload)]() mutable {
      return downstream_->object(
          groupID, subgroupID, objectID, std::move(payload), extensions,
          finFetch);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> objectNotExists(
      uint64_t groupID,
      uint64_t subgroupID,
      uint64_t objectID,
      bool finFetch) override {
    return dispatch([=]() {
      return downstream_->objectNotExists(
          groupID, subgroupID, objectID, finFetch);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> groupNotExists(
      uint64_t groupID,
      uint64_t subgroupID,
      bool finFetch) override {
    return dispatch([=]() {
      return downstream_->groupNotExists(groupID, subgroupID, finFetch);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> beginObject(
      uint64_t groupID,
      uint64_t subgroupID,
      uint64_t objectID,
      uint64_t length,
      Payload initialPayload,
      Extensions extensions) override {
    auto payloadLength =
        initialPayload ? initialPayload->computeChainDataLength() : 0;
    auto res = lengthTracker_.beginObject(length, payloadLength);
    if (res.hasError()) {
      return res;
    }
    return dispatch([=, initialPayload = std::move(initialPayload)]() mutable {
      return downstream_->beginObject(
          groupID, subgroupID, objectID, length, std::move(initialPayload),
          extensions);
    });
  }

  folly::Expected<ObjectPublishStatus, MoQPublishError> objectPayload(
      Payload payload,
      bool finSubgroup) override {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto payloadLength = payload ? payload->computeChainDataLength() : 0;
    auto status = lengthTracker_.objectPayload(payloadLength);
    if (status.hasError()) {
      return status;
    }
    auto self = shared_from_this();
    exec_->add([self, payload = std::move(payload), finSubgroup]() mutable {
      auto res =
          self->downstream_->objectPayload(std::move(payload), finSubgroup);
      if (res.hasError()) {
        self->failed_ = true;
      }
    });
    return status;
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfGroup(
      uint64_t groupID,
      uint64_t subgroupID,
      uint64_t objectID,
      bool finFetch) override {
    return dispatch([=]() {
      return downstream_->endOfGroup(groupID, subgroupID, objectID, finFetch);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfTrackAndGroup(
      uint64_t groupID,
      uint64_t subgroupID,
      uint64_t objectID) override {
    return dispatch([=]() {
      return downstream_->endOfTrackAndGroup(groupID, subgroupID, objectID);
    });
  }

  folly::Expected<folly::Unit, MoQPublishError> endOfFetch() override {
    return dispatch([=]() { return downstream_->endOfFetch(); });
  }

  void reset(ResetStreamErrorCode error) override {
    failed_ = true;
    lengthTracker_.reset();
    auto self = shared_from_this();
    exec_->add([self, error]() { self->downstream_->reset(error); });
  }

  folly::Expected<folly::SemiFuture<uint64_t>, MoQPublishError>
  awaitReadyToConsume() override {
    return folly::makeSemiFuture<uint64_t>(0);
  }

 private:
  template <typename Fn>
  folly::Expected<folly::Unit, MoQPublishError> dispatch(Fn&& fn) {
    if (failed_) {
      return folly::makeUnexpected(
          MoQPublishError(MoQPublishError::CANCELLED, "Consumer failed"));
    }
    auto self = shared_from_this();
    exec_->add([self, fn = std::forward<Fn>(fn)]() mutable {
      auto res = fn();
      if (res.hasError()) {
        self->failed_ = true;
      }
    });
    return folly::unit;
  }

  std::shared_ptr<MoQExecutor> exec_;
  std::shared_ptr<FetchConsumer> downstream_;
  std::atomic<bool> failed_{false};
  ObjectLengthTracker lengthTracker_;
};

class TrackConsumerFilter : public TrackConsumer {
 public:
  explicit TrackConsumerFilter(std::shared_ptr<TrackConsumer> downstream)
      : downstream_(std::move(downstream)) {}

  folly::Expected<folly::Unit, MoQPublishError> setTrackAlias(
      TrackAlias alias) override {
    return downstream_->setTrackAlias(alias);
  }

  folly::Expected<std::shared_ptr<SubgroupConsumer>, MoQPublishError>
  beginSubgroup(uint64_t groupID, uint64_t subgroupID, Priority priority)
      override {
    return downstream_->beginSubgroup(groupID, subgroupID, priority);
  }

  folly::Expected<folly::SemiFuture<folly::Unit>, MoQPublishError>
  awaitStreamCredit() override {
    return downstream_->awaitStreamCredit();
  }

  folly::Expected<folly::Unit, MoQPublishError> objectStream(
      const ObjectHeader& header,
      Payload payload) override {
    return downstream_->objectStream(header, std::move(payload));
  }

  folly::Expected<folly::Unit, MoQPublishError> datagram(
      const ObjectHeader& header,
      Payload payload) override {
    return downstream_->datagram(header, std::move(payload));
  }

  folly::Expected<folly::Unit, MoQPublishError>
  groupNotExists(uint64_t groupID, uint64_t subgroup, Priority pri) override {
    return downstream_->groupNotExists(groupID, subgroup, pri);
  }

  folly::Expected<folly::Unit, MoQPublishError> subscribeDone(
      SubscribeDone subDone) override {
    return downstream_->subscribeDone(std::move(subDone));
  }

  void setDeliveryCallback(
      std::shared_ptr<DeliveryCallback> callback) override {
    downstream_->setDeliveryCallback(std::move(callback));
  }

 private:
  std::shared_ptr<TrackConsumer> downstream_;
};

} // namespace moxygen
