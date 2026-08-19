/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/SocketAddress.h>
#include <folly/container/small_vector.h>
#include <quic/codec/QuicConnectionId.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <moxygen/MoQFramer.h>

namespace moxygen {

/*
 * MoQSessionObserver is the single per-session instrumentation interface.
 *
 * It consolidates what used to be two parallel mechanisms hanging off
 * MoQSession: MLogger (qlog-style protocol tracing) and MoQStatsCallback
 * (aggregate counters). Both are now observers, so a session notifies each
 * event exactly once and each observer decides what to do with it.
 *
 * Two properties matter for the cost of this interface:
 *
 * 1. Every method takes moxygen's own types, never a logging schema type.
 *    Translation to the qlog MOQT* structs happens inside MLogger, so an
 *    observer that does not care about an event pays one virtual call rather
 *    than the cost of building a record nobody reads.
 *
 * 2. Every method has an empty default. Implementations override only what
 *    they consume, and declare the tiers they want via interests().
 *
 * Observers are notified in registration order. An observer MUST NOT call back
 * into the session that is notifying it; these are pure sinks.
 */
class MoQSessionObserver {
 public:
  virtual ~MoQSessionObserver() = default;

  /*
   * Which side of the wire an event happened on. Sent means this endpoint
   * produced the message (MLogger's ControlMessageType::CREATED); Received
   * means it came off the wire (ControlMessageType::PARSED).
   *
   * Where a control event fires relative to validation is part of the
   * contract, because the two directions want opposite things:
   *
   *   Received: reported straight after parse, BEFORE request-ID validation,
   *     GOAWAY checks or any other early return. A consumer needs to see the
   *     requests this session rejects, not just the ones it accepts -- an
   *     access log that cannot log its 4xx is not an access log.
   *
   *   Sent: reported AFTER the frame has been written. A message whose
   *     serialization failed never reached the peer, so reporting it would
   *     describe something that did not happen.
   *
   * The old code was not consistent about this: the stats callback and the
   * mlog record for the same event sometimes sat on opposite sides of a
   * validation check or a write. Collapsing them onto one notification forces
   * a single answer, and this is it.
   */
  enum class Direction : uint8_t { Sent, Received };

  /*
   * Our role in a subscription, for the events that bracket one.
   */
  enum class Role : uint8_t { Publisher, Subscriber };

  /*
   * mlog's notion of stream type, which is coarser than the wire-level
   * moxygen::StreamType (it does not distinguish subgroup header variants).
   */
  enum class ObservedStreamType : uint8_t { Control, SubgroupHeader, FetchHeader };

  /*
   * Interest tiers. An observer opts in to the tiers it consumes; the session
   * keeps the union of all registered observers' interests and skips the work
   * of preparing an event nobody wants. kObject is the data-plane hot path and
   * should only be requested by tracing observers.
   */
  enum Interest : uint32_t {
    kControl = 1u << 0,      // control messages, once per request/response
    kSubscription = 1u << 1, // subscription lifecycle + counters
    kObject = 1u << 2,       // per-object data plane (HOT)
  };

  /*
   * Defaults to interested in nothing, so a partially-implemented observer
   * costs nothing rather than silently taking the hot path.
   */
  virtual uint32_t interests() const {
    return 0;
  }

  /*
   * Connection metadata, known once the session is set up. This absorbs the
   * individual setDcid/setPeerAddress/... setters MLogger used to expose.
   */
  struct SessionContext {
    std::optional<folly::SocketAddress> localAddress;
    std::optional<folly::SocketAddress> peerAddress;
    std::optional<quic::ConnectionId> dcid;
    std::optional<quic::ConnectionId> srcCid;
    std::optional<uint64_t> negotiatedVersion;
    std::vector<std::string> experiments;
  };

  /*
   * Identifies a subscription across its begin/end bracket.
   */
  struct SubscriptionInfo {
    RequestID requestID{0};
    FullTrackName fullTrackName;
    std::optional<TrackAlias> trackAlias;
    Role role{Role::Publisher};
    // When the request that created this subscription was issued. Observers
    // derive their own latency from this rather than the session computing a
    // single number for everyone.
    std::chrono::steady_clock::time_point startTime{};
  };

  /*
   * What a subscription actually delivered, accumulated over its lifetime and
   * reported once at onSubscriptionEnd.
   */
  struct SubscriptionCounters {
    uint64_t objects{0};
    uint64_t bytes{0};
    uint64_t groups{0};
    std::optional<PublishDoneStatusCode> endReason;
  };

  // ---- Session lifecycle -------------------------------------------------

  /*
   * Session metadata. Fires more than once: the transport half (addresses,
   * connection IDs) is known before version negotiation, and the negotiated
   * version only after it. Each call carries the fullest context known so far,
   * so treat it as an upsert of the fields that are set rather than as a
   * one-shot start event. A session whose handshake fails gets the first call
   * and not the second.
   */
  virtual void onSessionStart(const SessionContext&) {}
  virtual void onSessionEnd(std::optional<SessionCloseErrorCode>) {}

  // ---- Setup -------------------------------------------------------------

  virtual void onClientSetup(Direction, const ClientSetup&, uint64_t) {}
  virtual void onServerSetup(Direction, const ServerSetup&, uint64_t) {}

  // ---- Control messages --------------------------------------------------

  virtual void onSubscribe(Direction, const SubscribeRequest&) {}
  virtual void onSubscribeOk(Direction, const SubscribeOk&) {}
  virtual void onSubscribeError(Direction, const SubscribeError&) {}
  virtual void onRequestUpdate(Direction, const RequestUpdate&) {}
  virtual void onUnsubscribe(Direction, const Unsubscribe&) {}

  virtual void onFetch(Direction, const Fetch&) {}
  virtual void onFetchOk(Direction, const FetchOk&) {}
  virtual void onFetchError(Direction, const FetchError&) {}
  virtual void onFetchCancel(Direction, const FetchCancel&) {}

  virtual void onPublish(Direction, const PublishRequest&) {}
  virtual void onPublishOk(Direction, const PublishOk&) {}
  virtual void onPublishError(Direction, const PublishError&) {}
  virtual void onPublishDone(Direction, const PublishDone&) {}

  virtual void onPublishNamespace(Direction, const PublishNamespace&) {}
  virtual void onPublishNamespaceOk(Direction, const PublishNamespaceOk&) {}
  virtual void onPublishNamespaceError(Direction, const PublishNamespaceError&) {
  }
  virtual void onPublishNamespaceDone(Direction, const PublishNamespaceDone&) {}
  virtual void onPublishNamespaceCancel(
      Direction,
      const PublishNamespaceCancel&) {}

  virtual void onSubscribeNamespace(Direction, const SubscribeNamespace&) {}
  virtual void onSubscribeNamespaceOk(Direction, const SubscribeNamespaceOk&) {}
  virtual void onSubscribeNamespaceError(
      Direction,
      const SubscribeNamespaceError&) {}
  virtual void onUnsubscribeNamespace(Direction, const UnsubscribeNamespace&) {}

  // SUBSCRIBE_TRACKS (draft 18+) has counters but no mlog record today.
  virtual void onSubscribeTracksOk(Direction, const SubscribeTracksOk&) {}
  virtual void onSubscribeTracksError(Direction, const SubscribeTracksError&) {}

  virtual void onTrackStatus(Direction, const TrackStatus&) {}
  virtual void onTrackStatusOk(Direction, const TrackStatusOk&) {}
  virtual void onTrackStatusError(Direction, const TrackStatusError&) {}

  virtual void onGoaway(Direction, const Goaway&) {}
  virtual void onMaxRequestID(Direction, uint64_t) {}
  virtual void onRequestsBlocked(Direction, uint64_t) {}

  /*
   * A request that failed without an error frame arriving from the peer: the
   * session was draining, a GOAWAY had been received, a joining FETCH could
   * not be resolved, the send failed, or the session was torn down while the
   * request was still outstanding.
   *
   * The FrameType is the *error* frame type this request would have produced
   * (SUBSCRIBE_ERROR, FETCH_ERROR, ...), matching both
   * PendingRequestState::getErrorFrameType() and notifyRequestError(), so
   * locally- and remotely-sourced failures are described the same way.
   *
   * This is deliberately not reported as an error in either Direction. Nothing
   * was sent, so Direction::Sent would describe a frame that does not exist,
   * and nothing arrived, so Direction::Received would be a fabrication.
   *
   * It is terminal on arrival: because the request never reached the peer, no
   * response can ever match it, so an observer must complete it here rather
   * than opening a pending entry that would dangle for the life of the
   * session.
   */
  virtual void onRequestFailedLocally(FrameType, const RequestError&) {}

  // ---- Subscription lifecycle -------------------------------------------

  /*
   * A subscription became active (SUBSCRIBE_OK sent/received, or a PUBLISH
   * accepted). Pairs exactly once with onSubscriptionEnd, so the difference is
   * a non-negative gauge of active subscriptions.
   */
  virtual void onSubscriptionBegin(const SubscriptionInfo&) {}
  virtual void onSubscriptionEnd(
      const SubscriptionInfo&,
      const SubscriptionCounters&) {}

  /*
   * Direction::Sent means we opened/closed an outbound subscription stream;
   * Received means the peer did so toward us.
   */
  virtual void onSubscriptionStreamOpened(Direction) {}
  virtual void onSubscriptionStreamClosed(Direction) {}

  /*
   * Sent: we reset an outbound subgroup. Received: the peer reset an inbound
   * stream to us.
   */
  virtual void onSubgroupReset(Direction, ResetStreamErrorCode) {}

  /*
   * Time from handing an object to QUIC until its bytes are acked. Subgroup
   * stream path only; datagrams have no ack mechanism.
   */
  virtual void onObjectAckLatency(std::chrono::microseconds) {}

  /*
   * Request-to-response latency, measured by the session at the point the
   * response lands. SubscriptionInfo::startTime lets an observer derive its
   * own timings for subscriptions, but these requests are not all
   * subscriptions and the session already has the measurement in hand, so
   * reporting it directly avoids making every observer keep a pending-request
   * map just to recover a number the session already computed.
   */
  virtual void onSubscribeLatency(std::chrono::milliseconds) {}
  virtual void onFetchLatency(std::chrono::milliseconds) {}
  virtual void onPublishLatency(std::chrono::milliseconds) {}
  virtual void onPublishNamespaceLatency(std::chrono::milliseconds) {}

  // ---- Object tier (HOT: gated on Interest::kObject) ---------------------

  virtual void onStreamTypeSet(Direction, uint64_t, ObservedStreamType) {}

  virtual void onDatagramObject(
      Direction,
      TrackAlias,
      const ObjectHeader&,
      const Payload&) {}

  virtual void onSubgroupHeader(
      Direction,
      uint64_t /*streamID*/,
      TrackAlias,
      uint64_t /*groupID*/,
      uint64_t /*subgroupID*/,
      uint8_t /*publisherPriority*/,
      const SubgroupOptions&) {}

  virtual void onSubgroupObject(
      Direction,
      uint64_t /*streamID*/,
      TrackAlias,
      const ObjectHeader&,
      const Payload&) {}

  virtual void onFetchHeader(
      Direction,
      uint64_t /*streamID*/,
      uint64_t /*requestID*/) {}

  virtual void onFetchObject(
      Direction,
      uint64_t /*streamID*/,
      const ObjectHeader&,
      const Payload&) {}
};

/*
 * The set of observers attached to one session.
 *
 * MoQSession owns one of these and shares it (by shared_ptr) with the per-
 * stream and per-track helper objects that used to each carry their own
 * MLogger pointer. Holding the list rather than a single observer is what lets
 * a second consumer attach without the data plane growing a second check.
 *
 * Not thread safe: a session's observers are added during setup and notified
 * on that session's own executor.
 */
class MoQSessionObserverList {
 public:
  void add(std::shared_ptr<MoQSessionObserver> observer) {
    if (!observer) {
      return;
    }
    interests_ |= observer->interests();
    observers_.emplace_back(std::move(observer));
  }

  void remove(const std::shared_ptr<MoQSessionObserver>& observer) {
    auto it = std::find(observers_.begin(), observers_.end(), observer);
    if (it == observers_.end()) {
      return;
    }
    observers_.erase(it);
    recomputeInterests();
  }

  bool empty() const {
    return observers_.empty();
  }

  uint32_t interests() const {
    return interests_;
  }

  bool interested(MoQSessionObserver::Interest interest) const {
    return (interests_ & interest) != 0;
  }

  /*
   * Invoke fn on each observer that opted into `interest`. Returns immediately
   * when no observer wants the tier, which is the fast path the data plane
   * relies on.
   */
  template <typename Fn>
  void forEach(MoQSessionObserver::Interest interest, Fn&& fn) const {
    if ((interests_ & interest) == 0) {
      return;
    }
    for (const auto& observer : observers_) {
      if (observer->interests() & interest) {
        fn(*observer);
      }
    }
  }

 private:
  void recomputeInterests() {
    interests_ = 0;
    for (const auto& observer : observers_) {
      interests_ |= observer->interests();
    }
  }

  folly::small_vector<std::shared_ptr<MoQSessionObserver>, 2> observers_;
  uint32_t interests_{0};
};

namespace detail {
inline const MoQSessionObserverList* observerList(
    const MoQSessionObserverList& list) {
  return &list;
}
inline const MoQSessionObserverList* observerList(
    const MoQSessionObserverList* list) {
  return list;
}
inline const MoQSessionObserverList* observerList(
    const std::shared_ptr<MoQSessionObserverList>& list) {
  return list.get();
}
} // namespace detail

/*
 * Notify every observer interested in `tier`. `call` is a method call on the
 * observer, e.g.
 *
 *   MOQ_OBSERVE(observers_, kControl, onSubscribeOk(Direction::Received, ok));
 *
 * `list` may be a MoQSessionObserverList, or a pointer/shared_ptr to one; a
 * null pointer is a no-op so helper objects that were built before observers
 * were attached stay safe.
 */
#define MOQ_OBSERVE(list, tier, call)                              \
  do {                                                             \
    if (auto* moqObserverList_ = ::moxygen::detail::observerList(list)) { \
      moqObserverList_->forEach(                                   \
          ::moxygen::MoQSessionObserver::tier,                     \
          [&](::moxygen::MoQSessionObserver& moqObserver_) {       \
            moqObserver_.call;                                     \
          });                                                      \
    }                                                              \
  } while (0)

/*
 * Tier-specific spellings, which are what call sites should use. Naming the
 * tier in the macro rather than passing it keeps `grep MOQ_OBSERVE_OBJECT`
 * an exact census of the hot path.
 *
 * Note these do not make the tier safe, only shorter: the tier still has to
 * agree with the method being called, and a mismatch routes the event to the
 * wrong observers without complaint.
 */
#define MOQ_OBSERVE_CONTROL(list, call) MOQ_OBSERVE(list, kControl, call)
#define MOQ_OBSERVE_SUBSCRIPTION(list, call) \
  MOQ_OBSERVE(list, kSubscription, call)
#define MOQ_OBSERVE_OBJECT(list, call) MOQ_OBSERVE(list, kObject, call)

} // namespace moxygen
