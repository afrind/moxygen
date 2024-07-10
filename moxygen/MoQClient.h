/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "moxygen/MoQSession.h"

#include <folly/experimental/coro/Promise.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>
#include <proxygen/lib/http/webtransport/QuicWebTransport.h>
#include <proxygen/lib/utils/URL.h>

namespace moxygen {

class MoQClient : public proxygen::QuicWebTransport::Handler {
 public:
  enum class TransportType { H3_WEBTRANSPORT, QUIC };
  MoQClient(
      folly::EventBase* evb,
      proxygen::URL url,
      TransportType ttype = TransportType::H3_WEBTRANSPORT)
      : evb_(evb), url_(std::move(url)), transportType_(ttype) {}

  folly::EventBase* getEventBase() {
    return evb_;
  }

  class HTTPHandler : public proxygen::HTTPTransactionHandler {
   public:
    explicit HTTPHandler(MoQClient& client) : client_(client) {}

    void setTransaction(proxygen::HTTPTransaction* txn) noexcept override {
      txn_ = txn;
    }
    void detachTransaction() noexcept override {}
    void onHeadersComplete(
        std::unique_ptr<proxygen::HTTPMessage> resp) noexcept override;

    void onBody(std::unique_ptr<folly::IOBuf>) noexcept override {}
    void onTrailers(std::unique_ptr<proxygen::HTTPHeaders>) noexcept override {}
    void onUpgrade(proxygen::UpgradeProtocol) noexcept override {}
    void onEgressPaused() noexcept override {}
    void onEgressResumed() noexcept override {}

    void onEOM() noexcept override {
      client_.onSessionEnd(folly::none);
    }
    void onError(const proxygen::HTTPException& ex) noexcept override;
    void onWebTransportBidiStream(
        proxygen::HTTPCodec::StreamID,
        proxygen::WebTransport::BidiStreamHandle handle) noexcept override {
      client_.onWebTransportBidiStream(std::move(handle));
    }
    void onWebTransportUniStream(
        proxygen::HTTPCodec::StreamID,
        proxygen::WebTransport::StreamReadHandle* handle) noexcept override {
      client_.onWebTransportUniStream(handle);
    }
    void onDatagram(std::unique_ptr<folly::IOBuf> datagram) noexcept override {
      client_.onDatagram(std::move(datagram));
    }

    MoQClient& client_;
    proxygen::HTTPTransaction* txn_{nullptr};
    std::pair<
        folly::coro::Promise<std::shared_ptr<MoQSession>>,
        folly::coro::Future<std::shared_ptr<MoQSession>>>
        sessionContract{
            folly::coro::makePromiseContract<std::shared_ptr<MoQSession>>()};
  };

  std::shared_ptr<MoQSession> moqSession_;
  folly::coro::Task<void> setupMoQSession(
      std::chrono::milliseconds connect_timeout,
      std::chrono::milliseconds transaction_timeout,
      Role role = Role::PUB_AND_SUB) noexcept;

 private:
  folly::coro::Task<void> setupMoQQuicSession(
      std::chrono::milliseconds connect_timeout,
      Role role) noexcept;

  void onSessionEnd(folly::Optional<proxygen::HTTPException> ex);
  void onWebTransportBidiStream(
      proxygen::HTTPCodec::StreamID,
      proxygen::WebTransport::BidiStreamHandle handle) noexcept override {
    onWebTransportBidiStream(std::move(handle));
  }
  void onWebTransportUniStream(
      proxygen::HTTPCodec::StreamID,
      proxygen::WebTransport::StreamReadHandle* handle) noexcept override {
    onWebTransportUniStream(handle);
  }

  void onWebTransportBidiStream(
      proxygen::WebTransport::BidiStreamHandle handle);
  void onWebTransportUniStream(
      proxygen::WebTransport::StreamReadHandle* handle);
  void onDatagram(std::unique_ptr<folly::IOBuf>) noexcept override;

  folly::EventBase* evb_{nullptr};
  proxygen::URL url_;
  HTTPHandler httpHandler_{*this};
  TransportType transportType_;
  std::shared_ptr<proxygen::QuicWebTransport> quicWebTransport_;
};

} // namespace moxygen
