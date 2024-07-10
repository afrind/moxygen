/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/MoQClient.h"

#include <folly/futures/ThreadWheelTimekeeper.h>
#include <proxygen/httpserver/samples/hq/InsecureVerifierDangerousDoNotUseInProduction.h>
#include <proxygen/lib/http/HQConnector.h>
#include <quic/api/QuicSocket.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

namespace {

class ConnectCB {
 public:
  explicit ConnectCB(
      folly::EventBase* evb = nullptr,
      std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) {
    auto contract = folly::coro::makePromiseContract<folly::Unit>();
    promise = std::move(contract.first);
    future = std::move(contract.second);
  }

  void connectSuccess() noexcept {
    promise.setValue(folly::unit);
  }

  std::optional<folly::AsyncSocketException> exception;
  folly::coro::Promise<folly::Unit> promise;
  folly::coro::Future<folly::Unit> future;
};

class QuicConnectCB : public quic::QuicSocket::ConnectionSetupCallback,
                      public ConnectCB {
 public:
  QuicConnectCB(
      folly::EventBase* evb,
      std::chrono::milliseconds timeout,
      std::shared_ptr<quic::QuicClientTransport> quicClient,
      folly::CancellationToken cancellationToken)
      : ConnectCB(evb, timeout),
        quicClient_(std::move(quicClient)),
        cancellationToken_(std::move(cancellationToken)) {}

  folly::exception_wrapper quicException;

 private:
  void quicConnectErr(folly::exception_wrapper ex) noexcept {
    quicException = std::move(ex);
    promise.setValue(folly::unit);
  }
  void onConnectionSetupError(quic::QuicError error) noexcept override {
    switch (error.code.type()) {
      case quic::QuicErrorCode::Type::ApplicationErrorCode:
        quicConnectErr(quic::QuicApplicationException(
            error.message, *error.code.asApplicationErrorCode()));
        break;
      case quic::QuicErrorCode::Type::LocalErrorCode:
        quicConnectErr(quic::QuicInternalException(
            error.message, *error.code.asLocalErrorCode()));
        break;
      case quic::QuicErrorCode::Type::TransportErrorCode:
        quicConnectErr(quic::QuicTransportException(
            error.message, *error.code.asTransportErrorCode()));
        break;
    }
  }
  void onReplaySafe() noexcept override {}
  void onTransportReady() noexcept override {
    if (cancellationToken_.isCancellationRequested()) {
      quicConnectErr(quic::QuicTransportException(
          "Connection has been cancelled",
          quic::TransportErrorCode::INTERNAL_ERROR));
    }
    connectSuccess();
  }
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  folly::CancellationToken cancellationToken_;
};

folly::coro::Task<std::shared_ptr<quic::QuicClientTransport>> connectQuic(
    folly::EventBase* eventBase,
    folly::SocketAddress connectAddr,
    std::chrono::milliseconds timeoutMs) {
  auto qEvb = std::make_shared<quic::FollyQuicEventBase>(eventBase);
  auto sock = std::make_unique<quic::FollyQuicAsyncUDPSocket>(qEvb);
  auto fizzContext = std::make_shared<fizz::client::FizzClientContext>();
  fizzContext->setSupportedAlpns({"moq-00"});
  auto quicClient = quic::QuicClientTransport::newClient(
      std::move(qEvb),
      std::move(sock),
      quic::FizzClientQuicHandshakeContext::Builder()
          .setFizzClientContext(fizzContext)
          .setCertificateVerifier(
              std::make_shared<
                  proxygen::InsecureVerifierDangerousDoNotUseInProduction>())
          .build(),
      /*connectionIdSize=*/0);
  quicClient->addNewPeerAddress(connectAddr);
  quicClient->setSupportedVersions({quic::QuicVersion::QUIC_V1});
  folly::CancellationToken cancellationToken =
      co_await folly::coro::co_current_cancellation_token;
  QuicConnectCB cb(
      eventBase, timeoutMs, quicClient, std::move(cancellationToken));
  quicClient->start(&cb, nullptr);
  folly::EventBaseThreadTimekeeper tk(*eventBase);
  auto res = co_await co_awaitTry(
      folly::coro::timeout(std::move(cb.future), timeoutMs, &tk));
  quicClient->setConnectionSetupCallback(nullptr);
  if (res.hasException()) {
    quic::ApplicationErrorCode err(0);
    std::string errString = (res.tryGetExceptionObject<folly::FutureTimeout>())
        ? "Connect timed out"
        : "Connection cancelled";
    quicClient->close(
        quic::QuicError(quic::QuicErrorCode(err), std::move(errString)));
    co_yield folly::coro::co_error(quic::QuicInternalException(
        errString, quic::LocalErrorCode::CONNECT_FAILED));
  }
  if (cb.quicException) {
    co_yield folly::coro::co_error(std::move(cb.quicException));
  }
  co_return quicClient;
}
} // namespace

namespace moxygen {
folly::coro::Task<void> MoQClient::setupMoQSession(
    std::chrono::milliseconds connect_timeout,
    std::chrono::milliseconds transaction_timeout,
    Role role) noexcept {
  if (transportType_ == TransportType::QUIC) {
    co_await setupMoQQuicSession(connect_timeout, role);
    co_return;
  }
  // Establish an H3 connection
  class ConnectCallback : public proxygen::HQConnector::Callback {
   public:
    ~ConnectCallback() override = default;
    void connectSuccess(proxygen::HQUpstreamSession* session) override {
      XLOG(INFO) << __func__;
      sessionContract.first.setValue(session);
    }
    void connectError(const quic::QuicErrorCode& ex) override {
      XLOG(INFO) << __func__;
      sessionContract.first.setException(
          std::runtime_error(quic::toString(ex)));
    }

    std::pair<
        folly::coro::Promise<proxygen::HQUpstreamSession*>,
        folly::coro::Future<proxygen::HQUpstreamSession*>>
        sessionContract{
            folly::coro::makePromiseContract<proxygen::HQUpstreamSession*>()};
  };
  XLOG(INFO) << __func__;
  auto g =
      folly::makeGuard([func = __func__] { XLOG(INFO) << "exit " << func; });
  ConnectCallback connectCb;
  proxygen::HQConnector hqConnector(&connectCb, transaction_timeout);
  quic::TransportSettings ts;
  ts.datagramConfig.enabled = true;
  // ts.idleTimeout = std::chrono::seconds(10);
  hqConnector.setTransportSettings(ts);
  hqConnector.setSupportedQuicVersions({quic::QuicVersion::QUIC_V1});
  auto fizzContext = std::make_shared<fizz::client::FizzClientContext>();
  fizzContext->setSupportedAlpns({"h3"});
  hqConnector.setH3Settings(
      {{proxygen::SettingsId::ENABLE_CONNECT_PROTOCOL, 1},
       {proxygen::SettingsId::_HQ_DATAGRAM_DRAFT_8, 1},
       {proxygen::SettingsId::_HQ_DATAGRAM, 1},
       {proxygen::SettingsId::_HQ_DATAGRAM_RFC, 1},
       {proxygen::SettingsId::ENABLE_WEBTRANSPORT, 1}});
  hqConnector.connect(
      evb_,
      folly::none,
      folly::SocketAddress(
          url_.getHost(), url_.getPort(), true), // blocking DNS,
      std::move(fizzContext),
      std::make_shared<
          proxygen::InsecureVerifierDangerousDoNotUseInProduction>(),
      connect_timeout,
      folly::emptySocketOptionMap,
      url_.getHost());
  auto session =
      co_await co_awaitTry(std::move(connectCb.sessionContract.second));
  if (session.hasException()) {
    XLOG(ERR) << session.exception().what();
    co_yield folly::coro::co_error(session.exception());
  }

  // Establish WebTransport session and create MoQSession
  auto txn = session.value()->newTransaction(&httpHandler_);
  proxygen::HTTPMessage req;
  req.setHTTPVersion(1, 1);
  req.setSecure(true);
  req.getHeaders().set(proxygen::HTTP_HEADER_HOST, url_.getHost());
  req.getHeaders().add("Sec-Webtransport-Http3-Draft02", "1");
  req.setURL(url_.makeRelativeURL());
  req.setMethod(proxygen::HTTPMethod::CONNECT);
  req.setUpgradeProtocol("webtransport");
  txn->sendHeaders(req);
  auto moqSession =
      co_await co_awaitTry(std::move(httpHandler_.sessionContract.second));
  if (moqSession.hasException()) {
    XLOG(ERR) << moqSession.exception().what();
    co_yield folly::coro::co_error(moqSession.exception());
  }
  session.value()->drain();

  // Setup MoQSession parameters
  moqSession_ = std::move(moqSession.value());
  moqSession_->start();
  moqSession_->setup(ClientSetup(
      {{kVersionDraftCurrent},
       {{folly::to_underlying(SetupKey::ROLE),
         "",
         folly::to_underlying(role)}}}));
  co_await moqSession_->setupComplete();
}

folly::coro::Task<void> MoQClient::setupMoQQuicSession(
    std::chrono::milliseconds connect_timeout,
    Role role) noexcept {
  auto quicClient = co_await connectQuic(
      evb_,
      folly::SocketAddress(
          url_.getHost(), url_.getPort(), true), // blocking DNS,
      connect_timeout);
  quicWebTransport_ =
      std::make_shared<proxygen::QuicWebTransport>(std::move(quicClient));
  quicWebTransport_->setHandler(this);
  moqSession_ = std::make_shared<MoQSession>(
      MoQCodec::Direction::CLIENT, quicWebTransport_.get(), evb_);

  // Setup MoQSession parameters
  moqSession_->start();
  moqSession_->setup(ClientSetup(
      {{kVersionDraftCurrent},
       {{folly::to_underlying(SetupKey::ROLE), "", folly::to_underlying(role)}
        /*,
          {folly::to_underlying(SetupKey::PATH), url_.getPath(), 0}*/}}));
  co_await moqSession_->setupComplete();
}

void MoQClient::HTTPHandler::onHeadersComplete(
    std::unique_ptr<proxygen::HTTPMessage> resp) noexcept {
  if (resp->getStatusCode() != 200) {
    txn_->sendAbort();
    sessionContract.first.setException(std::runtime_error(
        fmt::format("Non-200 response: {0}", resp->getStatusCode())));
    return;
  }
  auto wt = txn_->getWebTransport();
  if (!wt) {
    XLOG(ERR) << "Failed to get web transport, exiting";
    txn_->sendAbort();
    return;
  }
  sessionContract.first.setValue(std::make_shared<MoQSession>(
      MoQCodec::Direction::CLIENT, wt, client_.evb_));
}

void MoQClient::HTTPHandler::onError(
    const proxygen::HTTPException& ex) noexcept {
  XLOG(INFO) << __func__;
  if (!sessionContract.first.isFulfilled()) {
    sessionContract.first.setException(std::runtime_error(
        fmt::format("Error setting up WebTransport: {0}", ex.what())));
    return;
  }
  // the moq session has been torn down...
  XLOG(ERR) << ex.what();
  client_.onSessionEnd(ex);
}

void MoQClient::onSessionEnd(folly::Optional<proxygen::HTTPException>) {
  // TODO: cleanup?
  XLOG(INFO) << "resetting moqSession_";
  moqSession_.reset();
  CHECK(!moqSession_);
}

void MoQClient::onWebTransportBidiStream(
    proxygen::WebTransport::BidiStreamHandle bidi) {
  XLOG(INFO) << __func__;
  moqSession_->onNewBidiStream(std::move(bidi));
}

void MoQClient::onWebTransportUniStream(
    proxygen::WebTransport::StreamReadHandle* stream) {
  XLOG(INFO) << __func__;
  moqSession_->onNewUniStream(stream);
}

void MoQClient::onDatagram(std::unique_ptr<folly::IOBuf> datagram) noexcept {
  moqSession_->onDatagram(std::move(datagram));
}

} // namespace moxygen
