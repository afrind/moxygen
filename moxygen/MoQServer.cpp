/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/MoQServer.h"

using namespace quic::samples;
using namespace proxygen;

namespace moxygen {

MoQServer::MoQServer(
    uint16_t port,
    std::string cert,
    std::string key,
    std::string endpoint)
    : endpoint_(endpoint) {
  HQServerParams params;
  params.localAddress.emplace();
  params.localAddress->setFromLocalPort(port);
  params.serverThreads = 1;
  params.certificateFilePath = cert;
  params.keyFilePath = key;
  params.txnTimeout = std::chrono::seconds(60);
  hqServer_ = std::make_unique<HQServer>(
      params, [this](HTTPMessage*) { return new Handler(*this); });
  hqServer_->start();
}

void MoQServer::ControlVisitor::operator()(ClientSetup /*setup*/) const {
  XLOG(INFO) << "ClientSetup";
  // TODO: Make the default MAX_SUBSCRIBE_ID configurable and
  // take in the value from ClientSetup
  static constexpr size_t kDefaultMaxSubscribeId = 100;
  clientSession_->setup({
      kVersionDraftCurrent,
      {{folly::to_underlying(SetupKey::ROLE),
        "",
        folly::to_underlying(Role::PUB_AND_SUB)},
       {folly::to_underlying(SetupKey::MAX_SUBSCRIBE_ID),
        "",
        kDefaultMaxSubscribeId}},
  });
}

void MoQServer::ControlVisitor::operator()(ServerSetup) const {
  // error
  XLOG(ERR) << "Server received ServerSetup";
  clientSession_->close();
}

void MoQServer::ControlVisitor::operator()(
    SubscribeRequest subscribeReq) const {
  XLOG(INFO) << "SubscribeRequest track="
             << subscribeReq.fullTrackName.trackNamespace
             << subscribeReq.fullTrackName.trackName
             << " id=" << subscribeReq.subscribeID;
  clientSession_->subscribeError(
      {subscribeReq.subscribeID, 500, "not implemented"});
}

void MoQServer::ControlVisitor::operator()(
    SubscribeUpdate subscribeUpdate) const {
  XLOG(INFO) << "SubscribeRequest id=" << subscribeUpdate.subscribeID;
}

void MoQServer::ControlVisitor::operator()(
    MaxSubscribeId maxSubscribeId) const {
  XLOG(INFO) << fmt::format("maxSubscribeId id={}", maxSubscribeId.subscribeID);
}

void MoQServer::ControlVisitor::operator()(SubscribeDone subscribeDone) const {
  XLOG(INFO) << "SubscribeDone id=" << subscribeDone.subscribeID
             << " code=" << folly::to_underlying(subscribeDone.statusCode)
             << " reason=" << subscribeDone.reasonPhrase;
}

void MoQServer::ControlVisitor::operator()(Unsubscribe unsubscribe) const {
  XLOG(INFO) << "Unsubscribe id=" << unsubscribe.subscribeID;
}

void MoQServer::ControlVisitor::operator()(Announce announce) const {
  XLOG(INFO) << "Announce ns=" << announce.trackNamespace;
  clientSession_->announceError(
      {announce.trackNamespace, 500, "not implemented"});
}

void MoQServer::ControlVisitor::operator()(Unannounce unannounce) const {
  XLOG(INFO) << "Unannounce ns=" << unannounce.trackNamespace;
}

void MoQServer::ControlVisitor::operator()(
    AnnounceCancel announceCancel) const {
  XLOG(INFO) << "AnnounceCancel ns=" << announceCancel.trackNamespace;
}

void MoQServer::ControlVisitor::operator()(
    SubscribeNamespace subscribeNamespace) const {
  XLOG(INFO) << "SubscribeNamespace ns="
             << subscribeNamespace.trackNamespacePrefix;
  clientSession_->subscribeNamespaceError(
      {subscribeNamespace.trackNamespacePrefix, 500, "not implemented"});
}

void MoQServer::ControlVisitor::operator()(
    UnsubscribeNamespace unsubscribeNamespace) const {
  XLOG(INFO) << "UnsubscribeNamespace ns="
             << unsubscribeNamespace.trackNamespacePrefix;
}

void MoQServer::ControlVisitor::operator()(
    TrackStatusRequest trackStatusRequest) const {
  XLOG(INFO) << "TrackStatusRequest track="
             << trackStatusRequest.fullTrackName.trackNamespace
             << trackStatusRequest.fullTrackName.trackName;
}

void MoQServer::ControlVisitor::operator()(TrackStatus trackStatus) const {
  XLOG(INFO) << "TrackStatus track=" << trackStatus.fullTrackName.trackNamespace
             << trackStatus.fullTrackName.trackName;
}

void MoQServer::ControlVisitor::operator()(Goaway goaway) const {
  XLOG(INFO) << "Goaway nsuri=" << goaway.newSessionUri;
}

folly::coro::Task<void> MoQServer::handleClientSession(
    std::shared_ptr<MoQSession> clientSession) {
  clientSession->start();

  auto control = makeControlVisitor(clientSession);
  while (auto msg = co_await clientSession->controlMessages().next()) {
    boost::apply_visitor(*control, msg.value());
  }
}

void MoQServer::Handler::onHeadersComplete(
    std::unique_ptr<HTTPMessage> req) noexcept {
  HTTPMessage resp;
  resp.setHTTPVersion(1, 1);

  if (req->getPathAsStringPiece() != server_.getEndpoint()) {
    XLOG(INFO) << req->getPathAsStringPiece();
    req->dumpMessage(0);
    resp.setStatusCode(404);
    txn_->sendHeadersWithEOM(resp);
    return;
  }
  if (req->getMethod() != HTTPMethod::CONNECT || !req->getUpgradeProtocol() ||
      *req->getUpgradeProtocol() != std::string("webtransport")) {
    resp.setStatusCode(400);
    txn_->sendHeadersWithEOM(resp);
    return;
  }
  resp.setStatusCode(200);
  resp.getHeaders().add("sec-webtransport-http3-draft", "draft02");
  txn_->sendHeaders(resp);
  auto wt = txn_->getWebTransport();
  if (!wt) {
    XLOG(ERR) << "Failed to get WebTransport";
    txn_->sendAbort();
    return;
  }
  auto evb = folly::EventBaseManager::get()->getEventBase();
  clientSession_ =
      std::make_shared<MoQSession>(MoQControlCodec::Direction::SERVER, wt, evb);

  server_.handleClientSession(clientSession_).scheduleOn(evb).start();
}
} // namespace moxygen
