/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/MoQRelaySession.h"
#include "moxygen/MoQServer.h"
#include "moxygen/MoQServerBase.h"
#include "moxygen/relay/MoQRelay.h"
#include "moxygen/transports/MoQPicoQuicServer.h"
#include "moxygen/util/SignalHandler.h"

#include <folly/init/Init.h>

using namespace proxygen;

DEFINE_string(cert, "", "Cert path");
DEFINE_string(key, "", "Key path");
DEFINE_string(endpoint, "/moq-relay", "End point");
DEFINE_int32(port, 9668, "Relay Server Port");
DEFINE_bool(enable_cache, false, "Enable relay cache");
DEFINE_bool(insecure, false,
            "Use insecure verifier (skip certificate validation)");
DEFINE_bool(use_legacy_setup, false,
            "If true, use only moq-00 ALPN (legacy). If false, use latest "
            "draft ALPN with fallback to legacy");
DEFINE_string(
    server_type, "proxygen",
    "Server type: 'proxygen' for MoQServer, 'pico' for MoQPicoQuicServer");

namespace {
using namespace moxygen;

// Proxygen-based relay server
class ProxygenMoQRelayServer : public MoQServer {
public:
  // Used when the insecure flag is false
  ProxygenMoQRelayServer(const std::string &cert, const std::string &key,
                         std::shared_ptr<MoQRelay> relay)
      : MoQServer(cert, key, FLAGS_endpoint), relay_(std::move(relay)) {}

  // Used when the insecure flag is true
  ProxygenMoQRelayServer(std::shared_ptr<MoQRelay> relay)
      : MoQServer(quic::samples::createFizzServerContextWithInsecureDefault(
                      []() {
                        std::vector<std::string> alpns = {"h3"};
                        auto moqt =
                            getDefaultMoqtProtocols(!FLAGS_use_legacy_setup);
                        alpns.insert(alpns.end(), moqt.begin(), moqt.end());
                        return alpns;
                      }(),
                      fizz::server::ClientAuthMode::None, "" /* cert */,
                      "" /* key */),
                  FLAGS_endpoint),
        relay_(std::move(relay)) {}

  void onNewSession(std::shared_ptr<MoQSession> clientSession) override {
    clientSession->setPublishHandler(relay_);
    clientSession->setSubscribeHandler(relay_);
  }

protected:
  std::shared_ptr<MoQSession>
  createSession(folly::MaybeManagedPtr<proxygen::WebTransport> wt,
                std::shared_ptr<MoQExecutor> executor) override {
    return std::make_shared<MoQRelaySession>(
        folly::MaybeManagedPtr<proxygen::WebTransport>(std::move(wt)), *this,
        std::move(executor));
  }

private:
  std::shared_ptr<MoQRelay> relay_;
};

// PicoQuic-based relay server
class PicoQuicMoQRelayServer : public MoQPicoQuicServer {
public:
  PicoQuicMoQRelayServer(std::string cert, std::string key,
                         std::string endpoint, std::shared_ptr<MoQRelay> relay)
      : MoQPicoQuicServer(std::move(cert), std::move(key), std::move(endpoint)),
        relay_(std::move(relay)) {}

  void onNewSession(std::shared_ptr<MoQSession> clientSession) override {
    clientSession->setPublishHandler(relay_);
    clientSession->setSubscribeHandler(relay_);
  }

protected:
  std::shared_ptr<MoQSession>
  createSession(folly::MaybeManagedPtr<proxygen::WebTransport> wt,
                std::shared_ptr<MoQExecutor> executor) override {
    return std::make_shared<MoQRelaySession>(std::move(wt), *this,
                                             std::move(executor));
  }

private:
  std::shared_ptr<MoQRelay> relay_;
};

} // namespace

int main(int argc, char *argv[]) {
  folly::Init init(&argc, &argv, true);

  // Create shared relay instance
  auto relay = std::make_shared<MoQRelay>(FLAGS_enable_cache);

  // Create event base and address for both server types
  folly::EventBase evb;
  folly::SocketAddress addr("::", FLAGS_port);

  // Server pointer to hold either server type
  std::shared_ptr<MoQServerBase> server;

  if (FLAGS_server_type == "pico") {
    // PicoQuic server
    if (FLAGS_insecure) {
      XLOG(ERR) << "Insecure mode not supported with PicoQuic server";
      return 1;
    }
    if (FLAGS_cert.empty() || FLAGS_key.empty()) {
      XLOG(ERR) << "PicoQuic server requires --cert and --key";
      return 1;
    }

    server = std::make_shared<PicoQuicMoQRelayServer>(FLAGS_cert, FLAGS_key,
                                                      FLAGS_endpoint, relay);
    server->start(addr);

    XLOG(INFO) << "PicoQuic relay server running on port " << FLAGS_port;

  } else if (FLAGS_server_type == "proxygen") {
    // Proxygen server
    if (FLAGS_insecure) {
      server = std::make_shared<ProxygenMoQRelayServer>(relay);
    } else {
      if (FLAGS_cert.empty() || FLAGS_key.empty()) {
        XLOG(ERR)
            << "Proxygen server requires --cert and --key (or --insecure)";
        return 1;
      }
      server = std::make_shared<ProxygenMoQRelayServer>(FLAGS_cert, FLAGS_key,
                                                        relay);
    }

    server->start(addr);

    XLOG(INFO) << "Proxygen relay server running on port " << FLAGS_port;

  } else {
    XLOG(ERR) << "Invalid server type: " << FLAGS_server_type
              << ". Must be 'proxygen' or 'pico'";
    return 1;
  }

  // Set up signal handler and run event loop (common for both server types)
  SignalHandler sigHandler(&evb, [&server](int) { server->stop(); });
  evb.loopForever();

  return 0;
}
