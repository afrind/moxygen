/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/openmoq/transport/pico/PicoWebTransportBase.h"
#include <folly/io/IOBuf.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <proxygen/lib/http/webtransport/test/Mocks.h>
#include "moxygen/openmoq/transport/pico/PicoCnx.h"

using namespace moxygen;
using namespace testing;

// ---------------------------------------------------------------------------
// MockPicoCnx
// ---------------------------------------------------------------------------

class MockPicoCnx : public PicoCnx {
 public:
  MOCK_METHOD(WakeTimeGuard, getWakeTimeGuard, (const std::function<void()>&));
  MOCK_METHOD(uint64_t, getRtt, (), (const));
  MOCK_METHOD(uint64_t, getDataSent, (), (const));
  MOCK_METHOD(uint64_t, getDataReceived, (), (const));
  MOCK_METHOD(size_t, getMaxDatagramPayload, (), (const));
  MOCK_METHOD(
      uint8_t*,
      provideStreamDataBuffer,
      (uint8_t*, size_t, bool, bool));
};

// ---------------------------------------------------------------------------
// TestPicoWebTransport
// ---------------------------------------------------------------------------

class TestPicoWebTransport : public PicoWebTransportBase {
 public:
  explicit TestPicoWebTransport(
      std::unique_ptr<PicoCnx> cnx,
      bool isClient = false)
      : PicoWebTransportBase(
            isClient,
            folly::SocketAddress(),
            folly::SocketAddress(),
            std::move(cnx)) {}

  struct Call {
    std::string op;
    uint64_t arg0{0};
    uint64_t arg1{0};
  };
  std::vector<Call> calls;

  // Pure virtual implementations — record calls, provide minimal behaviour.
  folly::Expected<uint64_t, ErrorCode> createStreamImpl(bool bidi) override {
    calls.push_back({"createStream", bidi ? 1u : 0u, nextStreamId_});
    return nextStreamId_++;
  }

  void markStreamActiveImpl(uint64_t id) override {
    calls.push_back({"markActive", id, 0});
  }

  void markDatagramActiveImpl() override {
    calls.push_back({"markDatagram", 0, 0});
  }

  void resetStreamImpl(uint64_t id, uint32_t err) override {
    calls.push_back({"reset", id, err});
  }

  void stopSendingImpl(uint64_t id, uint32_t err) override {
    calls.push_back({"stopSending", id, err});
  }

  void sendCloseImpl(uint32_t err) override {
    calls.push_back({"sendClose", err, 0});
  }

  uint8_t* getDatagramBuffer(uint8_t* /*ctx*/, size_t length, bool keepPolling)
      override {
    calls.push_back(
        {"getDatagramBuffer", length, static_cast<uint64_t>(keepPolling)});
    if (length == 0) {
      return nullptr;
    }
    datagramBuf_.resize(length);
    return datagramBuf_.data();
  }

  // Expose protected entry points for tests.
  using PicoWebTransportBase::onJitProvideData;
  using PicoWebTransportBase::onJitProvideDatagram;
  using PicoWebTransportBase::onReceiveDatagramCommon;
  using PicoWebTransportBase::onSessionCloseCommon;
  using PicoWebTransportBase::onStopSendingCommon;
  using PicoWebTransportBase::onStreamDataCommon;
  using PicoWebTransportBase::onStreamResetCommon;
  using PicoWebTransportBase::processEgressEvents;

  std::vector<uint8_t> datagramBuf_;

 private:
  uint64_t nextStreamId_{0};
};

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class PicoWebTransportBaseTest : public Test {
 protected:
  void SetUp() override {
    auto mock = std::make_unique<NiceMock<MockPicoCnx>>();
    mock_ = mock.get();

    ON_CALL(*mock_, getWakeTimeGuard(_))
        .WillByDefault(
            [](const std::function<void()>&) { return WakeTimeGuard{}; });
    ON_CALL(*mock_, getMaxDatagramPayload()).WillByDefault(Return(1200));
    ON_CALL(*mock_, provideStreamDataBuffer(_, _, _, _))
        .WillByDefault(Invoke([this](uint8_t*, size_t len, bool, bool) {
          sendBuf_.resize(len);
          return sendBuf_.data();
        }));
    ON_CALL(*mock_, getRtt()).WillByDefault(Return(10000));
    ON_CALL(*mock_, getDataSent()).WillByDefault(Return(1000));
    ON_CALL(*mock_, getDataReceived()).WillByDefault(Return(2000));

    transport_ = std::make_unique<TestPicoWebTransport>(
        std::move(mock), /*isClient=*/
        false);
    transport_->setHandler(&handler_);
  }

  NiceMock<MockPicoCnx>* mock_{nullptr};
  NiceMock<proxygen::test::MockWebTransportHandler> handler_;
  std::unique_ptr<TestPicoWebTransport> transport_;
  std::vector<uint8_t> sendBuf_;
};
