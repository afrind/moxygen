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

  // Returns pointer to first call with the given op, or nullptr.
  const Call* findCall(const std::string& op) const {
    auto it = std::find_if(calls.begin(), calls.end(), [&op](const Call& c) {
      return c.op == op;
    });
    return it != calls.end() ? &*it : nullptr;
  }

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
  bool callbackFired_{false};
};

// ---------------------------------------------------------------------------
// Stream creation
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, CreateUniStream) {
  auto result = transport_->createUniStream();
  ASSERT_TRUE(result.hasValue());
  EXPECT_NE(result.value(), nullptr);
  ASSERT_EQ(transport_->calls.size(), 1u);
  EXPECT_EQ(transport_->calls[0].op, "createStream");
  EXPECT_EQ(transport_->calls[0].arg0, 0u); // bidi=false
}

TEST_F(PicoWebTransportBaseTest, CreateBidiStream) {
  auto result = transport_->createBidiStream();
  ASSERT_TRUE(result.hasValue());
  EXPECT_NE(result.value().readHandle, nullptr);
  EXPECT_NE(result.value().writeHandle, nullptr);
  ASSERT_EQ(transport_->calls.size(), 1u);
  EXPECT_EQ(transport_->calls[0].op, "createStream");
  EXPECT_EQ(transport_->calls[0].arg0, 1u); // bidi=true
}

TEST_F(PicoWebTransportBaseTest, CreateStreamAfterSessionClosed) {
  transport_->closeSession();
  EXPECT_FALSE(transport_->createUniStream().hasValue());
  EXPECT_FALSE(transport_->createBidiStream().hasValue());
}

// ---------------------------------------------------------------------------
// Egress stream write + JIT provide
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, WriteStreamDataAndJitProvide) {
  auto writeHandle = transport_->createUniStream();
  ASSERT_TRUE(writeHandle.hasValue());
  transport_->calls.clear();

  auto data = folly::IOBuf::copyBuffer("hello");
  transport_->writeStreamData(
      0, std::move(data), /*fin=*/false, /*deliveryCallback=*/nullptr);

  // markStreamActiveImpl should have been called
  ASSERT_GE(transport_->calls.size(), 1u);
  EXPECT_EQ(transport_->calls[0].op, "markActive");
  EXPECT_EQ(transport_->calls[0].arg0, 0u);

  // Simulate JIT callback: picoquic ready to send
  transport_->calls.clear();
  EXPECT_CALL(*mock_, provideStreamDataBuffer(_, 5, false, _))
      .WillOnce(Invoke([this](uint8_t*, size_t len, bool, bool) {
        sendBuf_.resize(len);
        return sendBuf_.data();
      }));
  transport_->onJitProvideData(0, nullptr, 1024);
  EXPECT_EQ(
      std::string(sendBuf_.begin(), sendBuf_.end()), std::string("hello"));
}

TEST_F(PicoWebTransportBaseTest, WriteStreamDataWithFin) {
  auto writeHandle = transport_->createUniStream();
  ASSERT_TRUE(writeHandle.hasValue());
  transport_->calls.clear();

  auto data = folly::IOBuf::copyBuffer("bye");
  transport_->writeStreamData(
      0, std::move(data), /*fin=*/true, /*deliveryCallback=*/nullptr);

  EXPECT_CALL(*mock_, provideStreamDataBuffer(_, 3, true, _))
      .WillOnce(Invoke([this](uint8_t*, size_t len, bool, bool) {
        sendBuf_.resize(len);
        return sendBuf_.data();
      }));
  bool finSent = transport_->onJitProvideData(0, nullptr, 1024);
  EXPECT_TRUE(finSent);
  EXPECT_EQ(std::string(sendBuf_.begin(), sendBuf_.end()), std::string("bye"));
}

TEST_F(PicoWebTransportBaseTest, WriteMultipleChunksDeliveredInOrder) {
  transport_->createUniStream();
  transport_->calls.clear();

  transport_->writeStreamData(
      0, folly::IOBuf::copyBuffer("first"), false, nullptr);
  transport_->writeStreamData(
      0, folly::IOBuf::copyBuffer("second"), false, nullptr);

  // First JIT call with maxLength=5 delivers only "first"
  EXPECT_CALL(*mock_, provideStreamDataBuffer(_, 5, false, _))
      .WillOnce(Invoke([this](uint8_t*, size_t len, bool, bool) {
        sendBuf_.resize(len);
        return sendBuf_.data();
      }));
  transport_->onJitProvideData(0, nullptr, 5);
  EXPECT_EQ(
      std::string(sendBuf_.begin(), sendBuf_.end()), std::string("first"));

  // Second JIT call delivers "second"
  EXPECT_CALL(*mock_, provideStreamDataBuffer(_, 6, false, _))
      .WillOnce(Invoke([this](uint8_t*, size_t len, bool, bool) {
        sendBuf_.resize(len);
        return sendBuf_.data();
      }));
  transport_->onJitProvideData(0, nullptr, 1024);
  EXPECT_EQ(
      std::string(sendBuf_.begin(), sendBuf_.end()), std::string("second"));
}

// ---------------------------------------------------------------------------
// Egress datagram + JIT provide
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, SendDatagramAndJitProvide) {
  auto dg = folly::IOBuf::copyBuffer("dgram");
  transport_->sendDatagram(std::move(dg));

  EXPECT_NE(transport_->findCall("markDatagram"), nullptr);
  transport_->calls.clear();

  // JIT callback: getDatagramBuffer called with dgram length
  transport_->onJitProvideDatagram(nullptr, 1200);
  ASSERT_GE(transport_->calls.size(), 1u);
  auto& dgCall = transport_->calls[0];
  EXPECT_EQ(dgCall.op, "getDatagramBuffer");
  EXPECT_EQ(dgCall.arg0, 5u); // "dgram" = 5 bytes
  EXPECT_EQ(
      std::string(
          transport_->datagramBuf_.begin(), transport_->datagramBuf_.end()),
      std::string("dgram"));
}

TEST_F(PicoWebTransportBaseTest, DatagramDeferredWhenNoSpace) {
  transport_->sendDatagram(folly::IOBuf::copyBuffer("toolarge"));
  transport_->calls.clear();

  // maxLength smaller than datagram — must defer
  transport_->onJitProvideDatagram(nullptr, 3);
  ASSERT_GE(transport_->calls.size(), 1u);
  EXPECT_EQ(transport_->calls[0].op, "getDatagramBuffer");
  EXPECT_EQ(transport_->calls[0].arg0, 0u); // length == 0
  EXPECT_EQ(transport_->calls[0].arg1, 1u); // keepPolling == true
}

TEST_F(PicoWebTransportBaseTest, DatagramQueueDrainedStopsPolling) {
  // JIT fires on empty queue — should signal stop
  transport_->onJitProvideDatagram(nullptr, 1200);
  // findCall only matches op; scan manually for keepPolling==false.
  const auto* c = transport_->findCall("getDatagramBuffer");
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(c->arg1, 0u); // keepPolling == false
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, IngressNewPeerUniStream) {
  // Client-initiated uni stream: bit0=0 (client), bit1=1 (uni) → ID 2.
  // The transport is server-side, so the peer (client) owns bit0=0.
  constexpr uint64_t kPeerUniId = 2;
  proxygen::WebTransport::StreamReadHandle* capturedHandle{nullptr};
  EXPECT_CALL(handler_, onNewUniStream(_))
      .WillOnce(SaveArg<0>(&capturedHandle));

  uint8_t payload[] = {1, 2, 3};
  transport_->onStreamDataCommon(kPeerUniId, payload, sizeof(payload), false);
  EXPECT_NE(capturedHandle, nullptr);
}

TEST_F(PicoWebTransportBaseTest, IngressNewPeerBidiStream) {
  // Client-initiated bidi stream: bit0=0 (client), bit1=0 (bidi) → ID 0.
  // The transport is server-side, so the peer (client) owns bit0=0.
  constexpr uint64_t kPeerBidiId = 0;
  EXPECT_CALL(handler_, onNewBidiStream(_));

  uint8_t payload[] = {9};
  transport_->onStreamDataCommon(kPeerBidiId, payload, sizeof(payload), false);
}

TEST_F(PicoWebTransportBaseTest, IngressStreamDataReadable) {
  // Client-initiated uni stream (ID 2) from server's perspective.
  constexpr uint64_t kStreamId = 2;
  uint8_t payload[] = {'h', 'i'};
  transport_->onStreamDataCommon(kStreamId, payload, sizeof(payload), false);

  // Data should be readable via readStreamData
  auto readResult = transport_->readStreamData(kStreamId);
  ASSERT_TRUE(readResult.hasValue());
  auto streamData = std::move(readResult.value()).get();
  ASSERT_NE(streamData.data, nullptr);
  EXPECT_EQ(streamData.data->computeChainDataLength(), 2u);
}

TEST_F(PicoWebTransportBaseTest, IngressStreamFinDelivered) {
  // Client-initiated uni stream (ID 2) from server's perspective.
  constexpr uint64_t kStreamId = 2;
  uint8_t payload[] = {'x'};
  transport_->onStreamDataCommon(kStreamId, payload, 1, true /* fin */);

  auto readResult = transport_->readStreamData(kStreamId);
  ASSERT_TRUE(readResult.hasValue());
  auto streamData = std::move(readResult.value()).get();
  EXPECT_TRUE(streamData.fin);
}

TEST_F(PicoWebTransportBaseTest, IngressDatagram) {
  std::unique_ptr<folly::IOBuf> received;
  EXPECT_CALL(handler_, onDatagram(_))
      .WillOnce(Invoke([&received](std::unique_ptr<folly::IOBuf> buf) mutable {
        received = std::move(buf);
      }));

  uint8_t payload[] = {0xDE, 0xAD};
  transport_->onReceiveDatagramCommon(payload, sizeof(payload));

  ASSERT_NE(received, nullptr);
  EXPECT_EQ(received->computeChainDataLength(), 2u);
  EXPECT_EQ(received->data()[0], 0xDE);
}

TEST_F(PicoWebTransportBaseTest, IngressSessionClose) {
  EXPECT_CALL(handler_, onSessionEnd(_));
  transport_->onSessionCloseCommon(42);
  // Second call is idempotent (sessionClosed_ guard)
  transport_->onSessionCloseCommon(0);
}

// ---------------------------------------------------------------------------
// Egress control frames via WtStreamManager → processEgressEvents
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, EgressResetStream) {
  transport_->createUniStream(); // stream ID 0
  transport_->calls.clear();

  transport_->resetStream(0, 99);
  transport_->processEgressEvents();

  const auto* c = transport_->findCall("reset");
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(c->arg0, 0u);
  EXPECT_EQ(c->arg1, 99u);
}

TEST_F(PicoWebTransportBaseTest, EgressStopSending) {
  // Client-initiated uni stream (ID 2) from server's perspective.
  uint8_t dummy[] = {0};
  transport_->onStreamDataCommon(2, dummy, 1, false);
  transport_->calls.clear();

  transport_->stopSending(2, 7);
  transport_->processEgressEvents();

  const auto* c = transport_->findCall("stopSending");
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(c->arg0, 2u);
  EXPECT_EQ(c->arg1, 7u);
}

TEST_F(PicoWebTransportBaseTest, CloseSession) {
  EXPECT_CALL(handler_, onSessionEnd(_));
  transport_->closeSession(folly::Optional<uint32_t>(5));

  const auto* c = transport_->findCall("sendClose");
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(c->arg0, 5u);
}

// ---------------------------------------------------------------------------
// Transport info
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, GetTransportInfo) {
  auto info = transport_->getTransportInfo();
  EXPECT_EQ(info.srtt, std::chrono::microseconds(10000));
  EXPECT_EQ(info.bytesSent, 1000u);
  EXPECT_EQ(info.bytesRecvd, 2000u);
}

// ---------------------------------------------------------------------------
// WakeTimeGuard fires callback
// ---------------------------------------------------------------------------

TEST_F(PicoWebTransportBaseTest, WakeTimeGuardFiresCallback) {
  // Use fixture-level bool so the lambda stays valid through transport_
  // teardown.
  transport_->setUpdateWakeTimeoutCallback([this]() { callbackFired_ = true; });

  // Configure mock to fire the callback via the guard
  ON_CALL(*mock_, getWakeTimeGuard(_))
      .WillByDefault([](const std::function<void()>& cb) {
        if (cb) {
          cb();
        }
        return WakeTimeGuard{};
      });

  transport_->createUniStream();
  auto data = folly::IOBuf::copyBuffer("x");
  transport_->writeStreamData(0, std::move(data), false, nullptr);

  EXPECT_TRUE(callbackFired_);
}
