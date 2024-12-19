/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/MoQCodec.h"
#include "moxygen/test/Mocks.h"
#include "moxygen/test/TestUtils.h"

#include <folly/portability/GTest.h>

namespace moxygen::test {
TestControlMessages fromDir(MoQControlCodec::Direction dir) {
  // The control messages to write are the opposite of dir
  return dir == MoQControlCodec::Direction::CLIENT
      ? TestControlMessages::SERVER
      : TestControlMessages::CLIENT;
}

void testAll(MoQControlCodec::Direction dir) {
  auto allMsgs = moxygen::test::writeAllControlMessages(fromDir(dir));
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQControlCodec codec(dir, &callback);

  if (dir == MoQControlCodec::Direction::SERVER) {
    EXPECT_CALL(callback, onClientSetup(testing::_));
  } else {
    EXPECT_CALL(callback, onServerSetup(testing::_));
  }
  EXPECT_CALL(callback, onSubscribe(testing::_));
  EXPECT_CALL(callback, onSubscribeUpdate(testing::_));
  EXPECT_CALL(callback, onSubscribeOk(testing::_));
  EXPECT_CALL(callback, onSubscribeError(testing::_));
  EXPECT_CALL(callback, onUnsubscribe(testing::_));
  EXPECT_CALL(callback, onSubscribeDone(testing::_)).Times(2);
  EXPECT_CALL(callback, onAnnounce(testing::_));
  EXPECT_CALL(callback, onAnnounceOk(testing::_));
  EXPECT_CALL(callback, onAnnounceError(testing::_));
  EXPECT_CALL(callback, onUnannounce(testing::_));
  EXPECT_CALL(callback, onTrackStatusRequest(testing::_));
  EXPECT_CALL(callback, onTrackStatus(testing::_));
  EXPECT_CALL(callback, onGoaway(testing::_));
  EXPECT_CALL(callback, onMaxSubscribeId(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnounces(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnouncesOk(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnouncesError(testing::_));
  EXPECT_CALL(callback, onUnsubscribeAnnounces(testing::_));
  EXPECT_CALL(callback, onFetch(testing::_));
  EXPECT_CALL(callback, onFetchCancel(testing::_));
  EXPECT_CALL(callback, onFetchOk(testing::_));
  EXPECT_CALL(callback, onFetchError(testing::_));
  EXPECT_CALL(callback, onFrame(testing::_)).Times(25);

  codec.onIngress(std::move(allMsgs), true);
}

TEST(MoQCodec, All) {
  testAll(MoQControlCodec::Direction::CLIENT);
  testAll(MoQControlCodec::Direction::SERVER);
}

TEST(MoQCodec, AllObject) {
  auto allMsgs = moxygen::test::writeAllObjectMessages();
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQObjectStreamCodec codec(&callback);

  EXPECT_CALL(callback, onObjectHeader(testing::_)).Times(2);
  EXPECT_CALL(
      callback,
      onObjectPayload(
          testing::_, testing::_, testing::_, testing::_, testing::_))
      .Times(1);
  codec.onIngress(std::move(allMsgs), true);
}

void testUnderflow(MoQControlCodec::Direction dir) {
  auto allMsgs = moxygen::test::writeAllControlMessages(fromDir(dir));
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQControlCodec codec(dir, &callback);

  folly::IOBufQueue readBuf{folly::IOBufQueue::cacheChainLength()};
  readBuf.append(std::move(allMsgs));

  if (dir == MoQControlCodec::Direction::SERVER) {
    EXPECT_CALL(callback, onClientSetup(testing::_));
  } else {
    EXPECT_CALL(callback, onServerSetup(testing::_));
  }
  EXPECT_CALL(callback, onSubscribe(testing::_));
  EXPECT_CALL(callback, onSubscribeUpdate(testing::_));
  EXPECT_CALL(callback, onSubscribeOk(testing::_));
  EXPECT_CALL(callback, onSubscribeError(testing::_));
  EXPECT_CALL(callback, onUnsubscribe(testing::_));
  EXPECT_CALL(callback, onSubscribeDone(testing::_)).Times(2);
  EXPECT_CALL(callback, onAnnounce(testing::_));
  EXPECT_CALL(callback, onAnnounceOk(testing::_));
  EXPECT_CALL(callback, onAnnounceError(testing::_));
  EXPECT_CALL(callback, onUnannounce(testing::_));
  EXPECT_CALL(callback, onTrackStatusRequest(testing::_));
  EXPECT_CALL(callback, onTrackStatus(testing::_));
  EXPECT_CALL(callback, onGoaway(testing::_));
  EXPECT_CALL(callback, onMaxSubscribeId(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnounces(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnouncesOk(testing::_));
  EXPECT_CALL(callback, onSubscribeAnnouncesError(testing::_));
  EXPECT_CALL(callback, onUnsubscribeAnnounces(testing::_));
  EXPECT_CALL(callback, onFetch(testing::_));
  EXPECT_CALL(callback, onFetchCancel(testing::_));
  EXPECT_CALL(callback, onFetchOk(testing::_));
  EXPECT_CALL(callback, onFetchError(testing::_));
  EXPECT_CALL(callback, onFrame(testing::_)).Times(25);
  while (!readBuf.empty()) {
    codec.onIngress(readBuf.split(1), false);
  }
  codec.onIngress(nullptr, true);
}

TEST(MoQCodec, Underflow) {
  testUnderflow(MoQControlCodec::Direction::CLIENT);
  testUnderflow(MoQControlCodec::Direction::SERVER);
}

TEST(MoQCodec, UnderflowObjects) {
  auto allMsgs = moxygen::test::writeAllObjectMessages();
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQObjectStreamCodec codec(&callback);

  folly::IOBufQueue readBuf{folly::IOBufQueue::cacheChainLength()};
  readBuf.append(std::move(allMsgs));

  EXPECT_CALL(callback, onObjectHeader(testing::_)).Times(2);
  EXPECT_CALL(
      callback,
      onObjectPayload(
          testing::_, testing::_, testing::_, testing::_, testing::_))
      .Times(strlen("hello world"));
  while (!readBuf.empty()) {
    codec.onIngress(readBuf.split(1), false);
  }
  codec.onIngress(nullptr, true);
}

TEST(MoQCodec, ObjectStreamPayload) {
  folly::IOBufQueue writeBuf{folly::IOBufQueue::cacheChainLength()};
  writeSingleObjectStream(
      writeBuf,
      {TrackAlias(1),
       2,
       3,
       4,
       5,
       ForwardPreference::Subgroup,
       ObjectStatus::NORMAL,
       11},
      folly::IOBuf::copyBuffer("hello world"));
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQObjectStreamCodec codec(&callback);

  EXPECT_CALL(callback, onObjectHeader(testing::_));
  EXPECT_CALL(
      callback,
      onObjectPayload(
          testing::_, testing::_, testing::_, testing::_, testing::_))
      .Times(1);

  codec.onIngress(writeBuf.move(), false);
  codec.onIngress(std::unique_ptr<folly::IOBuf>(), true);
}

TEST(MoQCodec, EmptyObjectPayload) {
  folly::IOBufQueue writeBuf{folly::IOBufQueue::cacheChainLength()};
  writeSingleObjectStream(
      writeBuf,
      {TrackAlias(1),
       2,
       3,
       4,
       5,
       ForwardPreference::Subgroup,
       ObjectStatus::OBJECT_NOT_EXIST,
       folly::none},
      nullptr);
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQObjectStreamCodec codec(&callback);

  EXPECT_CALL(callback, onObjectHeader(testing::_));

  // extra coverage of underflow in header
  codec.onIngress(writeBuf.split(3), false);
  codec.onIngress(writeBuf.move(), false);
  codec.onIngress(std::unique_ptr<folly::IOBuf>(), true);
}

TEST(MoQCodec, TruncatedObject) {
  folly::IOBufQueue writeBuf{folly::IOBufQueue::cacheChainLength()};
  auto res = writeStreamHeader(
      writeBuf,
      ObjectHeader({
          TrackAlias(1),
          2,
          3,
          4,
          5,
          ForwardPreference::Track,
          ObjectStatus::NORMAL,
          folly::none,
      }));
  res = writeObject(
      writeBuf,
      ObjectHeader(
          {TrackAlias(1),
           2,
           3,
           4,
           5,
           ForwardPreference::Track,
           ObjectStatus::NORMAL,
           11}),
      folly::IOBuf::copyBuffer("hello")); // missing " world"
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQObjectStreamCodec codec(&callback);

  EXPECT_CALL(callback, onObjectHeader(testing::_));

  codec.onIngress(writeBuf.move(), true);
}

TEST(MoQCodec, InvalidFrame) {
  folly::IOBufQueue writeBuf{folly::IOBufQueue::cacheChainLength()};
  writeBuf.append(std::string(" "));
  testing::NiceMock<MockMoQCodecCallback> callback;
  MoQControlCodec codec(MoQControlCodec::Direction::CLIENT, &callback);

  EXPECT_CALL(callback, onConnectionError(testing::_));

  codec.onIngress(writeBuf.move(), false);
}

TEST(MoQCodec, InvalidSetups) {
  testing::NiceMock<MockMoQCodecCallback> callback;
  folly::IOBufQueue writeBuf{folly::IOBufQueue::cacheChainLength()};

  // client gets client setup
  writeClientSetup(
      writeBuf,
      ClientSetup(
          {{1},
           {
               {folly::to_underlying(SetupKey::ROLE),
                "",
                folly::to_underlying(Role::SUBSCRIBER)},
               {folly::to_underlying(SetupKey::PATH), "/foo", 0},
               {folly::to_underlying(SetupKey::MAX_SUBSCRIBE_ID), "", 100},
           }}));
  {
    MoQControlCodec clientCodec(MoQControlCodec::Direction::CLIENT, &callback);
    EXPECT_CALL(callback, onConnectionError(testing::_));
    clientCodec.onIngress(writeBuf.move(), false);
  }

  // codec gets non-setup first
  writeUnsubscribe(
      writeBuf,
      Unsubscribe({
          0,
      }));
  {
    MoQControlCodec clientCodec(MoQControlCodec::Direction::CLIENT, &callback);
    EXPECT_CALL(callback, onConnectionError(testing::_));
    clientCodec.onIngress(writeBuf.move(), false);
  }

  writeServerSetup(
      writeBuf,
      ServerSetup(
          {1,
           {
               {folly::to_underlying(SetupKey::ROLE),
                "",
                folly::to_underlying(Role::SUBSCRIBER)},
               {folly::to_underlying(SetupKey::PATH), "/foo", 0},
           }}));
  auto serverSetup = writeBuf.front()->clone();
  {
    MoQControlCodec clientCodec(MoQControlCodec::Direction::CLIENT, &callback);
    // This is legal, to setup next test
    EXPECT_CALL(callback, onServerSetup(testing::_));
    clientCodec.onIngress(writeBuf.move(), false);
    // Second setup = error
    EXPECT_CALL(callback, onConnectionError(testing::_));
    clientCodec.onIngress(serverSetup->clone(), false);
  }

  {
    // Server gets server setup = error
    MoQControlCodec serverCodec(MoQControlCodec::Direction::SERVER, &callback);
    EXPECT_CALL(callback, onConnectionError(testing::_));
    serverCodec.onIngress(serverSetup->clone(), false);
  }
}
} // namespace moxygen::test
