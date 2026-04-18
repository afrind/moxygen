/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "moxygen/openmoq/transport/pico/PicoCnx.h"

typedef struct st_picoquic_cnx_t picoquic_cnx_t;

namespace moxygen {

/**
 * Production implementation of PicoCnx wrapping a real picoquic_cnx_t*.
 * Also defines WakeTimeGuard's constructor and destructor (which call
 * picoquic APIs and therefore live here to avoid spreading picoquic.h).
 */
class PicoCnxImpl : public PicoCnx {
 public:
  explicit PicoCnxImpl(picoquic_cnx_t* cnx);

  WakeTimeGuard getWakeTimeGuard(const std::function<void()>& cb) override;
  uint64_t getRtt() const override;
  uint64_t getDataSent() const override;
  uint64_t getDataReceived() const override;
  size_t getMaxDatagramPayload() const override;
  uint8_t* provideStreamDataBuffer(
      uint8_t* picoContext,
      size_t dataLen,
      bool fin,
      bool isActive) override;

 private:
  picoquic_cnx_t* cnx_;
  void* quic_; // picoquic_quic_t*, cached from picoquic_get_quic_ctx in ctor
};

} // namespace moxygen
