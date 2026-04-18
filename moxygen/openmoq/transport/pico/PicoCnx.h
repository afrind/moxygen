/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>

namespace moxygen {

class PicoCnx;

/**
 * RAII guard: captures picoquic's next wake time on construction and fires
 * a callback on destruction if the wake time decreased (e.g. after
 * mark_active_stream / mark_datagram_ready).
 *
 * Destructor defined in PicoCnxImpl.cpp; no picoquic.h needed here.
 * quic_ == nullptr means no-op destruction (used by MockPicoCnx).
 */
struct WakeTimeGuard {
  WakeTimeGuard() = default;
  WakeTimeGuard(void* quic, const std::function<void()>* cb, uint64_t before);
  ~WakeTimeGuard();
  WakeTimeGuard(WakeTimeGuard&&) noexcept;
  WakeTimeGuard& operator=(WakeTimeGuard&&) noexcept;
  WakeTimeGuard(const WakeTimeGuard&) = delete;
  WakeTimeGuard& operator=(const WakeTimeGuard&) = delete;

 private:
  void* quic_{nullptr}; // picoquic_quic_t*; null → no-op dtor
  const std::function<void()>* cb_{nullptr};
  uint64_t before_{std::numeric_limits<uint64_t>::max()};
};

/**
 * Abstract interface over the picoquic connection APIs used by
 * PicoWebTransportBase. Allows the base class to be unit-tested without a
 * live picoquic connection.
 *
 * PicoCnxImpl wraps a real picoquic_cnx_t*. Tests inject a MockPicoCnx.
 */
class PicoCnx {
 public:
  virtual ~PicoCnx() = default;

  /**
   * Returns a guard capturing picoquic's current wake time. On destruction
   * the guard fires cb if the wake time decreased. Pass an empty cb to get
   * a no-op guard with no overhead.
   */
  virtual WakeTimeGuard getWakeTimeGuard(const std::function<void()>& cb) = 0;

  virtual uint64_t getRtt() const = 0;
  virtual uint64_t getDataSent() const = 0;
  virtual uint64_t getDataReceived() const = 0;

  /** Max datagram payload size from peer's transport parameters. */
  virtual size_t getMaxDatagramPayload() const = 0;

  /** Remote flow-control limits from peer's transport parameters.
   *  Valid after the QUIC handshake completes (picoquic_callback_ready).
   *  Default implementations return max() for backward compatibility with
   *  mocks that don't override them. */
  virtual uint64_t getRemoteMaxStreamDataUni() const {
    return std::numeric_limits<uint64_t>::max();
  }
  virtual uint64_t getRemoteMaxStreamDataBidi() const {
    return std::numeric_limits<uint64_t>::max();
  }

  /**
   * JIT stream buffer provision. Wraps picoquic_provide_stream_data_buffer.
   * Returns pointer to write buffer on success, nullptr if picoquic rejected.
   */
  virtual uint8_t* provideStreamDataBuffer(
      uint8_t* picoContext,
      size_t dataLen,
      bool fin,
      bool isActive) = 0;
};

} // namespace moxygen
