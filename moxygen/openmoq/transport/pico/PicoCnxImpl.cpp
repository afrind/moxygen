/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "moxygen/openmoq/transport/pico/PicoCnxImpl.h"
#include <picoquic.h>

namespace moxygen {

// WakeTimeGuard — defined here so only this TU includes picoquic.h.

WakeTimeGuard::WakeTimeGuard(
    void* quic,
    const std::function<void()>* cb,
    uint64_t before)
    : quic_(quic), cb_(cb), before_(before) {}

WakeTimeGuard::~WakeTimeGuard() {
  if (quic_ && cb_ && *cb_) {
    auto* quic = static_cast<picoquic_quic_t*>(quic_);
    if (picoquic_get_next_wake_time(quic, picoquic_current_time()) < before_) {
      (*cb_)();
    }
  }
}

WakeTimeGuard::WakeTimeGuard(WakeTimeGuard&& other) noexcept
    : quic_(other.quic_), cb_(other.cb_), before_(other.before_) {
  other.quic_ = nullptr;
}

WakeTimeGuard& WakeTimeGuard::operator=(WakeTimeGuard&& other) noexcept {
  quic_ = other.quic_;
  cb_ = other.cb_;
  before_ = other.before_;
  other.quic_ = nullptr;
  return *this;
}

// PicoCnxImpl

PicoCnxImpl::PicoCnxImpl(picoquic_cnx_t* cnx)
    : cnx_(cnx), quic_(picoquic_get_quic_ctx(cnx)) {}

WakeTimeGuard PicoCnxImpl::getWakeTimeGuard(const std::function<void()>& cb) {
  if (!cb) {
    return {};
  }
  auto* quic = static_cast<picoquic_quic_t*>(quic_);
  uint64_t before = picoquic_get_next_wake_time(quic, picoquic_current_time());
  return WakeTimeGuard{quic_, &cb, before};
}

uint64_t PicoCnxImpl::getRtt() const {
  return picoquic_get_rtt(cnx_);
}

uint64_t PicoCnxImpl::getDataSent() const {
  return picoquic_get_data_sent(cnx_);
}

uint64_t PicoCnxImpl::getDataReceived() const {
  return picoquic_get_data_received(cnx_);
}

size_t PicoCnxImpl::getMaxDatagramPayload() const {
  auto* tp = picoquic_get_transport_parameters(cnx_, 0 /* peer */);
  return tp ? static_cast<size_t>(tp->max_datagram_frame_size) : 0;
}

uint8_t* PicoCnxImpl::provideStreamDataBuffer(
    uint8_t* picoContext,
    size_t dataLen,
    bool fin,
    bool isActive) {
  return picoquic_provide_stream_data_buffer(
      picoContext, dataLen, fin ? 1 : 0, isActive ? 1 : 0);
}

} // namespace moxygen
