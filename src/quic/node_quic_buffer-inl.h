#ifndef SRC_NODE_QUIC_BUFFER_INL_H_
#define SRC_NODE_QUIC_BUFFER_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_quic_buffer.h"
#include "util.h"
#include "uv.h"

namespace node {

namespace quic {

quic_buffer_chunk::quic_buffer_chunk(
    MallocedBuffer<uint8_t>&& buf_,
    done_cb done_)
  : quic_buffer_chunk(uv_buf_init(reinterpret_cast<char*>(buf_.data),
                                  buf_.size),
                      done_) {
  data_buf = std::move(buf_);
}

quic_buffer_chunk::quic_buffer_chunk(uv_buf_t buf_) : buf(buf_) {}

quic_buffer_chunk::quic_buffer_chunk(
    uv_buf_t buf_,
    done_cb done_)
  : quic_buffer_chunk(buf_) {
  done = std::move(done_);
}

quic_buffer_chunk::~quic_buffer_chunk() {
  CHECK(done_called);
}

void quic_buffer_chunk::Done(int status) {
  done_called = true;
  std::move(done)(status);
}

void quic_buffer_chunk::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("buf", buf.len);
}


QuicBuffer& QuicBuffer::operator=(QuicBuffer&& src) noexcept {
  if (this == &src) return *this;
  this->~QuicBuffer();
  return *new(this) QuicBuffer(std::move(src));
}

void QuicBuffer::Consume(ssize_t amount) { Consume(0, amount); }

size_t QuicBuffer::Cancel(int status) {
  size_t remaining = Length();
  Consume(status, -1);
  return remaining;
}

size_t QuicBuffer::DrainInto(
    std::vector<uv_buf_t>* list,
    size_t* length,
    size_t max_count) {
  return DrainInto(
      [&](uv_buf_t buf) { list->push_back(buf); },
      length,
      max_count);
}

uv_buf_t QuicBuffer::Head() {
  if (head_ == nullptr)
    return uv_buf_init(nullptr, 0);
  return uv_buf_init(
      head_->buf.base + head_->roffset,
      head_->buf.len - head_->roffset);
}

void QuicBuffer::Push(uv_buf_t buf) {
  Push(new quic_buffer_chunk(buf));
}

void QuicBuffer::Push(uv_buf_t buf, done_cb done) {
  Push(new quic_buffer_chunk(buf, done));
}

void QuicBuffer::reset(QuicBuffer* buffer) {
  buffer->head_ = nullptr;
  buffer->tail_ = nullptr;
  buffer->size_ = 0;
  buffer->length_ = 0;
  buffer->rlength_ = 0;
  buffer->count_ = 0;
}

template <typename T>
size_t QuicBuffer::DrainInto(
    std::vector<T>* list,
    size_t* length,
    size_t max_count) {
  return DrainInto([&](uv_buf_t buf) {
    list->push_back(T {
      reinterpret_cast<uint8_t*>(buf.base), buf.len });
  }, length, max_count);
}

template <typename T>
size_t QuicBuffer::DrainInto(
    T* list,
    size_t* count,
    size_t* length,
    size_t max_count) {
  *count = 0;
  return DrainInto([&](uv_buf_t buf) {
    list[*count]->base = reinterpret_cast<uint8_t*>(buf.base);
    list[*count]->len = buf.len;
    *count += 1;
  }, length, max_count);
  CHECK_LE(*count, max_count);
}

void default_quic_buffer_chunk_done(int status) {}

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_BUFFER_INL_H_
