#include "node_quic_buffer-inl.h"
#include "util.h"
#include "uv.h"

#include <array>
#include <algorithm>
#include <functional>
#include <vector>

namespace node {
namespace quic {

namespace {
inline bool IsEmptyBuffer(const uv_buf_t& buf) {
  return buf.len == 0 || buf.base == nullptr;
}
}  // namespace

QuicBuffer& QuicBuffer::operator+=(QuicBuffer&& src) noexcept {
  if (tail_ == nullptr) {
    // If this thing is empty, just do a move...
    return *this = std::move(src);
  }

  tail_->next = std::move(src.root_);
  // If head_ is null, then it had been read to the
  // end, set the new head_ equal to the appended
  // root.
  if (head_ == nullptr)
    head_ = tail_->next.get();
  tail_ = src.tail_;
  length_ += src.length_;
  rlength_ += src.length_;
  size_ += src.size_;
  count_ += src.size_;
  reset(&src);
  return *this;
}

size_t QuicBuffer::Push(uv_buf_t* bufs, size_t nbufs, done_cb done) {
  size_t len = 0;
  if (nbufs == 0 || bufs == nullptr || IsEmptyBuffer(bufs[0])) {
    done(0);
    return 0;
  }
  size_t n = 0;
  while (nbufs > 1) {
    if (!IsEmptyBuffer(bufs[n])) {
      Push(bufs[n]);
      length_ += bufs[n].len;
      rlength_ += bufs[n].len;
      len += bufs[n].len;
    }
    n++;
    nbufs--;
  }
  length_ += bufs[n].len;
  rlength_ += bufs[n].len;
  len += bufs[n].len;
  Push(bufs[n], done);
  return len;
}

size_t QuicBuffer::Push(MallocedBuffer<uint8_t>&& buffer, done_cb done) {
  if (buffer.size == 0) {
    done(0);
    return 0;
  }
  length_ += buffer.size;
  rlength_ += buffer.size;
  Push(new quic_buffer_chunk(std::move(buffer), done));
  return buffer.size;
}

void QuicBuffer::Push(quic_buffer_chunk* chunk) {
  size_++;
  count_++;
  if (!tail_) {
    root_.reset(chunk);
    head_ = tail_ = root_.get();
  } else {
    tail_->next.reset(chunk);
    tail_ = tail_->next.get();
    if (!head_)
      head_ = tail_;
  }
}

size_t QuicBuffer::SeekHead(size_t amount) {
  size_t n = 0;
  size_t amt = amount;
  while (head_ != nullptr && amt > 0) {
    head_ = head_->next.get();
    n++;
    amt--;
    count_--;
    rlength_ -= head_ == nullptr ? 0 : head_->buf.len;
  }
  return n;
}

void QuicBuffer::SeekHeadOffset(ssize_t amount) {
  if (amount < 0)
    return;
  size_t amt = std::min(amount < 0 ? length_ : amount, length_);
  while (head_ && amt > 0) {
    size_t len = head_->buf.len - head_->roffset;
    // If the remaining length in the head is greater than the
    // amount we're seeking, just adjust the roffset
    if (len > amt) {
      head_->roffset += amt;
      rlength_ -= amt;
      break;
    }
    // Otherwise, decrement the amt and advance the read head
    // one space and iterate from there.
    amt -= len;
    rlength_ -= len;
    head_ = head_->next.get();
  }
}

size_t QuicBuffer::DrainInto(
    add_fn add_to_list,
    size_t* length,
    size_t max_count) {
  size_t len = 0;
  size_t count = 0;
  bool seen_head = false;
  quic_buffer_chunk* pos = head_;
  if (pos == nullptr)
    return 0;
  if (length != nullptr) *length = 0;
  while (pos != nullptr && count < max_count) {
    count++;
    size_t datalen = pos->buf.len - pos->roffset;
    if (length != nullptr) *length += datalen;
    add_to_list(uv_buf_init(pos->buf.base + pos->roffset, datalen));
    if (pos == head_) seen_head = true;
    if (seen_head) len++;
    pos = pos->next.get();
  }
  return len;
}

bool QuicBuffer::Pop(int status) {
  if (!root_)
    return false;
  std::unique_ptr<quic_buffer_chunk> root(std::move(root_));
  root_ = std::move(root.get()->next);
  size_--;

  if (head_ == root.get())
    head_ = root_.get();
  if (tail_ == root.get())
    tail_ = root_.get();

  root->Done(status);
  return true;
}

void QuicBuffer::Consume(int status, ssize_t amount) {
  size_t amt = std::min(amount < 0 ? length_ : amount, length_);
  while (root_ && amt > 0) {
    auto root = root_.get();
    // Never allow for partial consumption of head when using a
    // non-cancel status
    // if (status == 0 && head_ == root)
    //   break;
    size_t len = root->buf.len - root->offset;
    if (len > amt) {
      length_ -= amt;
      root->offset += amt;
      break;
    }
    length_ -= len;
    amt -= len;
    Pop(status);
  }
}

}  // namespace quic
}  // namespace node
