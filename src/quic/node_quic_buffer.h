#ifndef SRC_NODE_QUIC_BUFFER_H_
#define SRC_NODE_QUIC_BUFFER_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "memory_tracker-inl.h"
#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_internals.h"
#include "util.h"
#include "uv.h"

namespace node {
namespace quic {

class QuicBuffer;

constexpr size_t MAX_VECTOR_COUNT = 16;

// QuicBuffer an internal linked list of uv_buf_t instances
// representing data that is to be sent. All data in the
// Buffer has to be retained until it is Consumed or Canceled.
// For QUIC, the data is not consumed until an explicit ack
// is received or we know that we do not need the data.

typedef std::function<void(int status)> done_cb;

typedef std::function<void(uv_buf_t buf)> add_fn;

// Default non-op done handler.
inline void default_quicbufferchunk_done(int status);

// A QuicBufferChunk contains the actual buffered data
// along with a callback to be called when the data has
// been consumed.
class QuicBufferChunk : public MemoryRetainer {
 public:
  // In this variant, the QuicBufferChunk owns the underlying
  // data storage within a MaybeStackBuffer. The data will be
  // freed when the QuicBufferChunk is destroyed.
  inline explicit QuicBufferChunk(size_t len);

  // In this variant, the QuicBufferChunk only maintains a
  // pointer to the underlying data buffer. The QuicBufferChunk
  // does not take ownership of the buffer. The done callback
  // is invoked to let the caller know when the chunk is no
  // longer being used.
  inline QuicBufferChunk(uv_buf_t buf_, done_cb done_);

  inline ~QuicBufferChunk() override;
  inline void Done(int status);
  inline void MemoryInfo(MemoryTracker* tracker) const override;

  uint8_t* out() { return reinterpret_cast<uint8_t*>(buf_.base); }

  SET_MEMORY_INFO_NAME(QuicBufferChunk)
  SET_SELF_SIZE(QuicBufferChunk)

 private:
  // In practice, the amount of data stored in data_buf_ can vary
  // broadly from double to quadruple digits. 200 should cover the
  // most common cases but we can adjust it up or down if necessary
  // later. Currently, data_buf_ is only used when writing handshake
  // data. See QuicCryptoContext::WriteHandshake
  MaybeStackBuffer<uint8_t, 200> data_buf_;
  uv_buf_t buf_;
  done_cb done_ = default_quicbufferchunk_done;
  size_t offset_ = 0;
  size_t roffset_ = 0;
  bool done_called_ = false;
  std::unique_ptr<QuicBufferChunk> next_;

  friend class QuicBuffer;
};

// A QuicBuffer is a linked-list of QuicBufferChunk instances.
// There are three significant pointers: root_, head_, and tail_.
//   * root_ is the base of the linked list
//   * head_ is a pointer to the current read position of the linked list
//   * tail_ is a pointer to the current write position of the linked list
// Items are dropped from the linked list only when either Consume() or
// Cancel() is called. Consume() will consume a given number of bytes up
// to, but not including the read head_. Cancel() will consume all remaining
// bytes in the linked list. As whole QuicBufferChunk instances are
// consumed, the corresponding Done callback will be invoked, allowing
// any memory to be freed up.
//
// Use SeekHead(n) to advance the read head_ forward n positions.
//
// DrainInto() will drain the remaining QuicBufferChunk instances
// into a vector and will advance the read head_ to the end of the
// QuicBuffer. The function will return the number of positions drained
// which would then be passed to SeekHead(n) to advance the read head.
//
// QuicBuffer supports move assignment that will completely reset the source.
// That is,
//  QuicBuffer buf1;
//  QuicBuffer buf2;
//  buf2 = std::move(buf1);
//
// Will reset the state of buf2 to that of buf1, then reset buf1
//
// There is also an overloaded += operator that will append the source
// content to the destination and reset the source.
// That is,
//  QuicBuffer buf1;
//  QuicBuffer buf2;
//  buf2 += std::move(buf1);
//
// Will append the contents of buf1 to buf2, then reset buf1
class QuicBuffer : public MemoryRetainer {
 public:
  QuicBuffer() {}

  QuicBuffer(QuicBuffer&& src) noexcept
    : head_(src.head_),
      tail_(src.tail_),
      size_(src.size_),
      count_(src.count_),
      length_(src.length_),
      rlength_(src.rlength_) {
    root_ = std::move(src.root_);
    reset(&src);
  }

  inline QuicBuffer& operator=(QuicBuffer&& src) noexcept;

  QuicBuffer& operator+=(QuicBuffer&& src) noexcept;

  ~QuicBuffer() override {
    Cancel();  // Cancel the remaining data
    CHECK_EQ(length_, 0);
  }

  // Push one or more uv_buf_t instances into the buffer.
  // the done_cb callback will be invoked when the last
  // uv_buf_t in the bufs array is consumed and popped out
  // of the internal linked list.
  size_t Push(
      uv_buf_t* bufs,
      size_t nbufs,
      done_cb done = default_quicbufferchunk_done);

  void Push(std::unique_ptr<QuicBufferChunk> chunk);

  // Consume the given number of bytes within the buffer. If amount is
  // negative, all buffered bytes that are available to be consumed are
  // consumed.
  inline void Consume(ssize_t amount = -1);

  // Cancels the remaining bytes within the buffer
  inline size_t Cancel(int status = UV_ECANCELED);

  // The total buffered bytes
  size_t Length() const { return length_; }

  size_t RemainingLength() const { return rlength_; }

  // The total number of buffers
  size_t Size() const { return size_; }

  // The number of buffers remaining to be read
  size_t ReadRemaining() const { return count_; }

  // Drain the remaining buffers into the given vector.
  // The function will return the number of positions the
  // read head_ can be advanced.
  inline size_t DrainInto(
      std::vector<uv_buf_t>* list,
      size_t* length = nullptr,
      size_t max_count = MAX_VECTOR_COUNT);

  template <typename T>
  inline size_t DrainInto(
      std::vector<T>* list,
      size_t* length,
      size_t max_count);

  template <typename T>
  inline size_t DrainInto(
      T* list,
      size_t* count,
      size_t* length,
      size_t max_count);

  // Returns the current read head or an empty buffer if
  // we're empty
  inline uv_buf_t Head();

  // Moves the current read head forward the given
  // number of buffers. If amount is greater than
  // the number of buffers remaining, move to the
  // end, and return the actual number advanced.
  size_t SeekHead(size_t amount = 1);
  void SeekHeadOffset(ssize_t amount);

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("length", length_);
  }
  SET_MEMORY_INFO_NAME(QuicBuffer);
  SET_SELF_SIZE(QuicBuffer);

 private:
  void Consume(int status, ssize_t amount);
  size_t DrainInto(add_fn add_to_list, size_t* length, size_t max_count);
  bool Pop(int status = 0);
  inline void Push(uv_buf_t buf, done_cb done = nullptr);
  inline static void reset(QuicBuffer* buf);

  std::unique_ptr<QuicBufferChunk> root_;
  QuicBufferChunk* head_ = nullptr;  // Current Read Position
  QuicBufferChunk* tail_ = nullptr;  // Current Write Position
  size_t size_ = 0;
  size_t count_ = 0;
  size_t length_ = 0;
  size_t rlength_ = 0;

  friend class QuicBufferChunk;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_BUFFER_H_
