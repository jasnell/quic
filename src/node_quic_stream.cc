#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "node.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "stream_base-inl.h"
#include "node_quic_session-inl.h"
#include "node_quic_stream.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <algorithm>
#include <limits>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace quic {

uv_buf_t QuicStreamListener::OnStreamAlloc(size_t size) {
  Environment* env = static_cast<QuicStream*>(stream_)->env();
  return env->AllocateManaged(size).release();
}

void QuicStreamListener::OnStreamRead(ssize_t nread, const uv_buf_t& buf) {
  QuicStream* stream = static_cast<QuicStream*>(stream_);
  Environment* env = stream->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  if (nread < 0) {
    PassReadErrorToPreviousListener(nread);
    return;
  }

  AllocatedBuffer buffer(stream->env(), buf);
  stream->CallJSOnreadMethod(nread, buffer.ToArrayBuffer());
}

// TODO(@jasnell): QUIC connections have an absolute maximum
// number of packets that can be transmitted over the lifetime
// of the stream. When the number of packets is exhausted, the
// connection must be silently closed without sending any
// additional frames to the peer. When that happens, all
// existing streams need to be shutdown and special event
// should be emitted so that we can pick up where things
// left off.

QuicStream::QuicStream(
    QuicSession* session,
    Local<Object> wrap,
    int64_t stream_id) :
    AsyncWrap(session->env(), wrap, AsyncWrap::PROVIDER_QUICSTREAM),
    StreamBase(session->env()),
    session_(session),
    stream_id_(stream_id),
    max_offset_(0),
    max_offset_ack_(0),
    flags_(QUICSTREAM_FLAG_INITIAL),
    available_outbound_length_(0),
    inbound_consumed_data_while_paused_(0),
    data_rx_rate_(1, std::numeric_limits<int64_t>::max()),
    data_rx_size_(1, NGTCP2_MAX_PKT_SIZE),
    data_rx_ack_(1, std::numeric_limits<int64_t>::max()),
    stats_buffer_(
      session->env()->isolate(),
      sizeof(stream_stats_) / sizeof(uint64_t),
      reinterpret_cast<uint64_t*>(&stream_stats_)) {
  CHECK_NOT_NULL(session);
  session->AddStream(this);
  Debug(this, "Created");
  StreamBase::AttachToObject(GetObject());
  PushStreamListener(&stream_listener_);
  stream_stats_.created_at = uv_hrtime();

  USE(wrap->DefineOwnProperty(
      env()->context(),
      env()->stats_string(),
      stats_buffer_.GetJSArray(),
      PropertyAttribute::ReadOnly));
}

std::string QuicStream::diagnostic_name() const {
  return std::string("QuicStream ") + std::to_string(GetID()) +
         " (" + std::to_string(static_cast<int64_t>(get_async_id())) +
         ", " + session_->diagnostic_name() + ")";
}

void QuicStream::Destroy() {
  if (IsDestroyed())
    return;
  SetDestroyed();
  SetReadClose();
  SetWriteClose();

  uint64_t now = uv_hrtime();
  Debug(this,
        "Destroying.\n"
        "  Duration: %" PRIu64 "\n"
        "  Bytes Received: %" PRIu64 "\n"
        "  Bytes Sent: " PRIu64,
        now - stream_stats_.created_at,
        stream_stats_.bytes_received,
        stream_stats_.bytes_sent);

  // If there is data currently buffered in the streambuf_,
  // then cancel will call out to invoke an arbitrary
  // JavaScript callback (the on write callback). Within
  // that callback, however, the QuicStream will no longer
  // be usable to send or receive data.
  streambuf_.Cancel();
  CHECK_EQ(streambuf_.Length(), 0);

  // The QuicSession maintains a map of std::unique_ptrs to
  // QuicStream instances. Removing this here will cause
  // this QuicStream object to be deconstructed, so the
  // QuicStream object will no longer exist after this point.
  session_->RemoveStream(stream_id_);
}

// Do shutdown is called when the JS stream writable side is closed.
// If we're not within an ngtcp2 callback, this will trigger the
// QuicSession to send any pending data. Any time after this is
// called, a final stream frame will be sent for this QuicStream,
// but it may not be sent right away.
int QuicStream::DoShutdown(ShutdownWrap* req_wrap) {
  if (IsDestroyed())
    return UV_EPIPE;
  Debug(this, "Shutdown writable side");
  // Do nothing if the stream was already shutdown. Specifically,
  // we should not attempt to send anything on the QuicSession
  if (!IsWritable())
    return 1;
  stream_stats_.closing_at = uv_hrtime();
  SetWriteClose();

  // If we're not currently within an ngtcp2 callback, then we need to
  // tell the QuicSession to initiate serialization and sending of any
  // pending frames.
  if (!QuicSession::Ngtcp2CallbackScope::InNgtcp2CallbackScope(session_))
    session_->SendStreamData(this);

  return 1;
}

int QuicStream::DoWrite(
    WriteWrap* req_wrap,
    uv_buf_t* bufs,
    size_t nbufs,
    uv_stream_t* send_handle) {
  CHECK_NULL(send_handle);

  // A write should not have happened if we've been destroyed or
  // the QuicStream is no longer (or was never) writable.
  if (IsDestroyed() || !IsWritable()) {
    req_wrap->Done(UV_EOF);
    return 0;
  }

  // The list of buffers will be appended onto streambuf_ without
  // copying. Those will remain in that buffer until the serialized
  // stream frames are acknowledged.
  uint64_t length =
      streambuf_.Push(
          bufs,
          nbufs,
          [&](int status, void* user_data) {
            // This callback function will be invoked once this
            // complete batch of buffers has been acknowledged
            // by the peer. This will have the side effect of
            // blocking additional pending writes from the
            // javascript side, so writing data to the stream
            // will be throttled by how quickly the peer is
            // able to acknowledge stream packets. This is good
            // in the sense of providing back-pressure, but
            // also means that writes will be significantly
            // less performant unless written in batches.
            WriteWrap* req_wrap = static_cast<WriteWrap*>(user_data);
            req_wrap->Done(status);
          },
          req_wrap,
          req_wrap->object());
  Debug(this, "Queuing %" PRIu64 " bytes of data from %d buffers",
        length, nbufs);
  IncrementStat(length, &stream_stats_, &stream_stats::bytes_sent);
  stream_stats_.stream_sent_at = uv_hrtime();

  // If we're not within an ngtcp2 callback, go ahead and send
  // the pending stream data. Otherwise, the data will be flushed
  // once the ngtcp2 callback scope exits and all streams with
  // data pending are flushed.
  if (!QuicSession::Ngtcp2CallbackScope::InNgtcp2CallbackScope(session_))
    session_->SendStreamData(this);

  // IncrementAvailableOutboundLength(len);
  return 0;
}

// AckedDataOffset is called when ngtcp2 has received an acknowledgement
// for one or more stream frames for this QuicStream. This will cause
// data stored in the streambuf_ outbound queue to be consumed and may
// result in the JavaScript callback for the write to be invoked.
void QuicStream::AckedDataOffset(uint64_t offset, size_t datalen) {
  if (IsDestroyed())
    return;

  // ngtcp2 guarantees that offset must always be greater
  // than the previously received offset, but let's just
  // make sure that holds.
  CHECK_GE(offset, max_offset_ack_);
  max_offset_ack_ = offset;

  Debug(this, "Acknowledging %d bytes", datalen);

  // Consumes the given number of bytes in the buffer. This may
  // have the side-effect of causing the onwrite callback to be
  // invoked if a complete chunk of buffered data has been acknowledged.
  streambuf_.Consume(datalen);

  uint64_t now = uv_hrtime();
  if (stream_stats_.stream_acked_at > 0)
    data_rx_ack_.Record(now - stream_stats_.stream_acked_at);
  stream_stats_.stream_acked_at = now;
}

void QuicStream::Commit(ssize_t amount) {
  CHECK(!IsDestroyed());
  streambuf_.SeekHeadOffset(amount);
}

size_t QuicStream::DrainInto(std::vector<ngtcp2_vec>* vec) {
  CHECK(!IsDestroyed());
  size_t length = 0;
  streambuf_.DrainInto(vec, &length);
  return length;
}

inline void QuicStream::IncrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ += amount;
}

inline void QuicStream::DecrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ -= amount;
}

int QuicStream::ReadStart() {
  CHECK(!this->IsDestroyed());
  CHECK(IsReadable());
  SetReadStart();
  SetReadResume();
  session_->ExtendStreamOffset(this, inbound_consumed_data_while_paused_);
  return 0;
}

int QuicStream::ReadStop() {
  CHECK(!this->IsDestroyed());
  CHECK(IsReadable());
  SetReadPause();
  return 0;
}

// Passes chunks of data on to the JavaScript side as soon as they are
// received but only if we're still readable. The caller of this must have a
// HandleScope.
//
// Note that this is pushing data to the JS side regardless of whether
// anything is listening. For flow-control, we only send window updates
// to the sending peer if the stream is in flowing mode, so the sender
// should not be sending too much data.
void QuicStream::ReceiveData(
    int fin,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving %d bytes. Final? %s. Readable? %s",
        datalen,
        fin ? "yes" : "no",
        IsReadable() ? "yes" : "no");

  // If the QuicStream is not (or was never) readable, just ignore the chunk.
  if (!IsReadable())
    return;

  // ngtcp2 guarantees that datalen will only be 0 if fin is set.
  // Let's just make sure.
  CHECK(datalen > 0 || fin == 1);

  // ngtcp2 guarantees that offset is always greater than the previously
  // received offset. Let's just make sure.
  CHECK_GE(offset, max_offset_);
  max_offset_ = offset;

  if (datalen > 0) {
    // IncrementStats will update the data_rx_rate_ and data_rx_size_
    // histograms. These will provide data necessary to detect and
    // prevent Slow Send DOS attacks specifically by allowing us to
    // see if a connection is sending very small chunks of data at very
    // slow speeds. It is important to emphasize, however, that slow send
    // rates may be perfectly legitimate so we cannot simply take blanket
    // action when slow rates are detected. Nor can we reliably define what
    // a slow rate even is! Will will need to determine some reasonable
    // default and allow user code to change the default as well as determine
    // what action to take. The current strategy will be to trigger an event
    // on the stream when data transfer rates are likely to be considered too
    // slow.
    IncrementStats(datalen);
    while (datalen > 0) {
      uv_buf_t buf = EmitAlloc(datalen);
      size_t avail = std::min(static_cast<size_t>(buf.len), datalen);

      // For now, we're allocating and copying. Once we determine if we can
      // safely switch to a non-allocated mode like we do with http2 streams,
      // we can make this branch more efficient by using the LIKELY
      // optimization. The way ngtcp2 currently works, however, we have
      // to memcpy here.
      if (UNLIKELY(buf.base == nullptr))
        buf.base = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
      else
        memcpy(buf.base, data, avail);
      data += avail;
      datalen -= avail;
      // Capture read_paused before EmitRead in case user code callbacks
      // alter the state when EmitRead is called.
      bool read_paused = IsReadPaused();
      EmitRead(avail, buf);
      // Reading can be paused while we are processing. If that's
      // the case, we still want to acknowledge the current bytes
      // so that pausing does not throw off our flow control.
      if (read_paused)
        inbound_consumed_data_while_paused_ += avail;
      else
        session_->ExtendStreamOffset(this, avail);
    }
  }

  // When fin != 0, we've received that last chunk of data for this
  // stream, indicating that the stream will no longer be readable.
  if (fin) {
    SetFinReceived();
    EmitRead(UV_EOF);
  }
}

inline void QuicStream::IncrementStats(size_t datalen) {
  uint64_t len = static_cast<uint64_t>(datalen);
  IncrementStat(len, &stream_stats_, &stream_stats::bytes_received);

  uint64_t now = uv_hrtime();
  if (stream_stats_.stream_received_at > 0)
    data_rx_rate_.Record(now - stream_stats_.stream_received_at);
  stream_stats_.stream_received_at = now;
  data_rx_size_.Record(len);
}

void QuicStream::Shutdown(uint64_t app_error_code) {
  // On calling shutdown, the stream will no longer be
  // readable or writable, all any pending data in the
  // streambuf_ will be canceled, and all data pending
  // to be acknowledged at the ngtcp2 level will be
  // abandoned.
  SetReadClose();
  SetWriteClose();
  session_->ShutdownStream(GetID(), app_error_code);
}

QuicStream* QuicStream::New(QuicSession* session, int64_t stream_id) {
  Local<Object> obj;
  if (!session->env()
              ->quicserverstream_constructor_template()
              ->NewInstance(session->env()->context()).ToLocal(&obj)) {
    return nullptr;
  }
  return new QuicStream(session, obj, stream_id);
}

// JavaScript API
namespace {
void QuicStreamGetID(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(static_cast<double>(stream->GetID()));
}

void OpenUnidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  if (!session->OpenUnidirectionalStream(&stream_id))
    return;

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void OpenBidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  if (!session->OpenBidirectionalStream(&stream_id))
    return;

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void QuicStreamDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Destroy();
}

void QuicStreamShutdown(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());

  uint32_t family = QUIC_ERROR_APPLICATION;
  uint64_t code = ExtractErrorCode(env, args[0]);
  USE(args[1]->Uint32Value(env->context()).To(&family));

  stream->Shutdown(family == QUIC_ERROR_APPLICATION ? code : NGTCP2_NO_ERROR);
}
}  // namespace

void QuicStream::Initialize(
    Environment* env,
    Local<Object> target,
    Local<Context> context) {
  Isolate* isolate = env->isolate();
  Local<String> class_name = FIXED_ONE_BYTE_STRING(isolate, "QuicStream");
  Local<FunctionTemplate> stream = FunctionTemplate::New(env->isolate());
  stream->SetClassName(class_name);
  stream->Inherit(AsyncWrap::GetConstructorTemplate(env));
  StreamBase::AddMethods(env, stream);
  Local<ObjectTemplate> streamt = stream->InstanceTemplate();
  streamt->SetInternalFieldCount(StreamBase::kStreamBaseFieldCount);
  streamt->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(stream, "destroy", QuicStreamDestroy);
  env->SetProtoMethod(stream, "shutdownStream", QuicStreamShutdown);
  env->SetProtoMethod(stream, "id", QuicStreamGetID);
  env->set_quicserverstream_constructor_template(streamt);
  target->Set(env->context(),
              class_name,
              stream->GetFunction(env->context()).ToLocalChecked()).FromJust();

  env->SetMethod(target, "openBidirectionalStream", OpenBidirectionalStream);
  env->SetMethod(target, "openUnidirectionalStream", OpenUnidirectionalStream);
}

}  // namespace quic
}  // namespace node
