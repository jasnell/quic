#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "node.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "stream_base-inl.h"
#include "node_quic_session.h"
#include "node_quic_stream.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "v8.h"

#include <algorithm>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace quic {

uv_buf_t QuicStreamListener::OnStreamAlloc(size_t size) {
  // TODO(@jasnell): For now, allocate space to copy the data into.
  // Check later to see if we can get away with not copying like
  // we do with http2
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

QuicStream::QuicStream(
    QuicSession* session,
    Local<Object> wrap,
    uint64_t stream_id) :
    AsyncWrap(session->env(), wrap, AsyncWrap::PROVIDER_QUICSTREAM),
    StreamBase(session->env()),
    session_(session),
    stream_id_(stream_id),
    flags_(QUICSTREAM_FLAG_INITIAL),
    available_outbound_length_(0),
    inbound_consumed_data_while_paused_(0) {
  CHECK_NOT_NULL(session);
  SetInitialFlags();
  session->AddStream(this);
  StreamBase::AttachToObject(GetObject());
  PushStreamListener(&stream_listener_);
  stream_stats_.created_at = uv_hrtime();
}

QuicStream::~QuicStream() {
  // Check that Destroy() has been called
  CHECK_NULL(session_);
  CHECK_EQ(0, streambuf_.Length());
  uint64_t now = uv_hrtime();
  Debug(this,
        "QuicStream %llu destroyed.\n"
        "  Duration: %llu\n"
        "  Bytes Received: %llu\n"
        "  Bytes Sent: %llu\n",
        GetID(),
        now - stream_stats_.created_at,
        stream_stats_.bytes_received,
        stream_stats_.bytes_sent);
}

inline void QuicStream::SetInitialFlags() {
  if (GetDirection() == QUIC_STREAM_UNIDIRECTIONAL) {
    if (session_->IsServer()) {
      switch (GetOrigin()) {
        case QUIC_STREAM_SERVER:
          SetReadClose();
          break;
        case QUIC_STREAM_CLIENT:
          SetWriteClose();
          break;
        default:
          UNREACHABLE();
      }
    } else {
      switch (GetOrigin()) {
        case QUIC_STREAM_SERVER:
          SetWriteClose();
          break;
        case QUIC_STREAM_CLIENT:
          SetReadClose();
          break;
        default:
          UNREACHABLE();
      }
    }
  }
}

// QuicStream::Close() is called by the QuicSession when ngtcp2 detects that
// a stream has been closed. This, in turn, calls out to the JavaScript to
// start the process of tearing down and destroying the QuicStream instance.
void QuicStream::Close(uint16_t app_error_code) {
  Debug(this, "Stream %llu closed with code %d", GetID(), app_error_code);
  SetReadClose();
  SetWriteClose();
  HandleScope scope(env()->isolate());
  Context::Scope context_context(env()->context());
  Local<Value> arg = Number::New(env()->isolate(), app_error_code);
  MakeCallback(env()->quic_on_stream_close_function(), 1, &arg);
}

// Receiving a reset means that any data we've accumulated to send
// can be discarded and we don't want to keep writing data, so
// we want to clear our outbound buffers here and notify
// the JavaScript side that we've been reset so that we stop
// pumping data out.
void QuicStream::Reset(uint64_t final_size, uint16_t app_error_code) {
  Debug(this,
        "Resetting stream %llu with app error code %d, and final size %llu",
        GetID(),
        app_error_code,
        final_size);
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  streambuf_.Cancel();
  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(final_size)),
    Integer::New(env()->isolate(), app_error_code)
  };
  MakeCallback(env()->quic_on_stream_reset_function(), arraysize(argv), argv);
}

void QuicStream::Destroy() {
  SetReadClose();
  SetWriteClose();
  streambuf_.Cancel();
  session_->RemoveStream(stream_id_);
  session_ = nullptr;
}

// Do shutdown is called when the JS stream writable side is closed.
// We want to mark the writable side closed and send pending data.
int QuicStream::DoShutdown(ShutdownWrap* req_wrap) {
  if (IsDestroyed())
    return UV_EPIPE;
  // Do nothing if the stream was already shutdown. Specifically,
  // we should not attempt to send anything on the QuicSession
  if (!IsWritable())
    return 1;
  stream_stats_.closing_at = uv_hrtime();
  SetWriteClose();
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
  // the QuicStream is no longer writable.
  if (IsDestroyed() || !IsWritable()) {
    req_wrap->Done(UV_EOF);
    return 0;
  }
  // There's a difficult balance required here:
  //
  // Unlike typical UDP, which is fire-and-forget, QUIC packets
  // have to be acknowledged. If a packet is not acknowledged
  // soon enough, it is retransmitted. The exact arrangement
  // of packets being retransmitted varies over the course of
  // the connection on many factors, so we can't simply encode
  // the packets and resend them. Instead, we have to retain the
  // original data and re-encode packets on each transmission
  // attempt. This means we have to persist the data written
  // until either an acknowledgement is received or the stream
  // is reset and canceled.
  //
  // That said, on the JS Streams API side, we can only write
  // one batch of buffers at a time. That is, DoWrite won't be
  // called again until the previous DoWrite is completed by
  // calling WriteWrap::Done(). The challenge, however, is that
  // calling Done() essentially signals that we're done with
  // the buffers being written, allowing those to be freed.
  //
  // In other words, if we just store the given buffers and
  // wait to call Done() when we receive an acknowledgement,
  // we severely limit our throughput and kill performance
  // because the JavaScript side won't be able to send additional
  // buffers until we receive the acknowledgement from the peer.
  // However, if we call Done() here to allow the next chunk to
  // be written, we have to copy the data because the buffers
  // may end up being freed once the callback is invoked. The
  // memcpy obviously incurs a cost but it'll at least be less
  // than waiting for the acknowledgement, allowing data to be
  // written faster but at the cost of a data copy.
  //
  // Because of the need to copy, performing many small writes
  // will incur a performance penalty over a smaller number of
  // larger writes, but only up to a point. Frequently copying
  // large chunks of data will end up slowing things down also.
  //
  // Because we are copying to allow the JS side to write
  // faster independently of the underlying send, we will have
  // to be careful not to allow the internal buffer to grow
  // too large, or we'll run into several other problems.

  uint64_t len = streambuf_.Copy(bufs, nbufs);
  IncrementStat(len, &stream_stats_, &stream_stats::bytes_sent);
  req_wrap->Done(0);
  stream_stats_.stream_sent_at = uv_hrtime();
  session_->SendStreamData(this);

  // IncrementAvailableOutboundLength(len);
  return 0;
}

void QuicStream::AckedDataOffset(uint64_t offset,  size_t datalen) {
  if (IsDestroyed())
    return;
  streambuf_.Consume(datalen);
  stream_stats_.stream_acked_at = uv_hrtime();
}

size_t QuicStream::DrainInto(
    std::vector<ngtcp2_vec>* vec,
    QuicBuffer::drain_from from) {
  return streambuf_.DrainInto(vec, from);
}

void QuicStream::Commit(size_t count) {
  streambuf_.SeekHead(count);
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
// TODO(@jasnell): There's currently no flow control here. The data is pushed
// up to the JavaScript side regardless of whether the JS stream is flowing and
// the connected peer is told to keep sending. We need to implement back
// pressure.
void QuicStream::ReceiveData(int fin, const uint8_t* data, size_t datalen) {
  Debug(this, "Receiving %d bytes of data. Final? %s. Readable? %s",
        datalen, fin ? "yes" : "no", IsReadable() ? "yes" : "no");

  if (!IsReadable())
    return;

  IncrementStat(datalen, &stream_stats_, &stream_stats::bytes_received);

  stream_stats_.stream_received_at = uv_hrtime();

  while (datalen > 0) {
    uv_buf_t buf = EmitAlloc(datalen);
    size_t avail = std::min(static_cast<size_t>(buf.len), datalen);

    // TODO(@jasnell): For now, we're allocating and copying. Once
    // we determine if we can safely switch to a non-allocated mode
    // like we do with http2 streams, we can make this branch more
    // efficient by using the LIKELY optimization
    // if (LIKELY(buf.base == nullptr))
    if (buf.base == nullptr)
      buf.base = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
    else
      memcpy(buf.base, data, avail);
    data += avail;
    datalen -= avail;
    EmitRead(avail, buf);
    if (IsReadPaused())
      inbound_consumed_data_while_paused_ += avail;
    else
      session_->ExtendStreamOffset(this, avail);
  };

  // When fin != 0, we've received that last chunk of data for this
  // stream, indicating that the stream is no longer readable.
  if (fin) {
    SetReadClose();
    EmitRead(UV_EOF);
  }
}

QuicStream* QuicStream::New(
    QuicSession* session,
    uint64_t stream_id) {
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
  int err = session->OpenUnidirectionalStream(&stream_id);
  if (err != 0) {
    args.GetReturnValue().Set(err);
    return;
  }

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void OpenBidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  int err = session->OpenBidirectionalStream(&stream_id);
  if (err != 0) {
    args.GetReturnValue().Set(err);
    return;
  }

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void QuicStreamDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Destroy();
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
  env->SetProtoMethod(stream,
                      "destroy",
                      QuicStreamDestroy);
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
