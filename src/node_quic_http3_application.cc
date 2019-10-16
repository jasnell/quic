#include "node.h"
#include "debug_utils.h"
#include "node_http_common.h"
#include "node_quic_http3_application.h"
#include "node_quic_session-inl.h"
#include "node_quic_stream.h"
#include "node_quic_util.h"
#include "node_http_common.h"

#include <nghttp3/nghttp3.h>
#include <algorithm>

namespace node {

using v8::MaybeLocal;
using v8::Number;
using v8::String;
using v8::Value;

namespace quic {

namespace {
bool IsZeroLengthHeader(nghttp3_rcbuf* name, nghttp3_rcbuf* value) {
  return Http3RcBufferPointer::IsZeroLength(name) ||
         Http3RcBufferPointer::IsZeroLength(value);
}

const char* to_http_header_name(int32_t token) {
  switch (token) {
    default:
      // Fall through
    case -1: return nullptr;
#define V(name, value) case NGHTTP3_QPACK_TOKEN__##name: return value;
    HTTP_SPECIAL_HEADERS(V)
#undef V
#define V(name, value) case NGHTTP3_QPACK_TOKEN_##name: return value;
    HTTP_REGULAR_HEADERS(V)
#undef V
  }
}
}  // namespace

Http3Header::Http3Header(
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value) :
    token_(token) {
  // Only retain the name buffer if it's not a known token
  if (token == -1)
    name_.reset(name, true);  // Internalizable
  value_.reset(value);
}

MaybeLocal<String> Http3Header::GetName(Environment* env) const {
  const char* header_name = to_http_header_name(token_);

  // TODO(@jasnell): Can possibly just make these env strings.
  if (header_name != nullptr)
    return OneByteString(env->isolate(), header_name);

  if (UNLIKELY(!name_))
    return String::Empty(env->isolate());

  return Http3RcBufferPointer::External::New(env, name_);
}

MaybeLocal<String> Http3Header::GetValue(Environment* env) const {
  if (UNLIKELY(!value_))
    return String::Empty(env->isolate());

  return Http3RcBufferPointer::External::New(env, value_);
}

Http3Application::Http3Application(
    QuicSession* session) :
    QuicApplication(session) {
}

bool Http3Application::SubmitInformation(
    int64_t stream_id,
    v8::Local<v8::Array> headers) {
  Http3Headers nva(Session()->env(), headers);
  // TODO(@jasnell): Do we need more granularity on error conditions?
  return nghttp3_conn_submit_info(
      Connection(),
      stream_id,
      *nva,
      nva.length()) == 0;
}

bool Http3Application::SubmitHeaders(
    int64_t stream_id,
    v8::Local<v8::Array> headers,
    uint32_t flags) {
  Http3Headers nva(Session()->env(), headers);

  // If the TERMINAL flag is set, reader_ptr should be nullptr
  // so the stream will be terminated immediately after submitting
  // the headers.
  nghttp3_data_reader reader = { Http3Application::OnReadData };
  nghttp3_data_reader* reader_ptr;
  if (!(flags & QUICSTREAM_HEADER_FLAGS_TERMINAL))
    reader_ptr = &reader;

  // TODO(@jasnell): Do we need more granularity on error conditions?
  switch (Session()->CryptoContext()->Side()) {
    case NGTCP2_CRYPTO_SIDE_CLIENT:
      return nghttp3_conn_submit_request(
          Connection(),
          stream_id,
          *nva,
          nva.length(),
          reader_ptr,
          nullptr) == 0;
    case NGTCP2_CRYPTO_SIDE_SERVER:
      return nghttp3_conn_submit_response(
          Connection(),
          stream_id,
          *nva,
          nva.length(),
          reader_ptr) == 0;
    default:
      UNREACHABLE();
  }
  return false;
}

bool Http3Application::SubmitTrailers(
    int64_t stream_id,
    v8::Local<v8::Array> headers) {
  Http3Headers nva(Session()->env(), headers);
  // TODO(@jasnell): Do we need more granularity on error conditions?
  return nghttp3_conn_submit_trailers(
      Connection(),
      stream_id,
      *nva,
      nva.length()) == 0;
}

nghttp3_conn* Http3Application::CreateConnection(
    Http3Application* app,
    nghttp3_conn_settings* settings) {

  // nghttp3_conn_server_new and nghttp3_conn_client_new share
  // identical definitions, so new_fn will work for both.
  using new_fn = decltype(&nghttp3_conn_server_new);
  static new_fn new_fns[] = {
    nghttp3_conn_client_new,  // NGTCP2_CRYPTO_SIDE_CLIENT
    nghttp3_conn_server_new,  // NGTCP2_CRYPTO_SIDE_SERVER
  };

  // TODO(@jasnell): Reconcile with http2 and quic allocator logic
  const nghttp3_mem* mem = nghttp3_mem_default();
  ngtcp2_crypto_side side = app->Session()->CryptoContext()->Side();
  nghttp3_conn* conn;

  if (new_fns[side](&conn, &callbacks_[side], settings, mem, app) != 0)
    return nullptr;

  return conn;
}

bool Http3Application::CreateAndBindControlStream() {
  if (!Session()->OpenUnidirectionalStream(&control_stream_id_))
    return false;
  return nghttp3_conn_bind_control_stream(
      Connection(),
      control_stream_id_) == 0;
}

bool Http3Application::CreateAndBindQPackStreams() {
  if (!Session()->OpenUnidirectionalStream(&qpack_enc_stream_id_) ||
      !Session()->OpenUnidirectionalStream(&qpack_dec_stream_id_)) {
    return false;
  }

  return nghttp3_conn_bind_qpack_streams(
      Connection(),
      qpack_enc_stream_id_,
      qpack_dec_stream_id_) == 0;
}

bool Http3Application::Initialize() {
  if (!NeedsInit())
    return false;

  // The QuicSession must allow for at least three local unidirectional streams.
  // This number is fixed by the http3 specification.
  if (Session()->GetMaxLocalStreamsUni() < 3)
    return false;

  // TODO(@jasnell): How we provide application specific settings...
  nghttp3_conn_settings settings;
  nghttp3_conn_settings_default(&settings);

  // TODO(@jasnell): Make configurable
  settings.qpack_max_table_capacity = DEFAULT_QPACK_MAX_TABLE_CAPACITY;
  settings.qpack_blocked_streams = DEFAULT_QPACK_BLOCKED_STREAMS;

  connection_.reset(CreateConnection(this, &settings));
  CHECK(connection_);

  ngtcp2_transport_params params;
  Session()->GetLocalTransportParams(&params);

  nghttp3_conn_set_max_client_streams_bidi(
      Connection(),
      params.initial_max_streams_bidi);

  if (!CreateAndBindControlStream() ||
      !CreateAndBindQPackStreams()) {
    return false;
  }

  SetInitDone();
  return true;
}

bool Http3Application::ReceiveStreamData(
    int64_t stream_id,
    int fin,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  ssize_t nread =
      nghttp3_conn_read_stream(
          Connection(), stream_id, data, datalen, fin);
  if (nread < 0) {
    Debug(Session(), "Failure to read HTTP/3 Stream Data [%" PRId64 "]", nread);
    return false;
  }

  return true;
}

void Http3Application::AcknowledgeStreamData(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen) {
  if (nghttp3_conn_add_ack_offset(Connection(), stream_id, datalen) != 0)
    Debug(Session(), "Failure to acknowledge HTTP/3 Stream Data");
}

void Http3Application::StreamOpen(int64_t stream_id) {
  // FindOrCreateStream(stream_id);
}

void Http3Application::StreamClose(
    int64_t stream_id,
    uint64_t app_error_code) {
  if (app_error_code == 0)
    app_error_code = NGHTTP3_HTTP_NO_ERROR;
  nghttp3_conn_close_stream(Connection(), stream_id, app_error_code);
  QuicApplication::StreamClose(stream_id, app_error_code);
}

void Http3Application::StreamReset(
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code) {
  nghttp3_conn_reset_stream(Connection(), stream_id);
  QuicApplication::StreamReset(stream_id, final_size, app_error_code);
}

void Http3Application::ExtendMaxStreamsRemoteUni(uint64_t max_streams) {
  nghttp3_conn_set_max_client_streams_bidi(Connection(), max_streams);
}

void Http3Application::ExtendMaxStreamData(
    int64_t stream_id,
    uint64_t max_data) {
  nghttp3_conn_unblock_stream(Connection(), stream_id);
}

bool Http3Application::StreamCommit(QuicStream* stream, ssize_t datalen) {
  CHECK_GT(datalen, 0);
  stream->Commit(datalen);
  int err = nghttp3_conn_add_write_offset(
      Connection(),
      stream->GetID(),
      datalen);
  if (err != 0) {
    Session()->SetLastError(QUIC_ERROR_APPLICATION, err);
    return false;
  }
  return true;
}

bool Http3Application::SendPendingData() {
  std::array<nghttp3_vec, 16> vec;
  QuicPathStorage path;
  int err;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    ssize_t sveccnt = 0;

    if (Connection() && Session()->GetMaxDataLeft()) {
      sveccnt =
          nghttp3_conn_writev_stream(
              Connection(),
              &stream_id,
              &fin,
              vec.data(),
              vec.size());
      if (sveccnt < 0)
        return false;
    }

    QuicStream* stream = Session()->FindStream(stream_id);
    CHECK_NOT_NULL(stream);
    ssize_t ndatalen;
    nghttp3_vec* v = vec.data();
    size_t vcnt = static_cast<size_t>(sveccnt);

    MallocedBuffer<uint8_t> dest(Session()->GetMaxPacketLength());
    ssize_t nwrite =
        ngtcp2_conn_writev_stream(
            Session()->Connection(),
            &path.path,
            dest.data,
            Session()->GetMaxPacketLength(),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            stream_id,
            fin,
            reinterpret_cast<const ngtcp2_vec *>(v),
            vcnt,
            uv_hrtime());
    if (nwrite < 0) {
      switch (nwrite) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          if (Session()->GetMaxDataLeft() == 0)
            return true;
          // Fall through
        case NGTCP2_ERR_STREAM_SHUT_WR:
          err = nghttp3_conn_block_stream(Connection(), stream_id);
          if (err != 0) {
            Session()->SetLastError(QUIC_ERROR_APPLICATION, err);
            return false;
          }
          continue;
        case NGTCP2_ERR_WRITE_STREAM_MORE:
          if (!StreamCommit(stream, ndatalen))
            return false;
          continue;
      }
      return false;
    }

    if (nwrite == 0)
      return true;  // Congestion limited

    if (!StreamCommit(stream, ndatalen))
      return false;

    Debug(stream, "Sending %" PRIu64 "bytes in serialized packet", nwrite);
    dest.Realloc(nwrite);
    if (!Session()->SendPacket(std::move(dest), &path))
      return false;

    if (fin)
      stream->SetFinSent();
  }
  return true;
}

bool Http3Application::SendStreamData(QuicStream* stream) {
  return SendPendingData();
}

ssize_t Http3Application::H3ReadData(
    int64_t stream_id,
    nghttp3_vec* vec,
    size_t veccnt,
    uint32_t* pflags) {
  QuicStream* stream = Session()->FindStream(stream_id);
  size_t count = 0;
  if (stream) {
    stream->DrainInto(&vec, &count, std::min(veccnt, MAX_VECTOR_COUNT));
    CHECK_LE(count, MAX_VECTOR_COUNT);
    if (!stream->IsWritable())
      *pflags |= NGHTTP3_DATA_FLAG_EOF;
  }
  return count;
}

void Http3Application::H3AckedStreamData(
    int64_t stream_id,
    size_t datalen) {
  QuicStream* stream = Session()->FindStream(stream_id);
  if (stream) {
    stream->AckedDataOffset(0, datalen);
    nghttp3_conn_resume_stream(Connection(), stream_id);
  }
}

void Http3Application::H3StreamClose(
    int64_t stream_id,
    uint64_t app_error_code) {
  Environment* env = Session()->env();
  Local<Value> argv[] = {
    Number::New(env->isolate(), static_cast<double>(stream_id)),
    Number::New(env->isolate(), static_cast<double>(app_error_code))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(Session());
  Session()->MakeCallback(
      env->quic_on_stream_close_function(),
      arraysize(argv),
      argv);
}

QuicStream* Http3Application::FindOrCreateStream(int64_t stream_id) {
  QuicStream* stream = Session()->FindStream(stream_id);
  if (!stream) {
    if (Session()->IsGracefullyClosing()) {
      nghttp3_conn_close_stream(Connection(), stream_id, NGTCP2_ERR_CLOSING);
      return nullptr;
    }
    stream = Session()->CreateStream(stream_id);
    nghttp3_conn_set_stream_user_data(Connection(), stream_id, stream);
  }
  CHECK_NOT_NULL(stream);
  return stream;
}

void Http3Application::H3ReceiveData(
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen) {
  QuicStream* stream = FindOrCreateStream(stream_id);
  if (stream)
    stream->ReceiveData(0, data, datalen, 0);
}

void Http3Application::H3DeferredConsume(
    int64_t stream_id,
    size_t consumed) {
  H3ReceiveData(stream_id, nullptr, consumed);
}

void Http3Application::H3BeginHeaders(
  int64_t stream_id,
  QuicStreamHeadersKind kind) {
  QuicStream* stream = FindOrCreateStream(stream_id);
  if (!stream)
    return;
  stream->BeginHeaders(kind);
}

bool Http3Application::H3ReceiveHeader(
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags) {
  // Protect against zero-length headers
  if (!IsZeroLengthHeader(name, value)) {
    QuicStream* stream = Session()->FindStream(stream_id);
    if (stream) {
      if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
        nghttp3_vec vec = nghttp3_rcbuf_get_buf(value);
        if (memcmp(vec.base, "1", 1))
          stream->SetHeadersKind(QUICSTREAM_HEADERS_KIND_INFORMATIONAL);
        else
          stream->SetHeadersKind(QUICSTREAM_HEADERS_KIND_INITIAL);
      }
      auto header = std::make_unique<Http3Header>(token, name, value);
      return stream->AddHeader(std::move(header));
    }
  }

  return true;
}

void Http3Application::H3EndHeaders(int64_t stream_id) {
  QuicStream* stream = Session()->FindStream(stream_id);
  if (stream)
    stream->EndHeaders();
}

int Http3Application::H3BeginPushPromise(
    int64_t stream_id,
    int64_t push_id) {
  return 0;
}

bool Http3Application::H3ReceivePushPromise(
    int64_t stream_id,
    int64_t push_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags) {
  return true;
}

int Http3Application::H3EndPushPromise(
    int64_t stream_id,
    int64_t push_id) {
  return 0;
}

void Http3Application::H3CancelPush(
    int64_t push_id,
    int64_t stream_id) {
}

void Http3Application::H3SendStopSending(
    int64_t stream_id,
    uint64_t app_error_code) {
  Session()->ShutdownStream(stream_id, app_error_code);
}

int Http3Application::H3PushStream(
    int64_t push_id,
    int64_t stream_id) {
  return 0;
}

int Http3Application::H3EndStream(
    int64_t stream_id) {
  QuicStream* stream = FindOrCreateStream(stream_id);
  if (stream)
    stream->ReceiveData(1, nullptr, 0, 0);
  return 0;
}

const nghttp3_conn_callbacks Http3Application::callbacks_[2] = {
  // NGTCP2_CRYPTO_SIDE_CLIENT
  {
    OnAckedStreamData,
    OnStreamClose,
    OnReceiveData,
    OnDeferredConsume,
    OnBeginHeaders,
    OnReceiveHeader,
    OnEndHeaders,
    OnBeginTrailers, // Begin Trailers
    OnReceiveHeader, // Receive Trailer
    OnEndHeaders,    // End Trailers
    OnBeginPushPromise,
    OnReceivePushPromise,
    OnEndPushPromise,
    OnCancelPush,
    OnSendStopSending,
    OnPushStream,
    OnEndStream
  },
  // NGTCP2_CRYPTO_SIDE_SERVER
  {
    OnAckedStreamData,
    OnStreamClose,
    OnReceiveData,
    OnDeferredConsume,
    OnBeginHeaders,
    OnReceiveHeader,
    OnEndHeaders,
    OnBeginTrailers,  // Begin Trailers
    OnReceiveHeader, // Receive Trailer
    OnEndHeaders,    // End Trailers
    OnBeginPushPromise,
    OnReceivePushPromise,
    OnEndPushPromise,
    OnCancelPush,
    OnSendStopSending,
    OnPushStream,
    OnEndStream
  }
};

int Http3Application::OnAckedStreamData(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3AckedStreamData(stream_id, datalen);
  return 0;
}

int Http3Application::OnStreamClose(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3StreamClose(stream_id, app_error_code);
  return 0;
}

int Http3Application::OnReceiveData(
    nghttp3_conn* conn,
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3ReceiveData(stream_id, data, datalen);
  return 0;
}

int Http3Application::OnDeferredConsume(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t consumed,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3DeferredConsume(stream_id, consumed);
  return 0;
}

int Http3Application::OnBeginHeaders(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3BeginHeaders(stream_id);
  return 0;
}

int Http3Application::OnBeginTrailers(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3BeginHeaders(stream_id, QUICSTREAM_HEADERS_KIND_TRAILING);
  return 0;
}

int Http3Application::OnReceiveHeader(
    nghttp3_conn* conn,
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  // TODO(@jasnell): Need to determine the appropriate response code here
  // for when the header is not going to be accepted.
  return app->H3ReceiveHeader(stream_id, token, name, value, flags) ?
      0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

int Http3Application::OnEndHeaders(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3EndHeaders(stream_id);
  return 0;
}

int Http3Application::OnBeginPushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3BeginPushPromise(stream_id, push_id);
}

int Http3Application::OnReceivePushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3ReceivePushPromise(
      stream_id,
      push_id,
      token,
      name,
      value,
      flags) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

int Http3Application::OnEndPushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3EndPushPromise(stream_id, push_id);
}

int Http3Application::OnCancelPush(
    nghttp3_conn* conn,
    int64_t push_id,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3CancelPush(push_id, stream_id);
  return 0;
}

int Http3Application::OnSendStopSending(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3SendStopSending(stream_id, app_error_code);
  return 0;
}

int Http3Application::OnPushStream(
    nghttp3_conn* conn,
    int64_t push_id,
    int64_t stream_id,
    void* conn_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3PushStream(push_id, stream_id);
}

int Http3Application::OnEndStream(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3EndStream(stream_id);
}

ssize_t Http3Application::OnReadData(
    nghttp3_conn* conn,
    int64_t stream_id,
    nghttp3_vec* vec,
    size_t veccnt,
    uint32_t* pflags,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3ReadData(stream_id, vec, veccnt, pflags);
}
}  // namespace quic
}  // namespace node
