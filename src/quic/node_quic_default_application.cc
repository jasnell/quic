#include "debug_utils.h"
#include "node_quic_buffer-inl.h"
#include "node_quic_default_application.h"
#include "node_quic_session-inl.h"
#include "node_quic_socket.h"
#include "node_quic_stream-inl.h"
#include "node_quic_util-inl.h"
#include "node_sockaddr-inl.h"
#include <ngtcp2/ngtcp2.h>

#include <vector>

namespace node {
namespace quic {

DefaultApplication::DefaultApplication(
    QuicSession* session) :
    QuicApplication(session) {}

bool DefaultApplication::Initialize() {
  if (!needs_init())
    return false;
  Debug(session(), "Default QUIC Application Initialized");
  set_init_done();
  return true;
}

bool DefaultApplication::ReceiveStreamData(
    int64_t stream_id,
    int fin,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  // Ensure that the QuicStream exists before deferring to
  // QuicApplication specific processing logic.
  Debug(session(), "Default QUIC Application receiving stream data");
  QuicStream* stream = session()->FindStream(stream_id);
  if (stream == nullptr) {
    // Shutdown the stream explicitly if the session is being closed.
    if (session()->is_gracefully_closing()) {
      session()->ResetStream(stream_id, NGTCP2_ERR_CLOSING);
      return true;
    }

    // One potential DOS attack vector is to send a bunch of
    // empty stream frames to commit resources. Check that
    // here. Essentially, we only want to create a new stream
    // if the datalen is greater than 0, otherwise, we ignore
    // the packet. ngtcp2 should be handling this for us,
    // but we handle it just to be safe.
    if (UNLIKELY(datalen == 0))
      return true;

    stream = session()->CreateStream(stream_id);
  }
  CHECK_NOT_NULL(stream);

  stream->ReceiveData(fin, data, datalen, offset);
  return true;
}

void DefaultApplication::AcknowledgeStreamData(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen) {
  QuicStream* stream = session()->FindStream(stream_id);
  Debug(session(), "Default QUIC Application acknowledging stream data");
  // It's possible that the stream has already been destroyed and
  // removed. If so, just silently ignore the ack
  if (stream != nullptr)
    stream->Acknowledge(offset, datalen);
}

bool DefaultApplication::SendPendingData() {
  // Right now this iterates through the streams in the order they
  // were created. Later, we might want to implement a prioritization
  // scheme to allow higher priority streams to be serialized first.
  // Prioritization is left entirely up to the application layer in QUIC.
  // HTTP/3, for instance, drops prioritization entirely.
  Debug(session(), "Default QUIC Application sending pending data");
  for (const auto& stream : session()->streams()) {
    if (!SendStreamData(stream.second.get()))
      return false;

    // Check to make sure QuicSession state did not change in this iteration
    if (session()->is_in_draining_period() ||
        session()->is_in_closing_period() ||
        session()->is_destroyed()) {
      break;
    }
  }

  return true;
}

namespace {
void Consume(ngtcp2_vec** pvec, size_t* pcnt, size_t len) {
  ngtcp2_vec* v = *pvec;
  size_t cnt = *pcnt;

  for (; cnt > 0; --cnt, ++v) {
    if (v->len > len) {
      v->len -= len;
      v->base += len;
      break;
    }
    len -= v->len;
  }

  *pvec = v;
  *pcnt = cnt;
}

int IsEmpty(const ngtcp2_vec* vec, size_t cnt) {
  size_t i;
  for (i = 0; i < cnt && vec[i].len == 0; ++i) {}
  return i == cnt;
}
}  // anonymous namespace

int DefaultApplication::GetStreamData(StreamData* stream_data) {
  QuicStream* stream = session()->FindStream(stream_data->id);
  stream_data->remaining =
    stream->DrainInto(&stream_data->data, &stream_data->count, 16);
  stream_data->fin = stream->is_writable() ? 0 : 1;

  Debug(session(), "Selected %" PRId64 " buffers for stream %" PRId64 "%s",
        stream_data->count,
        stream_data->id,
        stream_data->fin == 1 ? " (fin)" : "");
  return 0;
}

bool DefaultApplication::SendStreamData(QuicStream* stream) {
  ssize_t ndatalen = 0;
  QuicPathStorage path;
  Debug(session(), "Default QUIC Application sending stream %" PRId64 " data",
        stream->id());

  StreamData stream_data;
  stream_data.id = stream->id();
  stream_data.user_data = stream;
  GetStreamData(&stream_data);

  // If there is no stream data and we're not sending fin,
  // Just return without doing anything.
  if (stream_data.count == 0 && !stream_data.fin) {
    Debug(stream, "There is no stream data to send");
    return true;
  }

  std::unique_ptr<QuicPacket> packet = CreateStreamDataPacket();
  uint8_t* pos = packet->data();

  for (;;) {
    // If packet was sent on the previous iteration, it will have been reset
    if (!packet) {
      packet = CreateStreamDataPacket();
      pos = packet->data();
    }

    ssize_t nwrite = WriteVStream(&path, pos, &ndatalen, stream_data);

    if (nwrite <= 0) {
      switch (nwrite) {
        case 0:
          goto congestion_limited;
        case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
          // There is a finite number of packets that can be sent
          // per connection. Once those are exhausted, there's
          // absolutely nothing we can do except immediately
          // and silently tear down the QuicSession. This has
          // to be silent because we can't even send a
          // CONNECTION_CLOSE since even those require a
          // packet number.
          session()->SilentClose();
          return false;
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          session()->StreamDataBlocked(stream->id());
          if (session()->max_data_left() == 0)
            goto congestion_limited;
          return true;
        case NGTCP2_ERR_STREAM_SHUT_WR:
          if (UNLIKELY(!BlockStream(stream_data.id)))
            return false;
          return true;
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          return true;
        case NGTCP2_ERR_WRITE_STREAM_MORE:
          CHECK_GT(ndatalen, 0);
          CHECK(StreamCommit(&stream_data, ndatalen));
          pos += ndatalen;
          continue;
      }
      session()->set_last_error(QUIC_ERROR_SESSION, static_cast<int>(nwrite));
      return false;
    }

    pos += nwrite;

    if (ndatalen >= 0)
      CHECK(StreamCommit(&stream_data, ndatalen));

    Debug(stream, "Sending %" PRIu64 " bytes in serialized packet", nwrite);
    packet->set_length(nwrite);
    if (!session()->SendPacket(std::move(packet), path))
      return false;

    packet.reset();
    pos = nullptr;

    if (ShouldSetFin(stream_data))
      set_stream_fin(stream_data.id);

    if (IsEmpty(stream_data.buf, stream_data.count))
      break;
  }

  return true;

 congestion_limited:
  if (pos - packet->data()) {
    // Some data was serialized into the packet. We need to send it.
    packet->set_length(pos - packet->data());
    Debug(session(), "Congestion limited, but %" PRIu64 " bytes pending.",
          packet->length());
    if (!session()->SendPacket(std::move(packet), path))
      return false;
  }
  return true;
}

bool DefaultApplication::StreamCommit(
    StreamData* stream_data,
    size_t datalen) {
  QuicStream* stream = static_cast<QuicStream*>(stream_data->user_data);
  stream_data->remaining -= datalen;
  Consume(&stream_data->buf, &stream_data->count, datalen);
  stream->Commit(datalen);
  return true;
}

bool DefaultApplication::ShouldSetFin(const StreamData& stream_data) {
  if (!IsEmpty(stream_data.buf, stream_data.count))
    return false;
  QuicStream* stream = static_cast<QuicStream*>(stream_data.user_data);
  return !stream->is_writable();
}

}  // namespace quic
}  // namespace node
