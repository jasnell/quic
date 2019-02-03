#include "debug_utils.h"
#include "node.h"
#include "env.h"
#include "node_crypto.h"  // SecureContext
#include "node_quic.h"
#include "node_quic_state.h"
#include "handle_wrap.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "node_crypto_bio.h"  // NodeBIO
// ClientHelloParser
#include "node_crypto_clienthello-inl.h"

#include <limits.h>
#include <stdarg.h>
#include <algorithm>
#include <string>

namespace node {

using crypto::SecureContext;
using crypto::SSLWrap;
using v8::Context;
using v8::Float64Array;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace {

void DebugLog(void *user_data, const char *fmt, ...) {
//   QuicSession* session = reinterpret_cast<QuicSession*>(user_data);
//   va_list args;
//   va_start(args, fmt);
//   Debug(session, fmt, args);
//   va_end(args);
}
}  // namespace

QuicSocketConfig::QuicSocketConfig(Environment* env) {}

QuicSessionConfig::QuicSessionConfig(Environment* env) {

  AliasedBuffer<double, Float64Array>& buffer =
      env->quic_state()->quicsocketconfig_buffer;
  uint64_t flags = buffer[IDX_QUIC_SOCKET_CONFIG_COUNT];

  // IDX_QUIC_SOCKET_ACK_DELAY_EXPONENT,
  // IDX_QUIC_SOCKET_DISABLE_MIGRATION,
  // IDX_QUIC_SOCKET_MAX_ACK_DELAY,

#define V(idx, setting, def)                                                  \
  if (flags & (1 << IDX_QUIC_SOCKET_##idx))                                   \
    set_##setting(static_cast<uint64_t>(buffer[IDX_QUIC_SOCKET_##idx]));
  QUICSESSION_CONFIG(V)
#undef V
}

void QuicSessionConfig::ToSettings(ngtcp2_settings* settings) {
#define V(idx, setting, def) settings->setting = setting##_;
  QUICSESSION_CONFIG(V)
#undef V

  settings->log_printf = DebugLog;
  settings->initial_ts = uv_hrtime();
  settings->stateless_reset_token_present = 1;
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(std::begin(settings->stateless_reset_token),
                std::end(settings->stateless_reset_token),
                [&dis]() { return dis(randgen); });
}

QuicServerSession::QuicServerSession(QuicSocket* socket, Local<Object> wrap) :
    AsyncWrap(socket->env(), wrap, AsyncWrap::PROVIDER_QUICSERVERSESSION),
    QuicSession(socket),
    SSLWrap(socket->env(), socket->GetServerSecureContext(),
            SSLWrap<QuicServerSession>::kServer) {
  MakeWeak();
}

void QuicServerSession::NewSessionDoneCb() {}

QuicSession::QuicSession(QuicSocket* socket) : socket_(socket) {}

void QuicSession::SetRemoteAddress(const sockaddr* addr) {
  switch (addr->sa_family) {
  case AF_INET6:
    memcpy(&remote_address_, addr, sizeof(sockaddr_in6));
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  case AF_INET:
    memcpy(&remote_address_, addr, sizeof(sockaddr_in));
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  default:
    UNREACHABLE();
  }
}

void QuicSession::InitTLS(SSL* ssl, bool is_server) {
  enc_in_ = crypto::NodeBIO::New(socket_->env()).release();
  enc_out_ = crypto::NodeBIO::New(socket_->env()).release();
  SSL_set_app_data(ssl, this);

  // TODO(@jasnell): Finish TLS init
  // SSL_set_msg_callback(ssl_, msg_cb);
  // SSL_set_msg_callback_arg(ssl_, this);
  // SSL_set_key_callback(ssl_, key_cb, this);

  if (is_server) {
    SSL_set_accept_state(ssl);
  } else {
    crypto::NodeBIO::FromBIO(enc_in_)->set_initial(kInitialClientBufferLength);
    SSL_set_connect_state(ssl);
  }
}

QuicServerSession* QuicServerSession::New(QuicSocket* socket) {
  Local<Object> obj;
  if (!socket->env()
             ->quicserversession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return nullptr;
  }
  return new QuicServerSession(socket, obj);
}

// TODO(@jasnell): Determine what this does... :-)
int QuicSession::recv_client_initial(
    ngtcp2_conn *conn,
    const ngtcp2_cid *dcid,
    void *user_data) {

  auto h = static_cast<QuicSession*>(user_data);

  // if (h->recv_client_initial(dcid) != 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  return 0;
}

int QuicSession::recv_crypto_data(
    ngtcp2_conn *conn,
    uint64_t offset,
    const uint8_t *data,
    size_t datalen,
    void *user_data) {
  // int rv;

  // if (!config.quiet) {
  //   debug::print_crypto_data(data, datalen);
  // }

  // auto h = static_cast<Handler *>(user_data);

  // h->write_client_handshake(data, datalen);

  // if (!ngtcp2_conn_get_handshake_completed(h->conn())) {
  //   rv = h->tls_handshake();
  //   if (rv != 0) {
  //     return rv;
  //   }
  //   return 0;
  // }

  // // SSL_do_handshake() might not consume all data (e.g.,
  // // NewSessionTicket).
  // return h->read_tls();
  return 0;
}

int QuicSession::handshake_completed(ngtcp2_conn *conn, void *user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // if (!config.quiet) {
  //   debug::handshake_completed(conn, user_data);
  // }

  // h->send_greeting();

  // return 0;
}

ssize_t QuicSession::do_hs_encrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->hs_encrypt_data(dest, destlen, plaintext, plaintextlen, key,
  //                                  keylen, nonce, noncelen, ad, adlen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  // return nwrite;
  return 0;
}

ssize_t QuicSession::do_hs_decrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->hs_decrypt_data(dest, destlen, ciphertext, ciphertextlen,
  //                                  key, keylen, nonce, noncelen, ad, adlen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_TLS_DECRYPT;
  // }

  // return nwrite;
  return 0;
}

ssize_t QuicSession::do_encrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->encrypt_data(dest, destlen, plaintext, plaintextlen, key,
  //                               keylen, nonce, noncelen, ad, adlen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  // return nwrite;
  return 0;
}

ssize_t QuicSession::do_decrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->decrypt_data(dest, destlen, ciphertext, ciphertextlen, key,
  //                               keylen, nonce, noncelen, ad, adlen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_TLS_DECRYPT;
  // }

  // return nwrite;
  return 0;
}

ssize_t QuicSession::do_in_hp_mask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->in_hp_mask(dest, destlen, key, keylen, sample, samplelen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  // if (!config.quiet && config.show_secret) {
  //   debug::print_hp_mask(dest, destlen, sample, samplelen);
  // }

  // return nwrite;
  return 0;
}

ssize_t QuicSession::do_hp_mask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // auto nwrite = h->hp_mask(dest, destlen, key, keylen, sample, samplelen);
  // if (nwrite < 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  // if (!config.quiet && config.show_secret) {
  //   debug::print_hp_mask(dest, destlen, sample, samplelen);
  // }

  // return nwrite;
  return 0;
}

int QuicSession::recv_stream_data(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  // auto h = static_cast<Handler *>(user_data);

  // if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }

  return 0;
}

int QuicSession::acked_crypto_offset(
    ngtcp2_conn* conn,
    uint64_t offset,
    size_t datalen,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);
  // h->remove_tx_crypto_data(offset, datalen);
  return 0;
}

int QuicSession::acked_stream_data_offset(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    uint64_t offset,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  // auto h = static_cast<Handler *>(user_data);
  // if (h->remove_tx_stream_data(stream_id, offset, datalen) != 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }
  return 0;
}

int QuicSession::stream_close(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  // auto h = static_cast<Handler *>(user_data);
  // h->on_stream_close(stream_id);
  return 0;
}

int QuicSession::rand(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    ngtcp2_rand_ctx ctx,
    void* user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
}

int QuicSession::get_new_connection_id(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  // auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  // auto f = [&dis]() { return dis(randgen); };

  // std::generate_n(cid->data, cidlen, f);
  // cid->datalen = cidlen;
  // std::generate_n(token, NGTCP2_STATELESS_RESET_TOKENLEN, f);

  // auto h = static_cast<Handler *>(user_data);
  // h->server()->associate_cid(cid, h);

  return 0;
}

int QuicSession::update_key(
    ngtcp2_conn* conn,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);
  // if (h->update_key() != 0) {
  //   return NGTCP2_ERR_CALLBACK_FAILURE;
  // }
  return 0;
}

int QuicSession::remove_connection_id(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  // auto h = static_cast<Handler *>(user_data);
  // h->server()->dissociate_cid(cid);
  return 0;
}

int QuicSession::path_validation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data) {
  // if (!config.quiet) {
  //   debug::path_validation(path, res);
  // }
  return 0;
}

int QuicServerSession::Init(const struct sockaddr* addr,
                            const ngtcp2_cid* dcid,
                            const ngtcp2_cid* ocid,
                            uint32_t version) {
  SetRemoteAddress(addr);
  InitTLS(ssl_.get(), is_server());

  auto callbacks = ngtcp2_conn_callbacks{
    nullptr,
    QuicSession::recv_client_initial,
    QuicSession::recv_crypto_data,
    QuicSession::handshake_completed,
    nullptr,
    QuicSession::do_hs_encrypt,
    QuicSession::do_hs_decrypt,
    QuicSession::do_encrypt,
    QuicSession::do_decrypt,
    QuicSession::do_in_hp_mask,
    QuicSession::do_hp_mask,
    QuicSession::recv_stream_data,
    QuicSession::acked_crypto_offset,
    QuicSession::acked_stream_data_offset,
    nullptr,  // stream_open
    QuicSession::stream_close,
    nullptr,  // recv_stateless_reset
    nullptr,  // recv_retry
    nullptr,  // extend_max_streams_bidi
    nullptr,  // extend_max_streams_uni
    QuicSession::rand,
    QuicSession::get_new_connection_id,
    QuicSession::remove_connection_id,
    QuicSession::update_key,
    QuicSession::path_validation
  };

  ngtcp2_settings settings{};
  Socket()->SetServerSessionSettings(&settings);

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  scid_.datalen = NGTCP2_SV_SCIDLEN;
  std::generate(scid_.data, scid_.data + scid_.datalen,
                [&dis]() { return dis(randgen); });


  auto socket = Socket();
  auto connection = **this;

  sockaddr_storage storage;
  int addrlen = sizeof(storage);
  sockaddr* const local_addr = reinterpret_cast<sockaddr*>(&storage);
  CHECK_EQ(uv_udp_getsockname(**socket, local_addr, &addrlen), 0);

  int remote_len;
  switch (addr->sa_family) {
    case AF_INET6:
      remote_len = sizeof(sockaddr_in6);
      break;
    case AF_INET:
      remote_len = sizeof(sockaddr_in);
      break;
    default:
      UNREACHABLE();
  }

  // TODO(@jasnell): Validate that this is doing the right thing
  auto path = ngtcp2_path{
      // Local Address
      {
        addrlen,
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&local_addr))
      },
      // Remote Address
      {
        remote_len,
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(addr))
      }
    };

  int err = ngtcp2_conn_server_new(&connection,
                                   dcid,
                                   &scid_,
                                   &path,
                                   version,
                                   &callbacks,
                                   &settings,
                                   this);
  if (err != 0) {
    Debug(this, "There was an error creating the session. Error %d", err);
    return err;
  }

  if (ocid) {
    ngtcp2_conn_set_retry_ocid(connection, ocid);
  }

  return 0;
}

QuicSocket::QuicSocket(Environment* env, Local<Object> wrap) :
    HandleWrap(env, wrap,
               reinterpret_cast<uv_handle_t*>(&handle_),
               AsyncWrap::PROVIDER_QUICSOCKET),
    config_(env) {
  MakeWeak();
  CHECK_EQ(uv_udp_init(env->event_loop(), &handle_), 0);
}

std::string QuicSocket::diagnostic_name() const {
  return std::string("QuicSocket");
}

void QuicSocket::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  new QuicSocket(env, args.This());
}

int QuicSocket::Bind(const char* address,
                     uint32_t port,
                     uint32_t flags,
                     int family) {
  Debug(this,
        "QUICSOCKET::Bind::[address = %s, port = %d, "
        "flags = %d, family = %d]", address, port, flags, family);
  char addr[sizeof(sockaddr_in6)];
  int err;
  switch (family) {
  case AF_INET:
    err = uv_ip4_addr(address, port, reinterpret_cast<sockaddr_in*>(&addr));
    break;
  case AF_INET6:
    err = uv_ip6_addr(address, port, reinterpret_cast<sockaddr_in6*>(&addr));
    break;
  default:
    CHECK(0 && "unexpected address family");
    ABORT();
  }

  if (err == 0) {
    err = uv_udp_bind(&handle_,
                      reinterpret_cast<const sockaddr*>(&addr),
                      flags);
  }

  if (err == 0) {

    int fd = UV_EBADF;
#if !defined(_WIN32)
    uv_fileno(reinterpret_cast<uv_handle_t*>(&handle_), &fd);
#endif
    Local<Value> arg = Integer::New(env()->isolate(), fd);

    Debug(this, "QUICSOCKET::Bind::Bound");
    MakeCallback(env()->quic_on_socket_ready_function(), 1, &arg);
  } else {
    Debug(this, "QUICSOCKET::Bind::Error[%d]", err);
    Local<Value> arg = Integer::New(env()->isolate(), err);
    MakeCallback(env()->quic_on_socket_error_function(), 1, &arg);
  }
  return err;
}

int QuicSocket::SetTTL(int ttl) {
  Debug(this, "Setting UDP TTL to %d", ttl);
  return uv_udp_set_ttl(&handle_, ttl);
}

int QuicSocket::SetMulticastTTL(int ttl) {
  Debug(this, "Setting UDP Multicast TTL to %d", ttl);
  return uv_udp_set_multicast_ttl(&handle_, ttl);
}

int QuicSocket::SetBroadcast(bool on) {
  Debug(this, "Turning UDP Broadcast %s", on ? "on" : "off");
  return uv_udp_set_broadcast(&handle_, on ? 1 : 0);
}

int QuicSocket::SetMulticastLoopback(bool on) {
  Debug(this, "Turning UDP Multicast Loopback %s", on ? "on" : "off");
  return uv_udp_set_multicast_loop(&handle_, on ? 1 : 0);
}

int QuicSocket::SetMulticastInterface(const char* iface) {
  Debug(this, "Setting the UDP Multicast Interface to %s", iface);
  return uv_udp_set_multicast_interface(&handle_, iface);
}

int QuicSocket::AddMembership(const char* address, const char* iface) {
  Debug(this, "Joining UDP group: address %s, iface %s", address, iface);
  return uv_udp_set_membership(&handle_, address, iface, UV_JOIN_GROUP);
}

int QuicSocket::DropMembership(const char* address, const char* iface) {
  Debug(this, "Leaving UDP group: address %s, iface %s", address, iface);
  return uv_udp_set_membership(&handle_, address, iface, UV_LEAVE_GROUP);
}

int QuicSocket::ReceiveStart() {
  int err = uv_udp_recv_start(&handle_, OnAlloc, OnRecv);
  if (err == UV_EALREADY)
    err = 0;
  return err;
}

int QuicSocket::ReceiveStop() {
  return uv_udp_recv_stop(&handle_);
}

void QuicSocket::OnAlloc(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  buf->base = node::Malloc(suggested_size);
  buf->len = suggested_size;
}

void QuicSocket::OnRecv(uv_udp_t* handle,
                        ssize_t nread,
                        const uv_buf_t* buf,
                        const struct sockaddr* addr,
                        unsigned int flags) {
  OnScopeLeave on_scope_leave([&]() {
    if (buf->base != nullptr)
      free(buf->base);
  });

  if (nread == 0)
    return;

  QuicSocket* socket = static_cast<QuicSocket*>(handle->data);
  CHECK_NE(socket, nullptr);

  if (nread < 0) {
    Debug(socket,
          "An error occurred while reading data from the UDP socket. Error %d",
          nread);
    return;
  }

  socket->Receive(nread, buf, addr, flags);
}

void QuicSocket::SendPendingData() {
  Debug(this, "Sending pending data");
  // TODO(@jasnell): Figure this bit out
}

int QuicServerSession::Receive(ngtcp2_pkt_hd* hd,
                               ssize_t nread,
                               const uint8_t* data,
                               const struct sockaddr* addr,
                               unsigned int flags) {
  return 0;
}

QuicSession* QuicSocket::ServerReceive(
    const std::string& dcid,
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  if (static_cast<size_t>(nread) < MIN_INITIAL_QUIC_PKT_SIZE) {
    Debug(this, "Ignoring initial packet that is too short");
    return nullptr;
  }

  int err;
  err = ngtcp2_accept(hd, data, nread);
  if (err == -1) {
    Debug(this, "Ignoring unexpected QUIC packet.");
    return nullptr;
  }
  if (err == 1) {
    Debug(this, "Unexpected version. Sending version negotiation.");
    // TODO(@jasnell): Send version negotiation
    return nullptr;
  }

  ngtcp2_cid ocid;
  ngtcp2_cid *pocid = nullptr;
  if (validate_addr_ && hd->type == NGTCP2_PKT_INITIAL) {
    Debug(this, "Stateless address validation.");
    // TODO(@jasnell): Implement this
    // if (hd.tokenlen == 0 ||
    //     verify_token(&ocid, &hd, &su.sa, addrlen) != 0) {
    //   send_retry(&hd, &su.sa, addrlen);
    //   return 0;
    // }
    // pocid = &ocid;
  }

  Debug(this, "Creating and initializing a new QuicServerSession");
  QuicServerSession* session = QuicServerSession::New(this);
  CHECK_NE(session, nullptr);
  err = session->Init(addr, &hd->scid, pocid, hd->version);
  if (err < 0) {
    // TODO(@jasnell): What to do here?
    Debug(this, "The QuicSession could not be initialized. Error %d", err);
    delete session;
    return nullptr;
  }

  auto scid = session->scid();
  std::string scid_str(scid->data, scid->data + scid->datalen);
  sessions_.emplace(scid_str, session);
  dcid_to_scid_.emplace(dcid, scid_str);

  // Notify the JavaScript side that a new server session has been created
  Local<Value> argv[2] = {
    this->object(),
    session->object()
  };
  MakeCallback(env()->quic_on_session_ready_function(), arraysize(argv), argv);

  return session;
}

void QuicSocket::Receive(ssize_t nread,
                        const uv_buf_t* buf,
                        const struct sockaddr* addr,
                        unsigned int flags) {
  Debug(this, "Receiving %d bytes from the UDP socket.", nread);
  ngtcp2_pkt_hd hd;
  int err;

  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf->base);

  // Parse the packet header...
  err = (buf->base[0] & 0x80) ?
      ngtcp2_pkt_decode_hd_long(&hd, data, nread) :
      ngtcp2_pkt_decode_hd_short(&hd, data, nread, NGTCP2_SV_SCIDLEN);

  if (err < 0) {
    // There's nothing we should really do here but return. The packet is
    // likely not a QUIC packet. If this is sent by an attacker, returning
    // and doing nothing is likely best but we also might want to keep some
    // stats or record of the failure.
    Debug(this,
          "Could not decode a QUIC packet header. Not a QUIC packet? Error %d",
          err);
    return;
  }

  // Extract the DCID
  std::string dcid(hd.dcid.data, hd.dcid.data + hd.dcid.datalen);
  Debug(this, "Received a QUIC packet for DCID %s", dcid.c_str());

  QuicSession* session = nullptr;

  // Identify the appropriate handler
  auto session_it = sessions_.find(dcid);
  if (session_it == std::end(sessions_)) {
    auto scid_it = dcid_to_scid_.find(dcid);
    if (scid_it == std::end(dcid_to_scid_)) {
      Debug(this, "There is no existing session for DCID %s", dcid.c_str());
      if (!server_listening_) {
        Debug(this, "Ignoring unhandled packet");
        return;
      }
      Debug(this, "Dispatching packet to ServerReceive");
      session = ServerReceive(dcid, &hd, nread, data, addr, flags);
      if (session == nullptr) {
        // TODO(@jasnell): Could not init the session for some reason
        // Handle appropriately
        return;
      }
    } else {
      session_it = sessions_.find((*scid_it).second);
      session = (*session_it).second;
      CHECK_NE(session_it, std::end(sessions_));
    }
  } else {
    session = (*session_it).second;
  }

  CHECK_NE(session, nullptr);
  // An appropriate handler was found! Dispatch the data
  Debug(this, "Dispatching packet to session for DCID %s", dcid.c_str());
  err = session->Receive(&hd, nread, data, addr, flags);
  if (err != 0) {
    Debug(this, "Handler processing was unsuccessful. Error %d", err);
    // TODO(@jasnell): Is removing the right thing to do here?
    // Probably not
    RemoveSession(dcid);
    return;
  }

  SendPendingData();
}

void QuicSocket::OnSend(uv_udp_send_t* req, int status) {}

void QuicSocket::SetTTL(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  int ttl;
  if (!args[0]->Int32Value(env->context()).To(&ttl))
    return;
  args.GetReturnValue().Set(socket->SetTTL(ttl));
}

void QuicSocket::SetMulticastTTL(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  int ttl;
  if (!args[0]->Int32Value(env->context()).To(&ttl))
    return;
  args.GetReturnValue().Set(socket->SetMulticastTTL(ttl));
}

void QuicSocket::SetBroadcast(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  args.GetReturnValue().Set(socket->SetBroadcast(args[0]->IsTrue()));
}

void QuicSocket::SetMulticastLoopback(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  args.GetReturnValue().Set(socket->SetMulticastLoopback(args[0]->IsTrue()));
}

void QuicSocket::SetMulticastInterface(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsString());

  Utf8Value iface(env->isolate(), args[0]);
  args.GetReturnValue().Set(socket->SetMulticastInterface(*iface));
}

void QuicSocket::AddMembership(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());

  Utf8Value address(env->isolate(), args[0]);
  Utf8Value iface(env->isolate(), args[1]);
  args.GetReturnValue().Set(socket->AddMembership(*address, *iface));
}

void QuicSocket::DropMembership(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());

  Utf8Value address(env->isolate(), args[0]);
  Utf8Value iface(env->isolate(), args[1]);
  args.GetReturnValue().Set(socket->DropMembership(*address, *iface));
}

void QuicSocket::Bind(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));

  CHECK_EQ(args.Length(), 4);

  node::Utf8Value address(args.GetIsolate(), args[1]);
  Local<Context> ctx = args.GetIsolate()->GetCurrentContext();
  int32_t type;
  uint32_t port, flags;
  if (!args[0]->Int32Value(ctx).To(&type) ||
      !args[2]->Uint32Value(ctx).To(&port) ||
      !args[3]->Uint32Value(ctx).To(&flags))
    return;
  CHECK(type == AF_INET || type == AF_INET6);

  args.GetReturnValue().Set(socket->Bind(*address, port, flags, type));
}

void QuicSocket::ReceiveStart(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  args.GetReturnValue().Set(socket->ReceiveStart());
}

void QuicSocket::ReceiveStop(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  args.GetReturnValue().Set(socket->ReceiveStop());
}

void QuicSocket::Destroy(const FunctionCallbackInfo<Value>& args) {
}

void QuicSocket::Listen(SecureContext* sc) {
  CHECK_NE(sc, nullptr);
  CHECK_EQ(server_secure_context_, nullptr);
  CHECK(!server_listening_);
  Debug(this, "Starting to listen");
  server_session_config_.reset(new QuicSessionConfig(env()));
  server_secure_context_ = sc;
  server_listening_ = true;
  ReceiveStart();
}

void QuicSocket::Listen(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK(args[0]->IsObject());  // Secure Context
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[0].As<Object>(),
                          args.GetReturnValue().Set(UV_EBADF));
  socket->Listen(sc);
}

namespace {
// Register the JavaScript callbacks the internal binding will use to report
// status and updates. This is called only once when the quic module is loaded.
void QuicSetCallbacks(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

#define SETFUNCTION(name, callback)                                           \
  do {                                                                        \
    Local<Value> fn;                                                          \
    CHECK(obj->Get(env->context(),                                            \
                   FIXED_ONE_BYTE_STRING(env->isolate(), name)).ToLocal(&fn));\
    CHECK(fn->IsFunction());                                                  \
    env->set_quic_on_##callback##_function(fn.As<Function>());                \
  } while (0)

  SETFUNCTION("onSocketReady", socket_ready);
  SETFUNCTION("onSocketClose", socket_close);
  SETFUNCTION("onSocketError", socket_error);
  SETFUNCTION("onSessionReady", session_ready);
  SETFUNCTION("onSessionClose", session_close);
  SETFUNCTION("onSessionError", session_error);
  SETFUNCTION("onStreamReady", stream_ready);
  SETFUNCTION("onStreamClose", stream_close);
  SETFUNCTION("onStreamError", stream_error);

#undef SETFUNCTION
}

void QuicProtocolVersion(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(NGTCP2_PROTO_VER_D17);
}

void QuicALPNVersion(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(OneByteString(env->isolate(), NGTCP2_ALPN_D17));
}

}  // namespace

void QuicSocket::Initialize(Environment* env,
                            Local<Object> target,
                            Local<Context> context) {
  Local<String> quic_socket_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QuicSocket");
  Local<FunctionTemplate> socket =
      env->NewFunctionTemplate(QuicSocket::New);
  socket->SetClassName(quic_socket_name);
  socket->InstanceTemplate()->SetInternalFieldCount(1);
  socket->InstanceTemplate()->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(socket, "addMembership", QuicSocket::AddMembership);
  env->SetProtoMethod(socket, "bind", QuicSocket::Bind);
  env->SetProtoMethod(socket, "destroy", QuicSocket::Destroy);
  env->SetProtoMethod(socket, "dropMembership", QuicSocket::DropMembership);
  env->SetProtoMethod(socket, "getsockname",
                      GetSockOrPeerName<QuicSocket, uv_udp_getsockname>);
  env->SetProtoMethod(socket, "listen", QuicSocket::Listen);
  env->SetProtoMethod(socket, "receiveStart", QuicSocket::ReceiveStart);
  env->SetProtoMethod(socket, "receiveStop", QuicSocket::ReceiveStop);
  env->SetProtoMethod(socket, "setTTL", QuicSocket::SetTTL);
  env->SetProtoMethod(socket, "setBroadcast", QuicSocket::SetBroadcast);
  env->SetProtoMethod(socket, "setMulticastInterface",
                      QuicSocket::SetMulticastInterface);
  env->SetProtoMethod(socket, "setMulticastTTL", QuicSocket::SetMulticastTTL);
  env->SetProtoMethod(socket, "setMulticastLoopback",
                      QuicSocket::SetMulticastLoopback);
  socket->Inherit(HandleWrap::GetConstructorTemplate(env));
  target->Set(context,
              quic_socket_name,
              socket->GetFunction(env->context()).ToLocalChecked()).FromJust();
}

void QuicServerSession::Initialize(Environment* env,
                                   Local<Object> target,
                                   Local<Context> context) {
  Local<String> quicserversession_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QuicServerSession");
  Local<FunctionTemplate> session = FunctionTemplate::New(env->isolate());
  session->SetClassName(quicserversession_name);
  session->Inherit(AsyncWrap::GetConstructorTemplate(env));
  Local<ObjectTemplate> sessiont = session->InstanceTemplate();
  sessiont->SetInternalFieldCount(1);
  sessiont->Set(env->owner_symbol(), Null(env->isolate()));
  env->set_quicserversession_constructor_template(sessiont);
  target->Set(context,
              quicserversession_name,
              session->GetFunction(env->context()).ToLocalChecked()).FromJust();
}

void InitializeQuic(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  std::unique_ptr<QuicState> state(new QuicState(isolate));
#define SET_STATE_TYPEDARRAY(name, field)             \
  target->Set(context,                                \
              FIXED_ONE_BYTE_STRING(isolate, (name)), \
              (field)).FromJust()
  SET_STATE_TYPEDARRAY(
    "socketConfig", state->quicsocketconfig_buffer.GetJSArray());
#undef SET_STATE_TYPEDARRAY

  env->set_quic_state(std::move(state));

  QuicSocket::Initialize(env, target, context);
  QuicServerSession::Initialize(env, target, context);

  env->SetMethod(target, "setCallbacks", QuicSetCallbacks);
  env->SetMethod(target, "protocolVersion", QuicProtocolVersion);
  env->SetMethod(target, "alpnVersion", QuicALPNVersion);

  Local<Object> constants = Object::New(env->isolate());
  NODE_DEFINE_CONSTANT(constants, AF_INET);
  NODE_DEFINE_CONSTANT(constants, AF_INET6);
  NODE_DEFINE_CONSTANT(constants, UV_UDP_REUSEADDR);
  NODE_DEFINE_CONSTANT(constants, UV_UDP_IPV6ONLY);
  NODE_DEFINE_CONSTANT(constants, UV_EBADF);
  NODE_DEFINE_CONSTANT(constants, DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL);
  target->Set(context,
              env->constants_string(),
              constants).FromJust();
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::InitializeQuic)
