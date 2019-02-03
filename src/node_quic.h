#ifndef SRC_NODE_QUIC_H_
#define SRC_NODE_QUIC_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "node_crypto.h"  // SSLWrap
#include "ngtcp2/ngtcp2.h"
#include "node_internals.h"
#include "env.h"
#include "handle_wrap.h"
#include "v8.h"
#include "uv.h"

#include <openssl/ssl.h>

#include <map>
#include <random>
#include <string>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;

// Forward declarations
namespace crypto {
class SecureContext;
}

namespace {
constexpr size_t MIN_INITIAL_QUIC_PKT_SIZE = 1200;
constexpr size_t NGTCP2_SV_SCIDLEN = 18;

std::mt19937 make_mt19937() {
  std::random_device rd;
  return std::mt19937(rd());
}
auto randgen = make_mt19937();

constexpr unsigned long long operator"" _k(unsigned long long k) {
  return k * 1024;
}

constexpr unsigned long long operator"" _m(unsigned long long m) {
  return m * 1024 * 1024;
}

constexpr unsigned long long operator"" _g(unsigned long long g) {
  return g * 1024 * 1024 * 1024;
}

#define DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL 256_k

}  // namespace

class QuicClientSession;
class QuicServerSession;
class QuicStream;
class QuicSocket;
class QuicBuffer;

class QuicSocketConfig {
 public:
  explicit QuicSocketConfig(Environment* env);
  virtual ~QuicSocketConfig() {}

 private:
};

#define QUICSESSION_CONFIG(V)                                                 \
  V(MAX_STREAM_DATA_BIDI_LOCAL, max_stream_data_bidi_local, 256_k)            \
  V(MAX_STREAM_DATA_BIDI_REMOTE, max_stream_data_bidi_remote, 256_k)          \
  V(MAX_STREAM_DATA_UNI, max_stream_data_uni, 256_k)                          \
  V(MAX_DATA, max_data, 1_m)                                                  \
  V(MAX_STREAMS_BIDI, max_streams_bidi, 100)                                  \
  V(MAX_STREAMS_UNI, max_streams_uni, 0)                                      \
  V(IDLE_TIMEOUT, idle_timeout, 10 * 1000)                                    \
  V(MAX_PACKET_SIZE, max_packet_size, NGTCP2_MAX_PKT_SIZE)

class QuicSessionConfig {
 public:
  explicit QuicSessionConfig(Environment* env);
  ~QuicSessionConfig() {}

  void ToSettings(ngtcp2_settings* settings);

#define V(idx, name, def)                                                     \
  void set_##name(uint64_t value) { name##_ = value; }                        \
  uint64_t name() const { return name##_; }
  QUICSESSION_CONFIG(V)
#undef V

 private:
#define V(idx, name, def) uint64_t name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
};

// This will be a temporary holding buffer for the data accumulated
// from the QUIC session. It is possible, and in some cases likely,
// that data packets will be received out of order, so we need a buffer
// to hold the received data
class QuicBuffer {};

class QuicSession {
 public:
  static const int kInitialClientBufferLength = 4096;

  explicit QuicSession(QuicSocket* socket);
  virtual ~QuicSession() {}

  QuicSocket* Socket() { return socket_; }
  const QuicSocket* Socket() const { return socket_; }

  virtual int Receive(ngtcp2_pkt_hd* hd,
                      ssize_t nread,
                      const uint8_t* data,
                      const struct sockaddr* addr,
                      unsigned int flags) = 0;

  // ngtcp2 callbacks
  static int recv_client_initial(
    ngtcp2_conn* conn,
    const ngtcp2_cid *dcid,
    void* user_data);
  static int recv_crypto_data(
    ngtcp2_conn* conn,
    uint64_t offset,
    const uint8_t *data,
    size_t datalen,
    void* user_data);
  static int handshake_completed(
    ngtcp2_conn* conn,
    void* user_data);
  static ssize_t do_hs_encrypt(
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
    void* user_data);
  static ssize_t do_hs_decrypt(
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
    void* user_data);
  static ssize_t do_encrypt(
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
    void* user_data);
  static ssize_t do_decrypt(
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
    void* user_data);
  static ssize_t do_in_hp_mask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data);
  static ssize_t do_hp_mask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data);
  static int recv_stream_data(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data);
  static int acked_crypto_offset(
    ngtcp2_conn* conn,
    uint64_t offset,
    size_t datalen,
    void* user_data);
  static int acked_stream_data_offset(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    uint64_t offset,
    size_t datalen,
    void* user_data,
    void* stream_user_data);
  static int stream_close(
    ngtcp2_conn* conn,
    uint64_t stream_id,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data);
  static int rand(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    ngtcp2_rand_ctx ctx,
    void* user_data);
  static int get_new_connection_id(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data);
  static int remove_connection_id(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data);
  static int update_key(
    ngtcp2_conn* conn,
    void* user_data);
  static int path_validation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data);

 protected:
  // QuicStream* FindStream(uint32_t id);
  // void AddStream(QuicStream* stream);
  // void RemoveStream(uint32_t id);
  // void RemoveStream(QuicStream* stream);

  ngtcp2_conn* Connection() const { return connection_; }
  ngtcp2_conn* operator*() const { return connection_; }

  void SetRemoteAddress(const sockaddr* addr);

  const sockaddr* RemoteAddress() const { return remote_address_; }

  void InitTLS(SSL* ssl, bool is_server);

 private:
  QuicSocket* socket_;
  ngtcp2_conn* connection_;
  const sockaddr* remote_address_;
  size_t max_pktlen_;

  BIO* enc_in_ = nullptr;   // StreamListener fills this for SSL_read().
  BIO* enc_out_ = nullptr;  // SSL_write()/handshake fills this for EncOut().

  std::map<uint32_t, std::unique_ptr<QuicStream>> streams_;
};

class QuicStream : public AsyncWrap {
 public:
  QuicStream(Environment* env,
             Local<Object> wrap,
             QuicSession* session);
  ~QuicStream();

  QuicSession* Session() { return session_; }
  const QuicSession* Session() const { return session_; }

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicStream)
  SET_SELF_SIZE(QuicStream)

 private:
  QuicSession* session_;
};

class QuicServerSession : public AsyncWrap,
                          public QuicSession,
                          public crypto::SSLWrap<QuicServerSession> {
 public:
  static QuicServerSession* New(QuicSocket* socket);

  ~QuicServerSession() override {};

  int Init(const struct sockaddr* addr,
           const ngtcp2_cid *dcid,
           const ngtcp2_cid *ocid,
           uint32_t version);

  int Receive(ngtcp2_pkt_hd* hd,
              ssize_t nread,
              const uint8_t* data,
              const struct sockaddr* addr,
              unsigned int flags) override;

  const ngtcp2_cid* scid() const { return &scid_; }

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicServerSession)
  SET_SELF_SIZE(QuicServerSession)

  static void Initialize(Environment* env,
                         Local<Object> target,
                         Local<Context> context);

  // Called by the done() callback of the 'newSession' event.
  void NewSessionDoneCb();

 private:
  QuicServerSession(QuicSocket* socket, Local<Object> wrap);

  ngtcp2_cid scid_;
};

class QuicClientSession : public AsyncWrap,
                          public QuicSession,
                          public crypto::SSLWrap<QuicServerSession> {
 public:
  QuicClientSession(Environment* env,
                    Local<Object> wrap,
                    QuicSocket* socket);
  ~QuicClientSession();

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicClientSession)
  SET_SELF_SIZE(QuicClientSession)

 private:
};

// The QuicSocket wraps the uv_udp_t handle, manages the data flow between
// the uv_udp_t handle and ngtcp2, and the collection of QuicSessions associated
// with the socket.
class QuicSocket : public HandleWrap {
 public:
  QuicSocket(Environment* env, Local<Object> wrap);

  ~QuicSocket() override {
    // Safety checks
    CHECK(sessions_.empty());
  }

  crypto::SecureContext* GetServerSecureContext() {
    return server_secure_context_;
  }

  void SetServerSessionSettings(ngtcp2_settings* settings) {
    auto config = server_session_config_.get();
    CHECK_NE(config, nullptr);
    config->ToSettings(settings);
  }

  int Bind(const char* address, uint32_t port, uint32_t flags, int family);
  int SetTTL(int ttl);
  int SetBroadcast(bool on);
  int SetMulticastTTL(int ttl);
  int SetMulticastLoopback(bool on);
  int SetMulticastInterface(const char* iface);
  int AddMembership(const char* address, const char* iface);
  int DropMembership(const char* address, const char* iface);
  int ReceiveStart();
  int ReceiveStop();
  void SendPendingData();
  void Listen(crypto::SecureContext* context);
  bool Listening() { return server_listening_; }

  void AddSession(std::string dcid, QuicSession* session) {
    sessions_.emplace(dcid, session);
  }

  void RemoveSession(std::string dcid){
    sessions_.erase(dcid);
  }

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicSocket)
  SET_SELF_SIZE(QuicSocket)

  // JavaScript API
  static void Initialize(Environment* env,
                         Local<Object> target,
                         Local<Context> context);
  static void New(const FunctionCallbackInfo<Value>& args);

  static void AddMembership(const FunctionCallbackInfo<Value>& args);
  static void Bind(const FunctionCallbackInfo<Value>& args);
  static void Destroy(const FunctionCallbackInfo<Value>& args);
  static void DropMembership(const FunctionCallbackInfo<Value>& args);
  static void Listen(const FunctionCallbackInfo<Value>& args);
  static void ReceiveStart(const FunctionCallbackInfo<Value>& args);
  static void ReceiveStop(const FunctionCallbackInfo<Value>& args);
  static void SetBroadcast(const FunctionCallbackInfo<Value>& args);
  static void SetMulticastInterface(const FunctionCallbackInfo<Value>& args);
  static void SetMulticastLoopback(const FunctionCallbackInfo<Value>& args);
  static void SetMulticastTTL(const FunctionCallbackInfo<Value>& args);
  static void SetTTL(const FunctionCallbackInfo<Value>& args);

  std::string diagnostic_name() const override;

  void SetLocalAddress(ngtcp2_path* path);

  const uv_udp_t* operator*() const { return &handle_; }

 private:
  QuicSocketConfig config_;
  std::unique_ptr<QuicSessionConfig> server_session_config_;
  uv_udp_t handle_;
  bool server_listening_ = false;
  bool validate_addr_ = false;
  crypto::SecureContext* server_secure_context_ = nullptr;

  // TODO(@jasnell): Can this be unique_ptr ?
  std::map<std::string, QuicSession*> sessions_;
  std::map<std::string, std::string> dcid_to_scid_;

  typedef uv_udp_t HandleType;

  void Receive(ssize_t nread,
               const uv_buf_t* buf,
               const struct sockaddr* addr,
               unsigned int flags);
  QuicSession* ServerReceive(
      const std::string& dcid,
      ngtcp2_pkt_hd* hd,
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags);

  template <typename T,
            int (*F)(const typename T::HandleType*, sockaddr*, int*)>
  friend void GetSockOrPeerName(const v8::FunctionCallbackInfo<v8::Value>&);

  static void OnAlloc(uv_handle_t* handle,
                      size_t suggested_size,
                      uv_buf_t* buf);
  static void OnSend(uv_udp_send_t* req, int status);
  static void OnRecv(uv_udp_t* handle,
                     ssize_t nread,
                     const uv_buf_t* buf,
                     const struct sockaddr* addr,
                     unsigned int flags);
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_H_
