#ifndef SRC_NODE_QUIC_H_
#define SRC_NODE_QUIC_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "ngtcp2/ngtcp2.h"
#include "node_internals.h"
#include "env.h"
#include "v8.h"
#include "uv.h"

#include <map>
#include <string>

namespace node {

using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;

// Forward declarations
namespace crypto {
class SecureContext;
}

namespace quic {

class QuicBuffer;
class QuicClientSession;
class QuicServerSession;
class QuicSession;
class QuicStream;
class QuicSocket;

class QuicSocketConfig {
 public:
  QuicSocketConfig() {}
  explicit QuicSocketConfig(Local<Object> options);
  virtual ~QuicSocketConfig() {}

 private:
};

// This will be a temporary holding buffer for the data accumulated
// from the QUIC session. It is possible, and in some cases likely,
// that data packets will be received out of order, so we need a buffer
// to hold the received data
class QuicBuffer {};

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

class QuicSession : public AsyncWrap {
 public:
  QuicSession(Environment* env,
              Local<Object> wrap,
              AsyncWrap::ProviderType provider,
              QuicSocket* socket);
  virtual ~QuicSession();

  QuicSocket* Socket() { return socket_; }
  const QuicSocket* Socket() const { return socket_; }

 protected:
  QuicStream* FindStream(uint32_t id);
  void AddStream(QuicStream* stream);
  void RemoveStream(uint32_t id);
  void RemoveStream(QuicStream* stream);

  ngtcp2_conn* Connection() { return connection_; }
  const ngtcp2_conn* Connection() const { return connection_; }

  const sockaddr* RemoteAddress() const { return remote_address_; }

 private:
  QuicSocket* socket_;
  ngtcp2_conn* connection_;
  const sockaddr* remote_address_; 
  std::map<uint32_t, std::unique_ptr<QuicStream>> streams_;
};

class QuicServerSession : public QuicSession {
 public:
  QuicServerSession(Environment* env,
                    Local<Object> wrap,
                    QuicSocket* socket);
  ~QuicServerSession();

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicServerSession)
  SET_SELF_SIZE(QuicServerSession)

 private:
};

class QuicClientSession : public QuicSession {
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
class QuicSocket : public AsyncWrap {
 public:
  QuicSocket(Environment* env,
             Local<Object> wrap,
             const QuicSocketConfig& config,
             crypto::SecureContext* sc);
  ~QuicSocket() {}

  void Bind() {};
  void Close() {};

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicSocket)
  SET_SELF_SIZE(QuicSocket)

  // JavaScript API
  static void New(const FunctionCallbackInfo<Value>& args);

 private:
  QuicSession* FindSession(std::string id);
  void AddSession(std::string id, QuicSession* session);

  // Likely do not need both... 
  void RemoveSession(std::string id);
  void RemoveSession(QuicSession* session);

  uv_udp_t* udp_handle_;
  crypto::SecureContext* sc_;
  std::map<std::string, std::unique_ptr<QuicSession>> sessions_;
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_H_
