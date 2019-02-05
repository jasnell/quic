#include "node.h"
#include "env.h"
#include "node_quic.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"

namespace node {

using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace quic {

QuicSocketConfig::QuicSocketConfig(Local<Object> options) {}

QuicSocket::QuicSocket(Environment* env,
                       Local<Object> wrap,
                       const QuicSocketConfig& config,
                       crypto::SecureContext* sc) :
    AsyncWrap(env, wrap, AsyncWrap::PROVIDER_QUICSOCKET),
    sc_(sc) {
  MakeWeak();
}

void QuicSocket::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  CHECK(args[0]->IsObject());
  Local<Object> options = args[0].As<Object>();
  QuicSocketConfig config(options);
  QuicSocket* socket = new QuicSocket(env, args.This(), config, nullptr);
  socket->get_async_id();  // avoid compiler warning
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

void QuicSocketBind(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsObject());
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args[0].As<Object>());
  socket->Bind();
}

void QuicSocketClose(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsObject());
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args[0].As<Object>());
  socket->Close();
}

}  // namespace

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  Local<String> quic_socket_name = FIXED_ONE_BYTE_STRING(isolate, "QuicSocket");
  Local<FunctionTemplate> socket =
      env->NewFunctionTemplate(QuicSocket::New);
  socket->SetClassName(quic_socket_name);
  socket->InstanceTemplate()->SetInternalFieldCount(1);
  socket->InstanceTemplate()->Set(env->owner_symbol(), Null(env->isolate()));
  socket->Inherit(AsyncWrap::GetConstructorTemplate(env));
  target->Set(context,
              quic_socket_name,
              socket->GetFunction(env->context()).ToLocalChecked()).FromJust();

  env->SetMethod(target, "setCallbacks", QuicSetCallbacks);
  env->SetMethod(target, "socketBind", QuicSocketBind);
  env->SetMethod(target, "socketClose", QuicSocketClose);
  env->SetMethod(target, "protocolVersion", QuicProtocolVersion);
  env->SetMethod(target, "alpnVersion", QuicALPNVersion);
}

}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
