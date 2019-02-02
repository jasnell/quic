#include "node.h"
#include "env.h"
#include "node_quic.h"

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

namespace {
void QuicProtocolVersion(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(NGTCP2_PROTO_VER_D17);
}

void QuicALPNVersion(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(OneByteString(env->isolate(), NGTCP2_ALPN_D17));
}
}  // namespace

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  env->SetMethod(target, "protocolVersion", QuicProtocolVersion);
  env->SetMethod(target, "alpnVersion", QuicALPNVersion);
}

}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
