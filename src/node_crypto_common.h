#ifndef SRC_NODE_CRYPTO_COMMON_H_
#define SRC_NODE_CRYPTO_COMMON_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "env.h"
#include "node_crypto.h"
#include "v8.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string>
#include <unordered_map>

namespace node {
namespace crypto {

void LogSecret(
    SSL* ssl,
    const char* name,
    const unsigned char* secret,
    size_t secretlen);

void SetALPN(SSL* ssl, const std::string& alpn);

std::string GetSSLOCSPResponse(SSL* ssl);

bool SetTLSSession(SSL* ssl, const unsigned char* buf, size_t length);

std::unordered_multimap<std::string, std::string> GetCertificateAltNames(
    X509* cert);

std::string GetCertificateCN(X509* cert);

int VerifyPeerCertificate(SSL* ssl);

int UseSNIContext(SSL* ssl, SecureContext* context);

const char* GetClientHelloServerName(SSL* ssl);

bool SetGroups(SecureContext* sc, const char* groups);

const char* X509ErrorCode(int err);

v8::Local<v8::Value> GetCertificate(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetCipherName(
    Environment* env,
    SSL* ssl);

v8::Local<v8::Value> GetCipherVersion(
    Environment* env,
    SSL* ssl);

v8::Local<v8::Value> GetEphemeralKey(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetPeerCertificate(
    Environment* env,
    SSL* ssl,
    bool abbreviated = false,
    bool is_server = false);

}  // namespace crypto
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_CRYPTO_COMMON_H_
