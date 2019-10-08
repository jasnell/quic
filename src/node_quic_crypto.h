#ifndef SRC_NODE_QUIC_CRYPTO_H_
#define SRC_NODE_QUIC_CRYPTO_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_crypto.h"
#include "node_quic_util.h"
#include "node_url.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iterator>
#include <numeric>
#include <unordered_map>
#include <string>
#include <sstream>

namespace node {

using crypto::EntropySource;

namespace quic {

// Forward declaration
class QuicSession;

#define NGTCP2_ERR(V) (V != 0)
#define NGTCP2_OK(V) (V == 0)

#define NGTCP2_CRYPTO_SECRETLEN 64
#define NGTCP2_CRYPTO_KEYLEN 64
#define NGTCP2_CRYPTO_IVLEN 64
#define NGTCP2_CRYPTO_TOKEN_SECRETLEN 32
#define NGTCP2_CRYPTO_TOKEN_KEYLEN 32
#define NGTCP2_CRYPTO_TOKEN_IVLEN 32

using InitialSecret = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN>;
using InitialKey = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN>;
using InitialIV = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN>;
using SessionSecret = std::array<uint8_t, NGTCP2_CRYPTO_SECRETLEN>;
using SessionKey = std::array<uint8_t, NGTCP2_CRYPTO_KEYLEN>;
using SessionIV = std::array<uint8_t, NGTCP2_CRYPTO_IVLEN>;
using TokenSecret = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_SECRETLEN>;
using TokenKey = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_KEYLEN>;
using TokenIV = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_IVLEN>;

constexpr char QUIC_CLIENT_EARLY_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_TRAFFIC_SECRET_0[] = "QUIC_CLIENT_TRAFFIC_SECRET_0";
constexpr char QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_SERVER_TRAFFIC_SECRET_0[] = "QUIC_SERVER_TRAFFIC_SECRET_0";

void LogSecret(SSL* ssl,
    const char* name,
    const unsigned char* secret,
    size_t secretlen);

const ngtcp2_crypto_ctx* GetCryptoContext(ngtcp2_conn* conn, SSL* ssl);
const ngtcp2_crypto_ctx* GetInitialCryptoContext(ngtcp2_conn* conn);

void SetQuicMethod(SSL_CTX* ctx);
void InitializeTLS(QuicSession* session, SSL* ssl);

int CertCB(SSL* ssl, void* arg);

v8::Local<v8::Array> GetClientHelloCiphers(
    Environment* env,
    SSL* ssl);

const char* GetClientHelloServerName(SSL* ssl);

const char* GetClientHelloALPN(SSL* ssl);

int UseSNIContext(SSL* ssl, crypto::SecureContext* context);

int Client_Hello_CB(
    SSL* ssl,
    int* tls_alert,
    void* arg);

int ALPN_Select_Proto_CB(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg);

int TLS_Status_Callback(SSL* ssl, void* arg);

bool GenerateRetryToken(
    uint8_t* token,
    size_t& tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret);

bool InvalidRetryToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret,
    uint64_t verification_expiration);

int VerifyPeerCertificate(SSL* ssl);

std::string GetCertificateCN(X509* cert);

std::unordered_multimap<std::string, std::string> GetCertificateAltNames(
    X509* cert);

bool SplitHostname(
    const char* hostname,
    std::vector<std::string>* parts,
    const char delim = '.');


bool CheckCertNames(
    const std::vector<std::string>& host_parts,
    const std::string& name,
    bool use_wildcard = true);

int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames);

int VerifyHostnameIdentity(SSL* ssl, const char* hostname);

const char* X509ErrorCode(int err);

// Get the SNI hostname requested by the client for the session
v8::Local<v8::Value> GetServerName(
    Environment* env,
    SSL* ssl,
    const char* host_name);

// Get the ALPN protocol identifier that was negotiated for the session
v8::Local<v8::Value> GetALPNProtocol(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetCipherName(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetCipherVersion(Environment* env, SSL* ssl);

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_CRYPTO_H_
