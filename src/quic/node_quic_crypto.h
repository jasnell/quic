#ifndef SRC_NODE_QUIC_CRYPTO_H_
#define SRC_NODE_QUIC_CRYPTO_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_crypto.h"
#include "node_quic_util.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

namespace node {

namespace quic {

// Forward declaration
class QuicSession;

#define NGTCP2_ERR(V) (V != 0)
#define NGTCP2_OK(V) (V == 0)

// Called by QuicSession::OnSecrets when openssl
// delivers crypto secrets to the QuicSession.
// This will derive and install the keys and iv
// for TX and RX at the specified level, and
// generates the QUIC specific keylog events.
bool SetCryptoSecrets(
    QuicSession* session,
    ngtcp2_crypto_level level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen);

// Called by QuicInitSecureContext to initialize the
// given SecureContext with the defaults for the given
// QUIC side (client or server).
void InitializeSecureContext(
    crypto::SecureContext* sc,
    ngtcp2_crypto_side side);

// Called in the QuicSession::InitServer and
// QuicSession::InitClient to configure the
// appropriate settings for the SSL* associated
// with the session.
void InitializeTLS(QuicSession* session);

// Called when the client QuicSession is created and
// when the server QuicSession first receives the
// client hello.
bool DeriveAndInstallInitialKey(
    QuicSession* session,
    const ngtcp2_cid* dcid);

// Generates a stateless reset token using HKDF with the
// cid and token secret as input. The token secret is
// either provided by user code when a QuicSocket is
// created or is generated randomly.
//
// QUIC leaves the generation of stateless session tokens
// up to the implementation to figure out. The idea, however,
// is that it ought to be possible to generate a stateless
// reset token reliably even when all state for a connection
// has been lost. We use the cid as it's the only reliably
// consistent bit of data we have when a session is destroyed.
bool GenerateResetToken(
    uint8_t* token,
    const uint8_t* secret,
    const ngtcp2_cid* cid);

// The Retry Token is an encrypted token that is sent to the client
// by the server as part of the path validation flow. The plaintext
// format within the token is opaque and only meaningful the server.
// We can structure it any way we want. It needs to:
//   * be hard to guess
//   * be time limited
//   * be specific to the client address
//   * be specific to the original cid
//   * contain random data.
bool GenerateRetryToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    const uint8_t* token_secret);

// Verifies the validity of a retry token. Returns true if the
// token is not valid, false otherwise.
bool InvalidRetryToken(
    const uint8_t* token,
    size_t tokenlen,
    const sockaddr* addr,
    ngtcp2_cid* ocid,
    const uint8_t* token_secret,
    uint64_t verification_expiration);

int VerifyHostnameIdentity(SSL* ssl, const char* hostname);
int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames);

// Get the ALPN protocol identifier that was negotiated for the session
v8::Local<v8::Value> GetALPNProtocol(QuicSession* session);

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_CRYPTO_H_
