#ifndef SRC_NODE_QUIC_CRYPTO_INL_H_
#define SRC_NODE_QUIC_CRYPTO_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include <array>
#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <functional>
#include <utility>
#include <type_traits>

namespace node {
namespace quic {
// NOTE(@jasnell): The majority of this is adapted directly from the
// example code in https://github.com/ngtcp2/ngtcp2. It can likely
// use a refactor to be more Node-ish

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T> struct Defer {
  Defer(F &&f, T &&... t)
      : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = typename std::result_of<typename std::decay<F>::type(
      typename std::decay<T>::type...)>::type;
  std::function<ResultType()> f;
};

template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&... t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

struct CryptoContext {
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  std::array<uint8_t, 64> tx_secret, rx_secret;
  size_t secretlen;
};

inline int HKDF_Expand(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* info,
    size_t infolen,
    const CryptoContext& ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr)
    return -1;

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1)
    return -1;

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
    return -1;

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1)
    return -1;

  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1)
    return -1;

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    return -1;

  return 0;
}

inline int HKDF_Extract(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* salt,
    size_t saltlen,
    const CryptoContext& ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr)
    return -1;

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1)
    return -1;

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1)
    return -1;

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1)
    return -1;

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    return -1;

  return 0;
}

inline int HKDF_Expand_Label(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* label,
    size_t labellen,
    const CryptoContext& ctx) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = arraysize(LABEL) + labellen;
  p = std::copy_n(LABEL, arraysize(LABEL), p);
  p = std::copy_n(label, labellen, p);
  *p++ = 0;

  return HKDF_Expand(dest, destlen,
                     secret, secretlen,
                     info.data(),
                     p - std::begin(info),
                     ctx);
}


inline void prf_sha256(CryptoContext& ctx) { ctx.prf = EVP_sha256(); }

inline void aead_aes_128_gcm(CryptoContext& ctx) {
  ctx.aead = EVP_aes_128_gcm();
  ctx.hp = EVP_aes_128_ctr();
}

inline size_t aead_key_length(const CryptoContext &ctx) {
  return EVP_CIPHER_key_length(ctx.aead);
}

inline size_t aead_nonce_length(const CryptoContext &ctx) {
  return EVP_CIPHER_iv_length(ctx.aead);
}

inline int DeriveInitialSecret(
    uint8_t* dest,
    size_t destlen,
    const ngtcp2_cid* secret,
    const uint8_t* salt,
    size_t saltlen) {
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Extract(dest, destlen,
                      secret->data, secret->datalen,
                      salt, saltlen, ctx);
}

inline int DeriveServerInitialSecret(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen) {
  static constexpr uint8_t LABEL[] = "server in";
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Expand_Label(dest, destlen,
                           secret, secretlen,
                           LABEL,
                           arraysize(LABEL), ctx);
}

inline int DeriveClientInitialSecret(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen) {
  static constexpr uint8_t LABEL[] = "client in";
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Expand_Label(dest, destlen,
                           secret, secretlen,
                           LABEL,
                           arraysize(LABEL), ctx);
}

inline ssize_t DerivePacketProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext &ctx) {
  static constexpr uint8_t LABEL[] = "quic key";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  if (HKDF_Expand_Label(dest, keylen,
                        secret, secretlen,
                        LABEL, arraysize(LABEL),
                        ctx) != 0) {
    return -1;
  }

  return keylen;
}

inline ssize_t DerivePacketProtectionIV(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext& ctx) {
  static constexpr uint8_t LABEL[] = "quic iv";

  size_t ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(ctx));
  if (ivlen > destlen)
    return -1;

  if (HKDF_Expand_Label(dest, ivlen,
                        secret, secretlen,
                        LABEL, arraysize(LABEL),
                        ctx) != 0) {
    return -1;
  }

  return ivlen;
}

inline ssize_t DeriveHeaderProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext &ctx) {
  static constexpr uint8_t LABEL[] = "quic hp";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  if(HKDF_Expand_Label(dest, keylen,
                       secret, secretlen,
                       LABEL, arraysize(LABEL),
                       ctx) != 0) {
    return -1;
  }

  return keylen;
}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_CRYPTO_INL_H_
