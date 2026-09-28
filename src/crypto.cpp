#include "internal.hpp"
#include <algorithm>
#include <limits>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace ecl {
namespace {
using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
void require(int result) {
    if (result != 1) throw Error("OpenSSL operation failed");
}
int checked_size(std::size_t n) {
    if (n > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw Error("crypto input exceeds supported size");
    return static_cast<int>(n);
}
Cipher cipher() {
    Cipher result(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!result) throw Error("cannot allocate cipher context");
    return result;
}
void check_key_nonce(View key, View nonce) {
    if (key.size() != 32 || nonce.size() != 12) throw Error("invalid AES-256-GCM key/nonce length");
}
}

Bytes random_bytes(std::size_t size) {
    Bytes output(size);
    if (size) require(RAND_bytes(output.data(), checked_size(size)));
    return output;
}
Bytes sha256(View data) {
    Bytes result(32);
    unsigned int length = 0;
    require(EVP_Digest(data.data(), data.size(), result.data(), &length, EVP_sha256(), nullptr));
    if (length != result.size()) throw Error("unexpected SHA-256 length");
    return result;
}
std::string hex(View data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (auto b : data) { result += digits[b >> 4]; result += digits[b & 15]; }
    return result;
}

namespace detail {
Bytes concat(std::initializer_list<View> parts) {
    Bytes result;
    for (auto part : parts) {
        if (part.size() > result.max_size() - result.size()) throw Error("record size overflow");
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}
void cleanse(Bytes& bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
}
bool secure_equal(View a, View b) {
    return a.size() == b.size() && (a.empty() || CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0);
}
Bytes aes_gcm_encrypt(View key, View nonce, View plain, View aad) {
    check_key_nonce(key, nonce);
    auto ctx = cipher();
    require(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()));
    int n = 0, tail = 0;
    require(EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), checked_size(aad.size())));
    if (plain.size() > Bytes().max_size() - 16) throw Error("input is too large to encode");
    Bytes result(plain.size() + 16);
    std::size_t processed = 0;
    while (processed < plain.size()) {
        const auto chunk = static_cast<int>(std::min<std::size_t>(plain.size() - processed, 1U << 30));
        require(EVP_EncryptUpdate(ctx.get(), result.data() + processed, &n, plain.data() + processed, chunk));
        if (n != chunk) throw Error("unexpected GCM output length");
        processed += static_cast<std::size_t>(n);
    }
    require(EVP_EncryptFinal_ex(ctx.get(), result.data() + processed, &tail));
    if (tail != 0) throw Error("unexpected GCM final length");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, result.data() + plain.size()));
    return result;
}
Bytes aes_gcm_decrypt(View key, View nonce, View cipher_tag, View aad) {
    check_key_nonce(key, nonce);
    if (cipher_tag.size() < 16) throw AuthenticationError("truncated authentication tag");
    const auto length = cipher_tag.size() - 16;
    if (length > Bytes().max_size() - 16) throw Error("input is too large to decode");
    auto ctx = cipher();
    require(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()));
    int n = 0, tail = 0;
    require(EVP_DecryptUpdate(ctx.get(), nullptr, &n, aad.data(), checked_size(aad.size())));
    Bytes result(length + 16);
    std::size_t processed = 0;
    while (processed < length) {
        const auto chunk = static_cast<int>(std::min<std::size_t>(length - processed, 1U << 30));
        require(EVP_DecryptUpdate(ctx.get(), result.data() + processed, &n, cipher_tag.data() + processed, chunk));
        if (n != chunk) throw AuthenticationError("unexpected GCM plaintext length");
        processed += static_cast<std::size_t>(n);
    }
    std::array<Byte, 16> tag{};
    std::copy(cipher_tag.end() - 16, cipher_tag.end(), tag.begin());
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()));
    if (EVP_DecryptFinal_ex(ctx.get(), result.data() + processed, &tail) != 1) {
        OPENSSL_cleanse(result.data(), result.size());
        throw AuthenticationError("authentication failed: wrong key, damaged file, or wrong metadata");
    }
    if (tail != 0) throw AuthenticationError("unexpected GCM final length");
    result.resize(processed);
    return result;
}
Bytes aes_gcm_siv_encrypt(View key, View nonce, View plain, View aad) {
    check_key_nonce(key, nonce);
    const auto length = checked_size(plain.size());
    const auto aad_length = checked_size(aad.size());
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> algorithm(
        EVP_CIPHER_fetch(nullptr, "AES-256-GCM-SIV", nullptr), EVP_CIPHER_free);
    if (!algorithm) throw Error("OpenSSL provider does not support AES-256-GCM-SIV");
    auto ctx = cipher();
    require(EVP_EncryptInit_ex2(ctx.get(), algorithm.get(), key.data(), nonce.data(), nullptr));
    int n = 0, tail = 0;
    require(EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), aad_length));
    Bytes result(plain.size() + 16);
    const Byte empty = 0;
    // SIV requires exactly one payload update per context. Callers split large records.
    require(EVP_EncryptUpdate(ctx.get(), result.data(), &n,
                             plain.empty() ? &empty : plain.data(), length));
    if (n != length) throw Error("unexpected GCM-SIV ciphertext length");
    require(EVP_EncryptFinal_ex(ctx.get(), result.data() + n, &tail));
    if (tail != 0) throw Error("unexpected GCM-SIV final length");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, result.data() + n));
    return result;
}
Bytes aes_gcm_siv_decrypt(View key, View nonce, View cipher_tag, View aad) {
    check_key_nonce(key, nonce);
    if (cipher_tag.size() < 16) throw AuthenticationError("truncated GCM-SIV tag");
    const auto length = checked_size(cipher_tag.size() - 16);
    const auto aad_length = checked_size(aad.size());
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> algorithm(
        EVP_CIPHER_fetch(nullptr, "AES-256-GCM-SIV", nullptr), EVP_CIPHER_free);
    if (!algorithm) throw Error("OpenSSL provider does not support AES-256-GCM-SIV");
    auto ctx = cipher();
    require(EVP_DecryptInit_ex2(ctx.get(), algorithm.get(), key.data(), nonce.data(), nullptr));
    std::array<Byte, 16> tag{};
    std::copy(cipher_tag.end() - 16, cipher_tag.end(), tag.begin());
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data()));
    int n = 0, tail = 0;
    require(EVP_DecryptUpdate(ctx.get(), nullptr, &n, aad.data(), aad_length));
    Bytes result(static_cast<std::size_t>(length) + 16);
    if (EVP_DecryptUpdate(ctx.get(), result.data(), &n, cipher_tag.data(), length) != 1 ||
        n != length || EVP_DecryptFinal_ex(ctx.get(), result.data() + n, &tail) != 1 || tail != 0) {
        cleanse(result);
        throw AuthenticationError("authentication failed: wrong key or damaged record");
    }
    result.resize(static_cast<std::size_t>(length));
    return result;
}
Bytes privacy_key(View key, View salt, const std::string& purpose) {
    if (key.size() != 32 || salt.size() != 32) throw Error("invalid privacy key or salt length");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) throw Error("cannot allocate HKDF context");
    const std::string info = "0xBOF/ECLAB002/" + purpose;
    require(EVP_PKEY_derive_init(ctx.get()));
    require(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()));
    require(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), checked_size(salt.size())));
    require(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), checked_size(key.size())));
    require(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), reinterpret_cast<const Byte*>(info.data()), checked_size(info.size())));
    Bytes output(32);
    auto length = output.size();
    if (EVP_PKEY_derive(ctx.get(), output.data(), &length) != 1 || length != output.size()) {
        cleanse(output);
        throw Error("HKDF key derivation failed");
    }
    return output;
}
Bytes hmac_sha256(View key, std::initializer_list<View> parts) {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> algorithm(
        EVP_MAC_fetch(nullptr, "HMAC", nullptr), EVP_MAC_free);
    if (!algorithm) throw Error("OpenSSL provider does not support HMAC");
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(
        EVP_MAC_CTX_new(algorithm.get()), EVP_MAC_CTX_free);
    if (!ctx) throw Error("cannot allocate HMAC context");
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                           OSSL_PARAM_construct_end()};
    require(EVP_MAC_init(ctx.get(), key.data(), key.size(), params));
    for (const auto part : parts) if (!part.empty()) require(EVP_MAC_update(ctx.get(), part.data(), part.size()));
    Bytes output(32);
    std::size_t length = 0;
    require(EVP_MAC_final(ctx.get(), output.data(), &length, output.size()));
    if (length != output.size()) throw Error("unexpected HMAC length");
    return output;
}
Bytes aes_ctr_stream(View key, std::size_t length) {
    if (key.size() != 32) throw Error("invalid AES-256 key length");
    auto ctx = cipher();
    std::array<Byte, 16> iv{};
    require(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, key.data(), iv.data()));
    Bytes zero(length), output(length + 16);
    int n = 0, tail = 0;
    require(EVP_EncryptUpdate(ctx.get(), output.data(), &n, zero.data(), checked_size(length)));
    require(EVP_EncryptFinal_ex(ctx.get(), output.data() + n, &tail));
    output.resize(static_cast<std::size_t>(n + tail));
    return output;
}
std::array<Bytes, 3> derive_keys(View key, View nonce, int profile, Layout layout) {
    if (key.size() != 32) throw Error("key file must contain exactly 32 raw bytes");
    if (nonce.size() != 32) throw Error("invalid file nonce");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) throw Error("cannot allocate HKDF context");
    const std::string prefix = "ECL-v1/keys/";
    Bytes info(prefix.begin(), prefix.end());
    info.push_back(static_cast<Byte>(profile)); info.push_back(static_cast<Byte>(layout));
    require(EVP_PKEY_derive_init(ctx.get()));
    require(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()));
    require(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), nonce.data(), checked_size(nonce.size())));
    require(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), checked_size(key.size())));
    require(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), checked_size(info.size())));
    std::array<Byte, 96> material{};
    auto length = material.size();
    require(EVP_PKEY_derive(ctx.get(), material.data(), &length));
    if (length != material.size()) throw Error("unexpected HKDF length");
    std::array<Bytes, 3> keys;
    for (std::size_t i = 0; i < keys.size(); ++i)
        keys[i].assign(material.begin() + i * 32, material.begin() + (i + 1) * 32);
    OPENSSL_cleanse(material.data(), material.size());
    return keys;
}
Bytes from_int(const BigInt& value, std::size_t width) {
    if (value < 0) throw Error("negative integer encoding");
    if (width == 0 && value == 0) return {};
    Bytes encoded;
    export_bits(value, std::back_inserter(encoded), 8, true);
    if (encoded.size() > width) throw Error("integer does not fit encoded width");
    Bytes result(width - encoded.size(), 0);
    result.insert(result.end(), encoded.begin(), encoded.end());
    return result;
}
BigInt to_int(View bytes) {
    BigInt result = 0;
    if (!bytes.empty()) import_bits(result, bytes.begin(), bytes.end(), 8, true);
    return result;
}
} // namespace detail
} // namespace ecl
