#include "internal.hpp"
#include <algorithm>
#include <limits>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

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
    for (auto part : parts) result.insert(result.end(), part.begin(), part.end());
    return result;
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
