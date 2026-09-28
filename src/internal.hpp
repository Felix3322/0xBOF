#pragma once
#include <ecl/ecl.hpp>

namespace ecl::detail {
Bytes concat(std::initializer_list<View> parts);
Bytes aes_gcm_encrypt(View key, View nonce, View plain, View aad);
Bytes aes_gcm_decrypt(View key, View nonce, View cipher_tag, View aad);
Bytes aes_gcm_siv_encrypt(View key, View nonce, View plain, View aad);
Bytes aes_gcm_siv_decrypt(View key, View nonce, View cipher_tag, View aad);
Bytes privacy_key(View key, View salt, const std::string& purpose);
Bytes hmac_sha256(View key, std::initializer_list<View> parts);
void cleanse(Bytes& bytes) noexcept;
struct WipeBytes {
    Bytes& bytes;
    explicit WipeBytes(Bytes& value) : bytes(value) {}
    WipeBytes(const WipeBytes&) = delete;
    WipeBytes& operator=(const WipeBytes&) = delete;
    ~WipeBytes() { cleanse(bytes); }
};
Bytes aes_ctr_stream(View key, std::size_t length);
std::array<Bytes, 3> derive_keys(View key, View nonce, int profile, Layout layout);
bool secure_equal(View a, View b);
Bytes from_int(const BigInt& value, std::size_t width);
BigInt to_int(View bytes);
// Legacy format fixture writer, not used by the public encryption API.
Encrypted encrypt_with_nonce(View data, View key, const Options& options, View nonce);
Decrypted decrypt_legacy(View ciphertext, View key, const std::optional<Bytes>& sidecar,
                         std::size_t max_plain = default_max_plain,
                         std::size_t max_cipher = default_max_cipher);
} // namespace ecl::detail
