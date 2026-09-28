#pragma once
#include <ecl/ecl.hpp>

namespace ecl::detail {
Bytes concat(std::initializer_list<View> parts);
Bytes aes_gcm_encrypt(View key, View nonce, View plain, View aad);
Bytes aes_gcm_decrypt(View key, View nonce, View cipher_tag, View aad);
Bytes aes_ctr_stream(View key, std::size_t length);
std::array<Bytes, 3> derive_keys(View key, View nonce, int profile, Layout layout);
bool secure_equal(View a, View b);
Bytes from_int(const BigInt& value, std::size_t width);
BigInt to_int(View bytes);
// Private test seam. The public API and CLI always generate a fresh nonce.
Encrypted encrypt_with_nonce(View data, View key, const Options& options, View nonce);
} // namespace ecl::detail
