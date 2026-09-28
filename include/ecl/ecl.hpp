#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <nlohmann/json.hpp>

namespace ecl {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using View = std::span<const Byte>;
using Counts = std::array<std::uint64_t, 256>;
using BigInt = boost::multiprecision::cpp_int;
using Json = nlohmann::ordered_json;
inline constexpr auto version = "1.0.1";
inline constexpr std::uint64_t scale = 1'000'000'000'000ULL;
// ECLAB001 compatibility constants. ECLAB002 metadata is class-dependent.
inline constexpr std::size_t header_size = 100;
inline constexpr std::size_t sidecar_size = 2213;
inline constexpr std::size_t default_max_plain = std::numeric_limits<std::size_t>::max();
inline constexpr std::size_t default_max_cipher = std::numeric_limits<std::size_t>::max();
enum class Layout : Byte { detached = 0, embedded = 1 };

struct Error : std::runtime_error { using runtime_error::runtime_error; };
struct AuthenticationError : Error { using Error::Error; };

struct Options {
    int profile = 2;
    std::string budget = "0";
    Layout layout = Layout::detached;
    std::size_t max_plain = default_max_plain;
    std::size_t max_cipher = default_max_cipher;
    std::size_t max_expansion = 64;
    // Public, reusable distribution. Mandatory for strict entropy mode.
    std::optional<Counts> public_template;
};
struct Encrypted {
    Bytes ciphertext;
    std::optional<Bytes> sidecar;
    Json report;
};
struct Decrypted {
    Bytes plaintext;
    Json report;
};

Counts histogram(View data);
double entropy(const Counts& counts);
std::vector<std::uint64_t> normalized_profile(const Counts& counts);
std::uint64_t budget_units(const std::string& value);
// ECLAB001 policy: strict mode preserves the complete normalized histogram.
void verify_entropy_policy(const Counts& source, const Counts& target, int profile, std::uint64_t budget);
Counts shape_counts(const Counts& source, std::uint64_t budget);
BigInt multinomial(const Counts& counts);
BigInt rank_bytes(View data, const Counts& counts);
Bytes unrank_bytes(const BigInt& rank, const Counts& counts);
std::size_t rank_length(const BigInt& domain);
Json check_pe(View data);
// A canonical one-peak distribution based only on public length and target entropy.
Counts make_public_template(std::uint64_t size, const std::string& target_entropy);
// ECLAB002 policy: compare against an unscaled public template of the same byte length.
void verify_shared_entropy_policy(const Counts& source, const Counts& public_template,
                                  int profile, std::uint64_t budget);
Counts parse_public_template(const Json& document);
Json public_template_document(const Counts& counts);
std::size_t max_metadata_size(std::size_t ciphertext_size);
Bytes random_bytes(std::size_t size);
Bytes sha256(View data);
std::string hex(View data);
Encrypted encrypt(View data, View key, const Options& options = {});
Decrypted decrypt(View ciphertext, View key, const std::optional<Bytes>& sidecar = std::nullopt,
                  std::size_t max_plain = default_max_plain,
                  std::size_t max_cipher = default_max_cipher);

Bytes read_limited(const std::filesystem::path& path, std::size_t limit);
void atomic_write(const std::filesystem::path& path, View data, bool force = false);
void ensure_distinct(const std::vector<std::filesystem::path>& paths);
} // namespace ecl
