#include "internal.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <numeric>
#include <boost/multiprecision/cpp_dec_float.hpp>

namespace ecl {
namespace {
using Decimal = boost::multiprecision::cpp_dec_float_100;
constexpr std::array<Byte, 8> magic{'E','C','L','A','B','0','0','2'};
constexpr std::array<Byte, 8> legacy_magic{'E','C','L','A','B','0','0','1'};
constexpr std::size_t counts_bytes = 256 * 8;
constexpr std::size_t public_header_bytes = 68 + counts_bytes;
constexpr std::size_t chunk_bytes = 1U << 20;
constexpr std::size_t outer_tag_bytes = 32;

std::size_t add(std::size_t a, std::size_t b) {
    if (b > Bytes().max_size() || a > Bytes().max_size() - b) throw Error("record size overflow");
    return a + b;
}
std::size_t bit_size(std::size_t bytes) {
    if (bytes > std::numeric_limits<std::size_t>::max() / 8) throw Error("record bit length overflow");
    return bytes * 8;
}
std::size_t integer_bits(const BigInt& x) {
    if (x < 0) throw Error("negative transport integer");
    return x == 0 ? 0 : static_cast<std::size_t>(boost::multiprecision::msb(x)) + 1;
}
void put64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<Byte>(value >> shift));
}
std::uint64_t get64(View input, std::size_t offset) {
    if (offset > input.size() || input.size() - offset < 8) throw Error("truncated privacy record");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | input[offset + i];
    return value;
}
std::uint64_t total(const Counts& counts) {
    std::uint64_t result = 0;
    for (auto count : counts) {
        if (count > UINT64_MAX - result) throw Error("template length overflow");
        result += count;
    }
    return result;
}
bool starts_with(View bytes, const std::array<Byte, 8>& prefix) {
    return bytes.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), bytes.begin());
}
Decimal shannon(const Counts& counts) {
    const auto n = total(counts);
    if (!n) return 0;
    // Group equal counts: one-peak templates have at most three distinct counts.
    std::map<std::uint64_t, unsigned> frequencies;
    for (auto c : counts) if (c) ++frequencies[c];
    if (frequencies.size() == 1 && std::has_single_bit(frequencies.begin()->second))
        return Decimal(std::bit_width(frequencies.begin()->second) - 1);
    const Decimal ln2 = log(Decimal(2));
    Decimal result = 0;
    for (const auto& [c, multiplicity] : frequencies) {
        const Decimal p = Decimal(c) / n;
        result -= Decimal(multiplicity) * p * log(p) / ln2;
    }
    return result;
}
Counts one_peak(std::uint64_t n, std::uint64_t mass) {
    Counts q{};
    q[0] = n - mass;
    const auto each = mass / 255, remainder = mass % 255;
    for (std::size_t i = 1; i < q.size(); ++i) q[i] = each + (i <= remainder ? 1 : 0);
    return q;
}
Counts template_at(std::uint64_t n, std::uint64_t entropy_units) {
    std::uint64_t low = 0, high = n - n / 256 - (n % 256 != 0 ? 1 : 0);
    const Decimal target = Decimal(entropy_units) / scale;
    while (low < high) {
        const auto middle = low + (high - low) / 2 + (high - low) % 2;
        if (shannon(one_peak(n, middle)) <= target) low = middle;
        else high = middle - 1;
    }
    return one_peak(n, low);
}
Counts automatic_template(const Counts& source, std::uint64_t budget) {
    if (!budget) throw Error("zero-budget encryption requires an explicit shared --template");
    const auto n = total(source);
    const Decimal h = shannon(source);
    // The grid is fixed by the PUBLIC budget, never by the source frequency spectrum.
    const auto step = std::max<std::uint64_t>(1, budget / 2);
    const auto last = (8 * scale + step - 1) / step;
    std::uint64_t low = 0, high = last;
    while (low < high) {
        const auto middle = low + (high - low) / 2;
        const auto q = template_at(n, std::min(8 * scale, middle * step));
        if (shannon(q) < h) low = middle + 1;
        else high = middle;
    }
    const auto q = template_at(n, std::min(8 * scale, low * step));
    const Decimal delta = shannon(q) - h;
    if (delta < 0 || delta > Decimal(budget) / scale)
        throw Error("no shared template covers this entropy budget; supply --template or increase --budget");
    return q;
}
bool same_exact_entropy(const Counts& a, const Counts& b) {
    if (total(a) != total(b)) return false;
    if (normalized_profile(a) == normalized_profile(b)) return true;
    // Compare product(c^c) without allocating an N*log(N)-bit integer or factoring
    // arbitrary 64-bit counts. Refine bases by gcd until the bases are coprime.
    std::map<std::uint64_t, BigInt> powers;
    const auto accumulate = [&](std::uint64_t base, const BigInt& exponent) {
        if (base <= 1 || exponent == 0) return;
        powers[base] += exponent;
        if (powers[base] == 0) powers.erase(base);
    };
    for (auto c : a) accumulate(c, BigInt(c));
    for (auto c : b) accumulate(c, -BigInt(c));
    for (;;) {
        bool split = false;
        for (auto i = powers.begin(); i != powers.end() && !split; ++i) {
            auto j = i; ++j;
            for (; j != powers.end(); ++j) {
                const auto g = std::gcd(i->first, j->first);
                if (g <= 1) continue;
                const auto x = i->first, y = j->first;
                const BigInt ex = i->second, ey = j->second;
                // Do not increment an erased iterator on leaving the outer loop.
                powers.erase(x); powers.erase(y);
                accumulate(g, ex + ey);
                accumulate(x / g, ex);
                accumulate(y / g, ey);
                split = true;
                break;
            }
            if (split) break;
        }
        if (!split) return powers.empty();
    }
}
void check_policy(const Counts& source, const Counts& q, int profile, std::uint64_t budget) {
    if (profile < 1 || profile > 2 || budget > 8 * scale || (profile == 2 && budget))
        throw Error("invalid privacy profile or budget");
    if (total(source) != total(q)) throw Error("shared template must match the original byte length");
    if (!budget) {
        if (!same_exact_entropy(source, q)) throw Error("input does not have the template's exact entropy");
    } else {
        if (normalized_profile(source) == normalized_profile(q)) return;
        const Decimal delta = shannon(q) - shannon(source);
        if (delta < 0 && same_exact_entropy(source, q)) return;
        if (delta < 0 || delta > Decimal(budget) / scale)
            throw Error("input is outside the selected public entropy class");
    }
}
struct Dimensions {
    std::size_t rank_bytes, plain_bytes, chunks, encrypted_bytes;
};
Dimensions dimensions(const Counts& q) {
    const auto n = total(q);
    if (n > Bytes().max_size()) throw Error("template exceeds addressable memory");
    // log2(multinomial(h)) <= N*H(h) <= N*H(q). A full extra byte
    // protects the public bound against decimal rounding. Clamp at N raw bytes.
    const Decimal bound = ceil(Decimal(n) * shannon(q) / 8);
    const auto width = bound >= Decimal(n) ? static_cast<std::size_t>(n)
        : std::min(static_cast<std::size_t>(n), add(bound.convert_to<std::size_t>(), 1));
    const auto plain = add(counts_bytes, width);
    const auto chunks = plain / chunk_bytes + (plain % chunk_bytes != 0 ? 1 : 0);
    if (chunks > Bytes().max_size() / 16) throw Error("too many authentication chunks");
    return {width, plain, chunks, add(add(plain, chunks * 16), 32)};
}
Bytes chunk_nonce(std::size_t index) {
    Bytes nonce(4, 0);
    put64(nonce, static_cast<std::uint64_t>(index));
    return nonce;
}
Bytes chunk_aad(View header, const Dimensions& d, std::size_t index) {
    Bytes aad(header.begin(), header.end());
    put64(aad, static_cast<std::uint64_t>(index));
    put64(aad, static_cast<std::uint64_t>(d.chunks));
    put64(aad, static_cast<std::uint64_t>(d.plain_bytes));
    return aad;
}
Bytes seal_record(View plain, View key, View header, const Dimensions& d) {
    if (plain.size() != d.plain_bytes) throw Error("invalid padded record length");
    Bytes encrypted; encrypted.reserve(d.encrypted_bytes);
    for (std::size_t index = 0, offset = 0; index < d.chunks; ++index) {
        const auto size = std::min(chunk_bytes, plain.size() - offset);
        const auto part = detail::aes_gcm_siv_encrypt(key, chunk_nonce(index),
            plain.subspan(offset, size), chunk_aad(header, d, index));
        encrypted.insert(encrypted.end(), part.begin(), part.end());
        offset += size;
    }
    auto record_key = detail::privacy_key(key, header.subspan(36, 32), "record-auth");
    detail::WipeBytes wipe_key(record_key);
    const auto tag = detail::hmac_sha256(record_key, {header, encrypted});
    encrypted.insert(encrypted.end(), tag.begin(), tag.end());
    return encrypted;
}
Bytes open_record(View encrypted, View key, View header, const Dimensions& d) {
    if (encrypted.size() != d.encrypted_bytes) throw AuthenticationError("invalid encrypted record length");
    auto record_key = detail::privacy_key(key, header.subspan(36, 32), "record-auth");
    detail::WipeBytes wipe_key(record_key);
    const auto tag = detail::hmac_sha256(record_key, {header, encrypted.first(encrypted.size() - 32)});
    if (!detail::secure_equal(tag, encrypted.last(32)))
        throw AuthenticationError("record authentication failed");
    Bytes plain; plain.reserve(d.plain_bytes);
    try {
        for (std::size_t index = 0, offset = 0; index < d.chunks; ++index) {
            const auto size = std::min(chunk_bytes, d.plain_bytes - plain.size());
            auto part = detail::aes_gcm_siv_decrypt(key, chunk_nonce(index),
                encrypted.subspan(offset, size + 16), chunk_aad(header, d, index));
            detail::WipeBytes wipe(part);
            plain.insert(plain.end(), part.begin(), part.end());
            offset += size + 16;
        }
    } catch (...) { detail::cleanse(plain); throw; }
    return plain;
}
struct Info {
    int profile;
    Layout layout;
    std::uint64_t original, output, budget;
    Bytes salt;
    Counts q;
    Bytes encode() const {
        Bytes bytes(magic.begin(), magic.end());
        bytes.insert(bytes.end(), {2, static_cast<Byte>(profile), static_cast<Byte>(layout), 0});
        put64(bytes, original); put64(bytes, output); put64(bytes, budget);
        bytes.insert(bytes.end(), salt.begin(), salt.end());
        for (auto count : q) put64(bytes, count);
        return bytes;
    }
};
Info decode_header(View bytes, std::size_t actual_size, Layout layout, std::size_t max_plain) {
    if (bytes.size() != public_header_bytes || !starts_with(bytes, magic) || bytes[8] != 2 ||
        bytes[9] < 1 || bytes[9] > 2 || bytes[10] != static_cast<Byte>(layout) || bytes[11])
        throw AuthenticationError("unsupported privacy header");
    Info info{bytes[9], layout, get64(bytes, 12), get64(bytes, 20), get64(bytes, 28),
              Bytes(bytes.begin() + 36, bytes.begin() + 68), {}};
    if (info.original > max_plain || info.original > Bytes().max_size() || info.output != actual_size ||
        info.budget > 8 * scale || (info.profile == 2 && info.budget))
        throw AuthenticationError("invalid privacy lengths or entropy policy");
    auto remaining = info.original;
    for (std::size_t i = 0; i < info.q.size(); ++i) {
        const auto count = get64(bytes, 68 + i * 8);
        if (count > remaining) throw AuthenticationError("invalid public template");
        info.q[i] = count; remaining -= count;
    }
    if (remaining || (layout == Layout::detached && info.original != actual_size))
        throw AuthenticationError("template length mismatch");
    return info;
}
Counts scaled(const Counts& q, std::size_t factor) {
    Counts result{};
    for (std::size_t i = 0; i < q.size(); ++i) {
        if (q[i] && factor > UINT64_MAX / q[i]) throw Error("template expansion overflow");
        result[i] = q[i] * factor;
    }
    return result;
}
Json report(const Info& info, std::size_t metadata_bytes) {
    return {{"version", version}, {"format", "ECLAB002"}, {"profile", info.profile},
        {"profile_name", info.profile == 1 ? "shared-entropy-budget" : "shared-exact-entropy"},
        {"layout", info.layout == Layout::detached ? "detached" : "embedded"},
        {"cipher_bytes", info.output}, {"external_metadata_bytes", metadata_bytes},
        {"total_storage_bytes", info.output > UINT64_MAX - metadata_bytes ? Json(nullptr) : Json(info.output + metadata_bytes)},
        {"budget_bits_per_byte", static_cast<double>(info.budget) / scale},
        {"cipher_entropy_bits_per_byte", entropy(info.q)},
        {"privacy_scope", "same public template, length, profile, budget and layout"},
        {"security_status", "experimental composition; not independently audited"}};
}
} // namespace

Counts make_public_template(std::uint64_t size, const std::string& target_entropy) {
    return template_at(size, budget_units(target_entropy));
}
void verify_shared_entropy_policy(const Counts& source, const Counts& public_template,
                                  int profile, std::uint64_t budget) {
    check_policy(source, public_template, profile, budget);
}
Counts parse_public_template(const Json& document) {
    if (!document.is_object() || document.value("format", std::string()) != "0xBOF-template-v1" ||
        !document.contains("counts") || !document["counts"].is_array() || document["counts"].size() != 256)
        throw Error("template must be a 0xBOF-template-v1 JSON object with 256 integer counts");
    Counts result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto& value = document["counts"][i];
        if (!value.is_number_unsigned() && (!value.is_number_integer() || value.get<std::int64_t>() < 0))
            throw Error("template counts must be unsigned 64-bit integers");
        result[i] = value.get<std::uint64_t>();
    }
    total(result);
    return result;
}
Json public_template_document(const Counts& counts) {
    return {{"format", "0xBOF-template-v1"}, {"bytes", total(counts)},
            {"entropy_bits_per_byte", entropy(counts)}, {"counts", counts}};
}
std::size_t max_metadata_size(std::size_t ciphertext_size) {
    // Includes public template, full encrypted record, chunk tags and outer MAC.
    // Saturation is a representational bound, not an arbitrary processed-file cap.
    const auto limit = Bytes().max_size();
    if (ciphertext_size > (limit - 8192) / 2) return limit;
    return 2 * ciphertext_size + 8192;
}

Encrypted encrypt(View data, View key, const Options& options) {
    if (key.size() != 32) throw Error("key file must contain exactly 32 raw bytes");
    if (data.size() > options.max_plain) throw Error("input exceeds configured resource limit");
    if (options.profile < 1 || options.profile > 2) throw Error("profile must be 1 or 2");
    if (options.layout != Layout::detached && options.layout != Layout::embedded) throw Error("invalid layout");
    const auto budget = budget_units(options.budget);
    if (options.profile == 2 && budget) throw Error("profile 2 requires budget=0");
    if (!options.public_template && (options.profile == 2 || !budget))
        throw Error("strict entropy requires an explicit shared --template; no per-file histogram fallback");
    const auto source = histogram(data);
    const auto q = options.public_template ? *options.public_template : automatic_template(source, budget);
    check_policy(source, q, options.profile, budget);
    const auto d = dimensions(q);
    Info info{options.profile, options.layout, data.size(), data.size(), budget, random_bytes(32), q};
    Counts output_counts = q;
    if (options.layout == Layout::detached) {
        if (data.size() > options.max_cipher) throw Error("ciphertext exceeds configured resource limit");
    } else {
        if (data.empty() || std::count_if(q.begin(), q.end(), [](auto c) { return c != 0; }) < 2)
            throw Error("embedded layout has no capacity for this public template; use detached");
        const auto max_factor = std::min(options.max_expansion, options.max_cipher / data.size());
        if (!max_factor) throw Error("embedded output exceeds configured expansion or byte limit");
        const auto frame_bytes = add(public_header_bytes, d.encrypted_bytes);
        const auto needed = add(bit_size(frame_bytes), 1);
        const auto fits = [&](std::size_t factor) {
            const auto domain = multinomial(scaled(q, factor));
            return integer_bits(domain) > needed; // domain >= 2^needed
        };
        std::size_t low = 1, high = 1;
        while (!fits(high)) {
            if (high == max_factor) throw Error("embedded template has insufficient capacity within --max-expansion");
            low = high + 1;
            high = high > max_factor / 2 ? max_factor : high * 2;
        }
        while (low < high) {
            const auto middle = low + (high - low) / 2;
            if (fits(middle)) high = middle; else low = middle + 1;
        }
        output_counts = scaled(q, low);
        info.output = data.size() * low; // bounded by max_cipher above
    }
    const auto header = info.encode();
    auto file_key = detail::privacy_key(key, info.salt, "payload");
    detail::WipeBytes wipe_key(file_key);
    Bytes plain; plain.reserve(d.plain_bytes);
    detail::WipeBytes wipe_plain(plain);
    for (auto count : source) put64(plain, count);
    auto rank = detail::from_int(rank_bytes(data, source), d.rank_bytes);
    detail::WipeBytes wipe_rank(rank);
    plain.insert(plain.end(), rank.begin(), rank.end());
    const auto encrypted = seal_record(plain, file_key, header, d);
    Encrypted result;
    if (options.layout == Layout::detached) {
        const auto domain = multinomial(q);
        const auto k = integer_bits(domain) - 1;
        const auto encrypted_bits = bit_size(d.encrypted_bytes);
        if (k > encrypted_bits) throw Error("invalid transport capacity");
        const auto spill_bits = encrypted_bits - k;
        const auto spill_bytes = spill_bits / 8 + (spill_bits % 8 != 0 ? 1 : 0);
        const auto x = detail::to_int(encrypted);
        const BigInt low = x & ((BigInt(1) << k) - 1);
        result.ciphertext = unrank_bytes(low, q);
        auto metadata = detail::concat({header, detail::from_int(x >> k, spill_bytes)});
        auto mac_key = detail::privacy_key(key, info.salt, "detached-transport");
        detail::WipeBytes wipe_mac(mac_key);
        const auto tag = detail::hmac_sha256(mac_key, {metadata, result.ciphertext});
        metadata.insert(metadata.end(), tag.begin(), tag.end());
        result.sidecar = std::move(metadata);
    } else {
        const auto frame = detail::concat({header, encrypted});
        const BigInt value = (BigInt(1) << bit_size(frame.size())) | detail::to_int(frame);
        result.ciphertext = unrank_bytes(value, output_counts);
    }
    result.report = report(info, result.sidecar ? result.sidecar->size() : 0);
    return result;
}

Decrypted decrypt(View ciphertext, View key, const std::optional<Bytes>& sidecar,
                  std::size_t max_plain, std::size_t max_cipher) {
    if (key.size() != 32) throw Error("key file must contain exactly 32 raw bytes");
    if (ciphertext.size() > max_cipher) throw Error("ciphertext exceeds configured resource limit");
    if (sidecar && starts_with(*sidecar, legacy_magic))
        return detail::decrypt_legacy(ciphertext, key, sidecar, max_plain, max_cipher);
    Info info{};
    Bytes header, encrypted;
    if (sidecar) {
        if (sidecar->size() < public_header_bytes + outer_tag_bytes ||
            sidecar->size() > max_metadata_size(ciphertext.size()))
            throw AuthenticationError("invalid sidecar length");
        const View metadata(*sidecar);
        header.assign(metadata.begin(), metadata.begin() + public_header_bytes);
        info = decode_header(header, ciphertext.size(), Layout::detached, max_plain);
        auto mac_key = detail::privacy_key(key, info.salt, "detached-transport");
        detail::WipeBytes wipe_mac(mac_key);
        const auto tag = detail::hmac_sha256(mac_key, {metadata.first(metadata.size() - outer_tag_bytes), ciphertext});
        if (!detail::secure_equal(tag, metadata.last(outer_tag_bytes)))
            throw AuthenticationError("authentication failed: wrong key, damaged file or metadata");
        // No multinomial or rank calculation precedes the outer authenticator.
        if (histogram(ciphertext) != info.q) throw AuthenticationError("public template mismatch");
        const auto d = dimensions(info.q);
        const auto k = integer_bits(multinomial(info.q)) - 1;
        const auto encrypted_bits = bit_size(d.encrypted_bytes);
        if (k > encrypted_bits) throw AuthenticationError("invalid transport capacity");
        const auto spill_bits = encrypted_bits - k;
        const auto spill_bytes = spill_bits / 8 + (spill_bits % 8 != 0 ? 1 : 0);
        if (metadata.size() != add(add(public_header_bytes, spill_bytes), outer_tag_bytes))
            throw AuthenticationError("noncanonical sidecar length");
        const auto low = rank_bytes(ciphertext, info.q);
        if (integer_bits(low) > k) throw AuthenticationError("unused transport codeword");
        const BigInt x = (detail::to_int(metadata.subspan(public_header_bytes, spill_bytes)) << k) | low;
        if (integer_bits(x) > encrypted_bits) throw AuthenticationError("noncanonical transport bits");
        encrypted = detail::from_int(x, d.encrypted_bytes);
    } else {
        if (ciphertext.empty()) throw AuthenticationError("empty embedded artifact");
        const auto actual = histogram(ciphertext);
        const auto rank = rank_bytes(ciphertext, actual);
        const auto bits = integer_bits(rank);
        if (!bits || (bits - 1) % 8) throw AuthenticationError("invalid embedded sentinel");
        const auto length = (bits - 1) / 8;
        const auto frame = detail::from_int(rank ^ (BigInt(1) << (bits - 1)), length);
        if (starts_with(frame, legacy_magic))
            return detail::decrypt_legacy(ciphertext, key, std::nullopt, max_plain, max_cipher);
        if (frame.size() < public_header_bytes) throw AuthenticationError("truncated embedded header");
        header.assign(frame.begin(), frame.begin() + public_header_bytes);
        info = decode_header(header, ciphertext.size(), Layout::embedded, max_plain);
        if (!info.original || ciphertext.size() % info.original)
            throw AuthenticationError("invalid embedded expansion");
        const auto factor = ciphertext.size() / static_cast<std::size_t>(info.original);
        if (actual != scaled(info.q, factor)) throw AuthenticationError("embedded template mismatch");
        const auto d = dimensions(info.q);
        if (frame.size() != add(public_header_bytes, d.encrypted_bytes))
            throw AuthenticationError("noncanonical embedded record length");
        encrypted.assign(frame.begin() + public_header_bytes, frame.end());
    }
    const auto d = dimensions(info.q);
    auto file_key = detail::privacy_key(key, info.salt, "payload");
    detail::WipeBytes wipe_key(file_key);
    auto plain = open_record(encrypted, file_key, header, d);
    detail::WipeBytes wipe_plain(plain);
    Counts source{};
    auto remaining = info.original;
    for (std::size_t i = 0; i < source.size(); ++i) {
        const auto count = get64(plain, i * 8);
        if (count > remaining) throw AuthenticationError("invalid authenticated source histogram");
        source[i] = count; remaining -= count;
    }
    if (remaining) throw AuthenticationError("invalid authenticated source length");
    check_policy(source, info.q, info.profile, info.budget);
    const auto rank = detail::to_int(View(plain).subspan(counts_bytes));
    auto restored = unrank_bytes(rank, source);
    return {std::move(restored), report(info, sidecar ? sidecar->size() : 0)};
}
} // namespace ecl
