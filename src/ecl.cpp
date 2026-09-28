#include "internal.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <limits>
#include <numeric>
#include <queue>
#include <sstream>
#include <tuple>
#include <boost/multiprecision/cpp_dec_float.hpp>

namespace ecl {
namespace {
using Decimal = boost::multiprecision::cpp_dec_float_100;
constexpr std::size_t counts_size = 256 * 8;
constexpr std::size_t private_base = counts_size + 32;
constexpr std::size_t embedded_meta_size = private_base + 16;
constexpr std::array<Byte, 8> magic{'E','C','L','A','B','0','0','1'};
bool exact(int profile) { return profile == 2; }
void check_profile(int profile) {
    if (profile < 1 || profile > 2) throw Error("profile must be 1 or 2");
}
std::uint64_t sum_counts(const Counts& counts) {
    std::uint64_t n = 0;
    for (auto count : counts) {
        if (count > std::numeric_limits<std::uint64_t>::max() - n)
            throw Error("histogram total overflow");
        n += count;
    }
    return n;
}
std::size_t bits(const BigInt& number) {
    if (number < 0) throw Error("negative rank");
    return number == 0 ? 0 : static_cast<std::size_t>(boost::multiprecision::msb(number)) + 1;
}
void put64(Bytes& out, std::uint64_t value) {
    for (int i = 56; i >= 0; i -= 8) out.push_back(static_cast<Byte>(value >> i));
}
std::uint64_t get64(View bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8) throw Error("truncated integer");
    std::uint64_t value = 0;
    for (std::size_t i = offset; i < offset + 8; ++i) value = (value << 8) | bytes[i];
    return value;
}
std::uint32_t get_le(View bytes, std::size_t offset, std::size_t width) {
    if (offset > bytes.size() || bytes.size() - offset < width) throw Error("truncated PE field");
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < width; ++i) value |= std::uint32_t(bytes[offset + i]) << (8 * i);
    return value;
}
Bytes pack_counts(const Counts& counts) {
    Bytes out; out.reserve(counts_size);
    for (auto count : counts) put64(out, count);
    return out;
}
Bytes digest_counts(const Counts& counts) { return sha256(pack_counts(counts)); }
Decimal entropy_decimal(const Counts& counts) {
    const auto n = sum_counts(counts);
    if (!n) return 0;
    Decimal result = 0;
    const Decimal ln2 = log(Decimal(2));
    auto sorted = counts; std::sort(sorted.begin(), sorted.end());
    for (auto c : sorted) if (c) {
        const Decimal p = Decimal(c) / n;
        result -= p * log(p) / ln2;
    }
    return result;
}
struct Fenwick {
    std::array<std::uint64_t, 257> tree{};
    explicit Fenwick(const Counts& counts) {
        for (std::size_t symbol = 0; symbol < 256; ++symbol)
            for (auto i = symbol + 1; i <= 256; i += i & (~i + 1)) tree[i] += counts[symbol];
    }
    void remove(std::size_t symbol) {
        for (auto i = symbol + 1; i <= 256; i += i & (~i + 1)) --tree[i];
    }
    std::uint64_t before(std::size_t symbol) const {
        std::uint64_t total = 0;
        for (auto i = symbol; i; i -= i & (~i + 1)) total += tree[i];
        return total;
    }
    std::pair<std::size_t, std::uint64_t> select(std::uint64_t k) const {
        std::size_t index = 0;
        const auto original = k;
        for (std::size_t step = 256; step; step >>= 1) {
            const auto next = index + step;
            if (next <= 256 && tree[next] <= k) { index = next; k -= tree[next]; }
        }
        if (index >= 256) throw Error("enumerative index out of range");
        return {index, original - k};
    }
};
BigInt rank_impl(View data, Counts counts, BigInt ways) {
    auto n = sum_counts(counts);
    if (n != data.size()) throw Error("rank length mismatch");
    Fenwick fw(counts);
    BigInt rank = 0;
    for (auto symbol : data) {
        if (!counts[symbol]) throw Error("rank histogram mismatch");
        rank += ways * fw.before(symbol) / n;
        ways = ways * counts[symbol] / n;
        --counts[symbol]; fw.remove(symbol); --n;
    }
    return rank;
}
Bytes unrank_impl(BigInt rank, Counts counts, BigInt ways) {
    auto n = sum_counts(counts);
    if (rank < 0 || rank >= ways) throw Error("rank is outside its enumerative domain");
    if (n > Bytes().max_size()) throw Error("histogram too large to decode");
    Bytes out(static_cast<std::size_t>(n));
    Fenwick fw(counts);
    for (auto& byte : out) {
        const BigInt k = rank * n / ways;
        const auto [symbol, before] = fw.select(k.convert_to<std::uint64_t>());
        rank -= ways * before / n;
        ways = ways * counts[symbol] / n;
        byte = static_cast<Byte>(symbol);
        --counts[symbol]; fw.remove(symbol); --n;
    }
    if (rank != 0) throw Error("invalid terminal rank");
    return out;
}
Counts relabel_counts(const Counts& counts, View key) {
    std::array<std::size_t, 256> perm{};
    std::iota(perm.begin(), perm.end(), 0);
    auto stream = detail::aes_ctr_stream(key, 1024);
    std::size_t pos = 0;
    for (std::size_t i = 255; i; --i) {
        const auto mask = (1U << std::bit_width(i)) - 1;
        std::size_t value;
        do {
            // Extend the same CTR stream, including the exceedingly rare long rejection run.
            if (pos == stream.size()) stream = detail::aes_ctr_stream(key, stream.size() * 2);
            value = stream[pos++] & mask;
        } while (value > i);
        std::swap(perm[i], perm[value]);
    }
    Counts result{};
    for (std::size_t i = 0; i < 256; ++i) result[perm[i]] = counts[i];
    return result;
}
struct Info {
    int profile;
    Layout layout;
    std::uint64_t plain_size, output_size, budget;
    Bytes nonce, hist_digest;
    Bytes encode() const {
        Bytes out(magic.begin(), magic.end());
        out.insert(out.end(), {1, static_cast<Byte>(profile), static_cast<Byte>(layout), 0});
        put64(out, plain_size); put64(out, output_size); put64(out, budget);
        return detail::concat({out, nonce, hist_digest});
    }
    static Info decode(View raw) {
        if (raw.size() != header_size) throw Error("truncated header");
        if (!std::equal(magic.begin(), magic.end(), raw.begin()) || raw[8] != 1 ||
            raw[9] < 1 || raw[9] > 2 || raw[10] > 1 || raw[11] != 0)
            throw Error("unsupported or corrupt ECL header");
        Info info{raw[9], static_cast<Layout>(raw[10]), get64(raw, 12), get64(raw, 20), get64(raw, 28),
                  Bytes(raw.begin() + 36, raw.begin() + 68), Bytes(raw.begin() + 68, raw.end())};
        if (info.budget > 8 * scale || (exact(info.profile) && info.budget))
            throw Error("invalid authenticated entropy policy");
        return info;
    }
};
std::pair<Counts, Bytes> read_private(View raw, std::uint64_t size) {
    if (raw.size() < private_base) throw AuthenticationError("invalid private metadata");
    Counts counts{};
    std::uint64_t remaining = size;
    for (std::size_t i = 0; i < 256; ++i) {
        counts[i] = get64(raw, i * 8);
        if (counts[i] > remaining) throw AuthenticationError("private histogram length mismatch");
        remaining -= counts[i];
    }
    if (remaining) throw AuthenticationError("private histogram length mismatch");
    return {counts, Bytes(raw.begin() + counts_size, raw.begin() + private_base)};
}
Json report(View data, View ciphertext, const Info& info, const std::optional<Bytes>& sidecar) {
    (void)data;
    const auto g = histogram(ciphertext);
    const std::array<const char*, 2> names{"entropy-budget", "exact-histogram"};
    return {{"version", version}, {"profile", info.profile}, {"profile_name", names[info.profile - 1]},
        {"layout", info.layout == Layout::detached ? "detached" : "embedded"},
        {"format", "ECLAB001"}, {"privacy_scope", "legacy per-file frequency spectrum"},
        {"entropy_scope", "entire main output file"},
        {"cipher_bytes", ciphertext.size()}, {"external_metadata_bytes", sidecar ? sidecar->size() : 0},
        {"total_storage_bytes", ciphertext.size() + (sidecar ? sidecar->size() : 0)},
        {"cipher_entropy_bits_per_byte", entropy(g)},
        {"budget_bits_per_byte", static_cast<double>(info.budget) / scale},
        {"cipher_sha256", hex(sha256(ciphertext))},
        {"security_status", "experimental composition; not independently audited"}};
}
} // namespace

Counts histogram(View data) {
    Counts counts{};
    for (auto symbol : data) ++counts[symbol];
    return counts;
}
double entropy(const Counts& counts) {
    const auto n = sum_counts(counts);
    if (!n) return 0;
    auto sorted = counts; std::sort(sorted.begin(), sorted.end());
    long double result = 0;
    for (auto count : sorted) if (count) {
        const auto p = static_cast<long double>(count) / n;
        result -= p * std::log2(p);
    }
    return static_cast<double>(result);
}
std::vector<std::uint64_t> normalized_profile(const Counts& counts) {
    std::vector<std::uint64_t> nonzero;
    std::uint64_t gcd = 0;
    for (auto count : counts) if (count) { nonzero.push_back(count); gcd = std::gcd(gcd, count); }
    std::sort(nonzero.begin(), nonzero.end());
    for (auto& count : nonzero) count /= gcd;
    return nonzero;
}
std::uint64_t budget_units(const std::string& value) {
    // Parse the decimal coefficient and exponent as integers: no binary rounding at the boundary.
    if (value.empty() || value.size() > 1024) throw Error("invalid entropy budget");
    std::size_t pos = 0;
    const bool negative = value[pos] == '-';
    if (value[pos] == '+' || negative) ++pos;
    std::string digits;
    std::int64_t fractional = 0;
    bool dot = false;
    while (pos < value.size()) {
        const auto c = value[pos];
        if (c >= '0' && c <= '9') { digits += c; if (dot) ++fractional; }
        else if (c == '.' && !dot) dot = true;
        else break;
        ++pos;
    }
    if (digits.empty()) throw Error("budget must be a finite decimal in [0, 8]");
    std::int64_t exponent = 0;
    if (pos < value.size() && (value[pos] == 'e' || value[pos] == 'E')) {
        ++pos;
        bool minus = false;
        if (pos < value.size() && (value[pos] == '+' || value[pos] == '-')) minus = value[pos++] == '-';
        const auto start = pos;
        while (pos < value.size() && value[pos] >= '0' && value[pos] <= '9') {
            if (exponent > 10000) throw Error("budget exponent is too large");
            exponent = exponent * 10 + value[pos++] - '0';
        }
        if (start == pos) throw Error("invalid budget exponent");
        if (minus) exponent = -exponent;
    }
    if (pos != value.size()) throw Error("budget must be a finite decimal in [0, 8]");
    const auto first = digits.find_first_not_of('0');
    if (first == std::string::npos) return 0;
    if (negative) throw Error("budget must be in [0, 8]");
    digits.erase(0, first);
    auto shift = 12 + exponent - fractional;
    while (shift < 0 && digits.back() == '0') { digits.pop_back(); ++shift; }
    if (shift < 0) throw Error("budget supports at most 12 decimal places");
    if (shift > 13 || digits.size() + static_cast<std::size_t>(shift) > 13)
        throw Error("budget must be in [0, 8]");
    digits.append(static_cast<std::size_t>(shift), '0');
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), result);
    if (parsed.ec != std::errc{} || result > 8 * scale) throw Error("budget must be in [0, 8]");
    return result;
}
void verify_entropy_policy(const Counts& source, const Counts& target, int profile, std::uint64_t budget) {
    check_profile(profile);
    if (budget > 8 * scale || (exact(profile) && budget)) throw Error("invalid entropy policy");
    if (normalized_profile(source) == normalized_profile(target)) return;
    if (exact(profile)) throw Error("exact-entropy invariant failed (integer histogram check)");
    const Decimal delta = entropy_decimal(target) - entropy_decimal(source);
    if (delta < 0 || delta > Decimal(budget) / scale) throw Error("entropy budget violated");
}
Counts shape_counts(const Counts& source, std::uint64_t budget) {
    if (budget > 8 * scale) throw Error("budget must be in [0, 8]");
    auto counts = source;
    const auto n = sum_counts(counts);
    const double limit = static_cast<double>(budget) / scale - 1e-10;
    if (n < 2 || limit <= 0) return counts;
    // Lexicographic pair ordering makes budget shaping deterministic.
    using Entry = std::pair<std::uint64_t, std::size_t>;
    auto max_compare = [](const Entry& a, const Entry& b) {
        return a.first != b.first ? a.first < b.first : a.second > b.second;
    };
    std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> minheap;
    std::priority_queue<Entry, std::vector<Entry>, decltype(max_compare)> maxheap(max_compare);
    for (std::size_t i = 0; i < 256; ++i) { minheap.emplace(counts[i], i); maxheap.emplace(counts[i], i); }
    const auto f = [](std::uint64_t x) { return x ? static_cast<double>(x) * std::log2(static_cast<double>(x)) : 0.; };
    double used = 0;
    for (std::uint64_t iteration = 0; iteration < n; ++iteration) {
        while (minheap.top().first != counts[minheap.top().second]) minheap.pop();
        while (maxheap.top().first != counts[maxheap.top().second]) maxheap.pop();
        const auto [b, ib] = minheap.top();
        const auto [a, ia] = maxheap.top();
        if (a <= b + 1) break;
        const auto increase = (f(a) + f(b) - f(a - 1) - f(b + 1)) / static_cast<double>(n);
        if (used + increase > limit) break;
        --counts[ia]; ++counts[ib]; used += increase;
        for (auto i : {ia, ib}) { minheap.emplace(counts[i], i); maxheap.emplace(counts[i], i); }
    }
    verify_entropy_policy(source, counts, 1, budget);
    return counts;
}
BigInt multinomial(const Counts& counts) {
    sum_counts(counts); // Reject totals that would overflow intermediate arithmetic.
    BigInt ways = 1;
    std::uint64_t total = 0;
    for (auto count : counts) if (count) {
        const auto combined = total + count;
        const auto k = std::min(count, total);
        BigInt choose = 1;
        for (std::uint64_t i = 1; i <= k; ++i) { choose *= combined - k + i; choose /= i; }
        ways *= choose;
        total = combined;
    }
    return ways;
}
BigInt rank_bytes(View data, const Counts& counts) { return rank_impl(data, counts, multinomial(counts)); }
Bytes unrank_bytes(const BigInt& rank, const Counts& counts) { return unrank_impl(rank, counts, multinomial(counts)); }
std::size_t rank_length(const BigInt& domain) {
    if (domain < 1) throw Error("invalid enumerative domain");
    return std::max<std::size_t>(1, (bits(domain - 1) + 7) / 8);
}
Json check_pe(View data) {
    if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z')
        throw Error("PE profile requires an MZ / PE32 / PE32+ image");
    const auto pe = static_cast<std::size_t>(get_le(data, 0x3c, 4));
    if (pe < 64 || pe > data.size() || data.size() - pe < 24 || get_le(data, pe, 4) != 0x4550)
        throw Error("invalid PE signature or e_lfanew");
    const auto machine = get_le(data, pe + 4, 2), sections = get_le(data, pe + 6, 2);
    const auto optional = get_le(data, pe + 20, 2), flags = get_le(data, pe + 22, 2);
    const auto opt = pe + 24;
    if (sections < 1 || sections > 96 || !(flags & 2)) throw Error("unsupported PE section count or image flags");
    if (optional < 2 || optional + sections * 40 > data.size() - opt) throw Error("truncated PE headers");
    const auto signature = get_le(data, opt, 2);
    if (signature != 0x10b && signature != 0x20b) throw Error("only PE32 and PE32+ are supported");
    if (optional < (signature == 0x10b ? 96U : 112U)) throw Error("truncated PE optional header");
    for (std::size_t i = 0; i < sections; ++i) {
        const auto off = opt + optional + i * 40;
        const auto size = get_le(data, off + 16, 4), ptr = get_le(data, off + 20, 4);
        if (size && (!ptr || ptr > data.size() || size > data.size() - ptr))
            throw Error("PE section raw-data range is outside the input");
    }
    std::ostringstream machine_hex; machine_hex << "0x" << std::hex << machine;
    return {{"format", signature == 0x20b ? "PE32+" : "PE32"}, {"machine", machine_hex.str()}, {"sections", sections}};
}

Encrypted detail::encrypt_with_nonce(View data, View key, const Options& options, View nonce) {
    check_profile(options.profile);
    const auto budget = budget_units(options.budget);
    if (exact(options.profile) && budget) throw Error("profile 2 requires budget=0");
    if (options.layout != Layout::detached && options.layout != Layout::embedded) throw Error("invalid layout");
    if (data.size() > options.max_plain) throw Error("input exceeds configured resource limit");
    const auto keys = derive_keys(key, nonce, options.profile, options.layout);
    const auto h = histogram(data);
    const auto q = exact(options.profile) ? h : shape_counts(h, budget);
    const auto g = relabel_counts(q, keys[2]);
    const auto source_domain = multinomial(h), base_domain = multinomial(g);
    if (base_domain < source_domain) throw Error("target histogram has insufficient enumerative capacity");
    const auto width = rank_length(base_domain);
    const auto plain_rank = from_int(rank_impl(data, h, source_domain), width);
    auto private_data = concat({pack_counts(h), sha256(data)});
    Info info{options.profile, options.layout, data.size(), data.size(), budget,
              Bytes(nonce.begin(), nonce.end()), {}};
    Encrypted result;
    if (options.layout == Layout::detached) {
        if (data.size() > options.max_cipher) throw Error("ciphertext exceeds configured resource limit");
        info.hist_digest = digest_counts(g);
        const auto header = info.encode();
        const auto enc_rank = aes_gcm_encrypt(keys[0], nonce.first(12), plain_rank, header);
        const BigInt value = to_int(View(enc_rank).first(width));
        const BigInt quotient = value / base_domain;
        if (quotient > 255) throw Error("internal rank spill exceeded one byte");
        result.ciphertext = unrank_impl(value % base_domain, g, base_domain);
        private_data.push_back(quotient.convert_to<Byte>());
        private_data.insert(private_data.end(), enc_rank.end() - 16, enc_rank.end());
        const auto meta = aes_gcm_encrypt(keys[1], nonce.subspan(12, 12), private_data, concat({header, result.ciphertext}));
        result.sidecar = concat({header, meta});
        if (result.sidecar->size() != sidecar_size) throw Error("internal sidecar size error");
    } else {
        if (data.empty() || base_domain == 1) throw Error("self-contained encoding has zero capacity; use detached layout or a feasible positive budget");
        const auto frame_length = header_size + embedded_meta_size + width + 16;
        const auto required_bits = 8 * frame_length + 1;
        Counts output_counts{};
        BigInt full_domain = 0;
        const auto max_factor = std::min(options.max_expansion, options.max_cipher / data.size());
        for (std::size_t factor = 2; factor <= max_factor; ++factor) {
            Counts candidate{};
            for (std::size_t i = 0; i < 256; ++i) candidate[i] = factor * g[i];
            auto capacity = multinomial(candidate);
            if (bits(capacity) > required_bits) { output_counts = candidate; full_domain = std::move(capacity); break; }
        }
        if (full_domain == 0) throw Error("self-contained encoding needs more space; raise --max-expansion / --max-output-bytes or use detached");
        info.output_size = sum_counts(output_counts); info.hist_digest = digest_counts(output_counts);
        const auto header = info.encode();
        const auto enc_rank = aes_gcm_encrypt(keys[0], nonce.first(12), plain_rank, header);
        const auto meta = aes_gcm_encrypt(keys[1], nonce.subspan(12, 12), private_data, concat({header, enc_rank}));
        const auto frame = concat({header, meta, enc_rank});
        const BigInt frame_rank = (BigInt(1) << (8 * frame.size())) | to_int(frame);
        result.ciphertext = unrank_impl(frame_rank, output_counts, full_domain);
    }
    verify_entropy_policy(h, histogram(result.ciphertext), options.profile, budget);
    result.report = report(data, result.ciphertext, info, result.sidecar);
    return result;
}

Decrypted detail::decrypt_legacy(View ciphertext, View key, const std::optional<Bytes>& sidecar,
                  std::size_t max_plain, std::size_t max_cipher) {
    if (ciphertext.size() > max_cipher) throw Error("ciphertext exceeds configured resource limit");
    if (key.size() != 32) throw Error("key file must contain exactly 32 raw bytes");
    const auto actual = histogram(ciphertext);
    Info info{};
    Bytes header, enc_rank, private_data, digest;
    Counts h{};
    std::array<Bytes, 3> keys;
    BigInt base_domain;
    if (sidecar) {
        if (sidecar->size() != sidecar_size) throw AuthenticationError("invalid sidecar length");
        header.assign(sidecar->begin(), sidecar->begin() + header_size);
        info = Info::decode(header);
        if (info.layout != Layout::detached || info.plain_size != ciphertext.size())
            throw AuthenticationError("sidecar / ciphertext mismatch");
        if (info.output_size != ciphertext.size() || info.plain_size > max_plain)
            throw Error("invalid lengths or plaintext exceeds resource limit");
        keys = detail::derive_keys(key, info.nonce, info.profile, info.layout);
        // Authenticate the detached payload before any expensive enumerative decoding.
        private_data = detail::aes_gcm_decrypt(keys[1], View(info.nonce).subspan(12, 12),
            View(*sidecar).subspan(header_size), detail::concat({header, ciphertext}));
        if (!detail::secure_equal(info.hist_digest, digest_counts(actual))) throw AuthenticationError("histogram binding mismatch");
        std::tie(h, digest) = read_private(private_data, info.plain_size);
        base_domain = multinomial(actual);
        const auto width = rank_length(base_domain);
        const auto residual = rank_impl(ciphertext, actual, base_domain);
        const BigInt value = private_data[private_base] * base_domain + residual;
        if (bits(value) > width * 8) throw AuthenticationError("invalid rank spill");
        enc_rank = detail::concat({detail::from_int(value, width), View(private_data).subspan(private_base + 1)});
    } else {
        if (ciphertext.empty()) throw AuthenticationError("empty self-contained artifact");
        const auto full_domain = multinomial(actual);
        const auto rank = rank_impl(ciphertext, actual, full_domain);
        const auto bit_length = bits(rank);
        if (!bit_length || (bit_length - 1) % 8) throw AuthenticationError("invalid self-contained frame sentinel");
        const auto length = (bit_length - 1) / 8;
        if (length < header_size + embedded_meta_size + 17) throw AuthenticationError("truncated self-contained frame");
        const auto frame = detail::from_int(rank ^ (BigInt(1) << (bit_length - 1)), length);
        header.assign(frame.begin(), frame.begin() + header_size);
        info = Info::decode(header);
        if (info.layout != Layout::embedded || info.output_size != ciphertext.size())
            throw AuthenticationError("self-contained length / layout mismatch");
        if (!info.plain_size || info.plain_size > max_plain || ciphertext.size() % info.plain_size)
            throw Error("invalid original size or plaintext exceeds resource limit");
        const auto factor = ciphertext.size() / info.plain_size;
        Counts base_counts{};
        if (factor < 2) throw AuthenticationError("invalid scaled histogram");
        for (std::size_t i = 0; i < 256; ++i) {
            if (actual[i] % factor) throw AuthenticationError("invalid scaled histogram");
            base_counts[i] = actual[i] / factor;
        }
        if (!detail::secure_equal(info.hist_digest, digest_counts(actual))) throw AuthenticationError("histogram binding mismatch");
        keys = detail::derive_keys(key, info.nonce, info.profile, info.layout);
        constexpr auto split = header_size + embedded_meta_size;
        enc_rank.assign(frame.begin() + split, frame.end());
        private_data = detail::aes_gcm_decrypt(keys[1], View(info.nonce).subspan(12, 12),
            View(frame).subspan(header_size, embedded_meta_size), detail::concat({header, enc_rank}));
        std::tie(h, digest) = read_private(private_data, info.plain_size);
        base_domain = multinomial(base_counts);
        if (enc_rank.size() != rank_length(base_domain) + 16) throw AuthenticationError("invalid encoded rank width");
    }
    const auto plain_rank = detail::aes_gcm_decrypt(keys[0], View(info.nonce).first(12), enc_rank, header);
    const auto rank = detail::to_int(plain_rank), domain = multinomial(h);
    if (domain > base_domain || rank >= domain) throw AuthenticationError("invalid source rank");
    auto data = unrank_impl(rank, h, domain);
    if (!detail::secure_equal(sha256(data), digest)) throw AuthenticationError("decoded plaintext hash mismatch");
    verify_entropy_policy(h, actual, info.profile, info.budget);
    auto result_report = report(data, ciphertext, info, sidecar);
    return {std::move(data), std::move(result_report)};
}
} // namespace ecl
