#include "cli.hpp"
#include "internal.hpp"
#include <chrono>
#include <iostream>
#include <numeric>
#include <sstream>

namespace {
using namespace ecl;
using Clock = std::chrono::steady_clock;
double seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now() - start).count(); }
Bytes synthetic_pe() {
    Bytes p(4096);
    const auto put = [&](std::size_t offset, std::uint32_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) p[offset + i] = static_cast<Byte>(value >> (i * 8));
    };
    p[0] = 'M'; p[1] = 'Z'; put(0x3c, 128, 4); p[128] = 'P'; p[129] = 'E';
    put(132, 0x8664, 2); put(134, 1, 2); put(148, 240, 2); put(150, 0x22, 2); put(152, 0x20b, 2);
    const std::string section = ".text";
    std::copy(section.begin(), section.end(), p.begin() + 392);
    put(400, 3584, 4); put(404, 4096, 4); put(408, 3584, 4); put(412, 512, 4);
    for (std::size_t i = 512; i < p.size(); ++i) p[i] = static_cast<Byte>(i);
    return p;
}
int run(const std::vector<std::string>& argv) {
    if (argv.empty() || argv[0] == "--help") {
        std::cout << "0xBOF benchmark " << version << "\n"
            "Usage: 0xbof-benchmark (--input FILE | --synthetic) --output-dir DIR [--template PATH]\n"
            "PUBLIC TEST KEY ONLY. Use only public, non-sensitive inputs.\n"
            "Writes benchmark.json and benchmark.csv without overwriting existing results.\n";
        return 0;
    }
    cli::Arguments args(argv, {"--input", "--output-dir", "--template"}, {"--synthetic"});
    if (!args.positional.empty() || args.values.contains("--input") == args.flags.contains("--synthetic"))
        throw Error("select exactly one of --input or --synthetic");
    const auto out = cli::path(args.required("--output-dir"));
    const auto json_path = out / "benchmark.json", csv_path = out / "benchmark.csv";
    if (std::filesystem::exists(json_path) || std::filesystem::exists(csv_path)) throw Error("benchmark output already exists");
    const bool synthetic = args.flags.contains("--synthetic");
    const auto data = synthetic ? synthetic_pe() : read_limited(cli::path(args.required("--input")), default_max_plain);
    Bytes key(32); std::iota(key.begin(), key.end(), Byte(0)); // Public test key.
    Json pe = nullptr;
    try { pe = check_pe(data); } catch (const Error&) {}
    Json rows = Json::array();
    std::optional<Counts> shared;
    if (args.values.contains("--template")) {
        const auto raw = read_limited(cli::path(args.required("--template")), 64 * 1024);
        shared = parse_public_template(Json::parse(raw.begin(), raw.end()));
    }
    for (int profile = 1; profile <= 2; ++profile) {
        for (auto layout : {Layout::detached, Layout::embedded}) {
            Options options;
            options.profile = profile; options.layout = layout;
            options.budget = profile == 2 ? "0" : "0.25";
            options.public_template = shared;
            std::optional<Encrypted> encrypted;
            const auto start = Clock::now();
            try { encrypted = encrypt(data, key, options); }
            catch (const Error& error) {
                rows.push_back({{"profile", profile}, {"layout", layout == Layout::detached ? "detached" : "embedded"},
                                {"status", "unsupported"}, {"reason", error.what()}});
                continue;
            }
            auto row = encrypted->report;
            row["plain_bytes"] = data.size();
            row["plain_entropy_bits_per_byte"] = entropy(histogram(data));
            row["entropy_delta_bits_per_byte"] = entropy(histogram(encrypted->ciphertext)) - entropy(histogram(data));
            row["encrypt_seconds"] = seconds(start);
            const auto decrypt_start = Clock::now();
            const auto recovered = decrypt(encrypted->ciphertext, key, encrypted->sidecar);
            row["decrypt_seconds"] = seconds(decrypt_start);
            if (recovered.plaintext != data) throw Error("benchmark roundtrip mismatch");
            row["roundtrip_equal"] = true; row["status"] = "pass";
            rows.push_back(std::move(row));
        }
    }
    Json curve = Json::array();
    for (const auto* budget : {"0", "0.05", "0.1", "0.25", "0.5", "1.0"}) {
        Options options; options.profile = 1; options.budget = budget;
        options.public_template = shared;
        std::optional<Encrypted> encrypted;
        try { encrypted = encrypt(data, key, options); }
        catch (const Error& error) {
            curve.push_back({{"budget", budget}, {"status", "unsupported"}, {"reason", error.what()}});
            continue;
        }
        if (decrypt(encrypted->ciphertext, key, encrypted->sidecar).plaintext != data)
            throw Error("budget curve roundtrip mismatch");
        curve.push_back({{"budget", encrypted->report["budget_bits_per_byte"]}, {"status", "pass"},
                         {"entropy", encrypted->report["cipher_entropy_bits_per_byte"]},
                         {"delta", entropy(histogram(encrypted->ciphertext)) - entropy(histogram(data))}});
    }
    Bytes nonce(12); std::iota(nonce.begin(), nonce.end(), Byte(0));
    const auto baseline = detail::aes_gcm_encrypt(key, nonce, data, cli::encoded("ECL benchmark baseline"));
    auto caesar = data; for (auto& byte : caesar) byte = static_cast<Byte>(byte + 37);
    Json report{
        {"project", "0xBOF"}, {"version", version},
        {"sample", {{"filename", synthetic ? "synthetic-pe32plus.bin" : cli::path_utf8(cli::path(args.get("--input")).filename())},
                    {"bytes", data.size()}, {"sha256", hex(sha256(data))}, {"pe_structure", pe},
                    {"provenance", synthetic ? "structural fixture; not a compiler-produced executable" : "explicit local input"}}},
        {"repetitions", 1}, {"timing_scope", "single local wall-clock observation; not a performance guarantee"},
        {"baselines", {{"plaintext_H", entropy(histogram(data))}, {"caesar_plus37_H", entropy(histogram(caesar))},
                       {"aes256gcm_data_only_H", entropy(histogram(View(baseline).first(data.size())))}}},
        {"rows", rows}, {"budget_curve", curve},
        {"security_note", "PUBLIC TEST KEY; functional measurements do not establish resistance to cryptanalysis"}};
    const std::vector<std::string> fields{"profile", "layout", "status", "plain_bytes", "cipher_bytes",
        "external_metadata_bytes", "total_storage_bytes", "plain_entropy_bits_per_byte", "cipher_entropy_bits_per_byte",
        "entropy_delta_bits_per_byte", "budget_bits_per_byte", "encrypt_seconds", "decrypt_seconds", "roundtrip_equal"};
    std::ostringstream csv;
    for (std::size_t i = 0; i < fields.size(); ++i) csv << (i ? "," : "") << fields[i];
    csv << '\n';
    for (const auto& row : rows) {
        for (std::size_t i = 0; i < fields.size(); ++i) {
            if (i) csv << ',';
            if (row.contains(fields[i])) csv << row[fields[i]].dump();
        }
        csv << '\n';
    }
    atomic_write(json_path, cli::encoded(report.dump(2) + "\n"));
    atomic_write(csv_path, cli::encoded(csv.str()));
    std::cout << report.dump(2) << '\n';
    return 0;
}
}
#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
#else
int main(int argc, char** argv) {
#endif
    try { return run(ecl::cli::arguments(argc, argv)); }
    catch (const std::exception& error) { std::cerr << "ERROR: " << error.what() << '\n'; return 2; }
}
