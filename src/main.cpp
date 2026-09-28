#include "cli.hpp"
#include "internal.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>

namespace {
using namespace ecl;
void help() {
    std::cout << "0xBOF " << version << " - shared-distribution file encryption (ECLAB002)\n"
        "Usage:\n"
        "  0xbof keygen KEY\n"
        "  0xbof template OUTPUT.json --bytes N --entropy TARGET\n"
        "  0xbof encrypt INPUT OUTPUT --key-file KEY --profile 1|2 [OPTIONS]\n"
        "  0xbof decrypt INPUT OUTPUT --key-file KEY [OPTIONS]\n"
        "  0xbof stats INPUT [--max-bytes N] [--sha256]\n"
        "Options:\n"
        "  --template PATH             Shared public template JSON; required for profile 2\n"
        "  --budget DECIMAL            Profile 1 default 0.25; profile 2 requires 0\n"
        "  --layout detached|embedded  Default: detached; embedded has no sidecar\n"
        "  --metadata PATH             Default: CIPHERTEXT.eclmeta\n"
        "  --max-bytes N               Optional input byte limit (default: unlimited)\n"
        "  --max-output-bytes N        Optional output byte limit (default: unlimited)\n"
        "  --max-metadata-bytes N      Optional sidecar byte limit\n"
        "  --max-expansion N           Embedded expansion factor limit, default 64\n"
        "  --report PATH               Save public report; no plaintext fingerprint\n"
        "  --diagnostics PATH          Explicit sensitive report: plaintext SHA-256/entropy/timing\n"
        "  --force                     Replace outputs; never input/key/template\n"
        "Profiles: 1 shared entropy budget, 2 exact entropy with a shared template.\n"
        "Profile 1 without --template selects from a public length/budget grid.\n"
        "Zero budget always requires --template. Uncovered classes are rejected.\n"
        "Reads ECLAB001 for compatibility; new encryption always writes ECLAB002.\n";
}
Counts load_template(const std::filesystem::path& path) {
    const auto bytes = read_limited(path, 64 * 1024);
    return parse_public_template(Json::parse(bytes.begin(), bytes.end()));
}
std::uint64_t unsigned_integer(const std::string& value) {
    std::uint64_t n = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), n);
    if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw Error("expected an unsigned 64-bit integer");
    return n;
}
int run(std::vector<std::string> argv) {
    if (argv.empty() || argv[0] == "--help" || argv[0] == "-h") { help(); return 0; }
    if (argv[0] == "--version" && argv.size() == 1) { std::cout << version << '\n'; return 0; }
    const auto command = argv.front(); argv.erase(argv.begin());
    if (argv.size() == 1 && (argv[0] == "--help" || argv[0] == "-h")) { help(); return 0; }
    if (command == "keygen") {
        cli::Arguments args(argv, {}, {});
        if (args.positional.size() != 1) throw Error("keygen requires one output path");
        auto key = random_bytes(32);
        detail::WipeBytes wipe(key);
        atomic_write(cli::path(args.positional[0]), key);
        std::cout << "Created 32-byte key; keep it private.\n";
        return 0;
    }
    if (command == "template") {
        cli::Arguments args(argv, {"--bytes", "--entropy"}, {"--force"});
        if (args.positional.size() != 1) throw Error("template requires one output JSON path");
        const auto q = make_public_template(unsigned_integer(args.required("--bytes")), args.required("--entropy"));
        const auto document = public_template_document(q);
        atomic_write(cli::path(args.positional[0]), cli::encoded(document.dump(2) + "\n"),
                     args.flags.contains("--force"));
        std::cout << "Created public template. Reuse it for all members of the intended class.\n";
        return 0;
    }
    if (command == "stats") {
        cli::Arguments args(argv, {"--max-bytes"}, {"--sha256"});
        if (args.positional.size() != 1) throw Error("stats requires one input path");
        auto data = read_limited(cli::path(args.positional[0]), args.number("--max-bytes", default_max_plain));
        detail::WipeBytes wipe(data);
        Json result{{"bytes", data.size()}, {"shannon_bits_per_byte", entropy(histogram(data))}};
        if (args.flags.contains("--sha256")) result["sha256"] = hex(sha256(data));
        std::cout << result.dump(2) << '\n';
        return 0;
    }
    const bool encrypting = command == "encrypt";
    if (!encrypting && command != "decrypt") throw Error("unknown command: " + command);
    std::set<std::string> values{"--key-file", "--layout", "--metadata", "--max-bytes",
        "--max-output-bytes", "--max-metadata-bytes", "--report", "--diagnostics"};
    if (encrypting) values.insert({"--profile", "--budget", "--max-expansion", "--template"});
    cli::Arguments args(argv, values, {"--force"});
    if (args.positional.size() != 2) throw Error("encrypt/decrypt require input and output paths");
    const auto layout = args.get("--layout", "detached");
    if (layout != "detached" && layout != "embedded") throw Error("layout must be detached or embedded");
    if (layout == "embedded" && (args.values.contains("--metadata") || args.values.contains("--max-metadata-bytes")))
        throw Error("embedded layout does not use external metadata");
    const auto input = cli::path(args.positional[0]), output = cli::path(args.positional[1]);
    const auto key_path = cli::path(args.required("--key-file"));
    std::optional<std::filesystem::path> meta_path, report_path, diagnostic_path, template_path;
    if (layout == "detached") {
        if (args.values.contains("--metadata")) meta_path = cli::path(args.required("--metadata"));
        else { auto stem = encrypting ? output : input; stem += ".eclmeta"; meta_path = stem; }
    }
    if (args.values.contains("--report")) report_path = cli::path(args.required("--report"));
    if (args.values.contains("--diagnostics")) diagnostic_path = cli::path(args.required("--diagnostics"));
    if (args.values.contains("--template")) template_path = cli::path(args.required("--template"));
    std::vector<std::filesystem::path> paths{input, output, key_path}, outputs{output};
    if (meta_path) { paths.push_back(*meta_path); if (encrypting) outputs.push_back(*meta_path); }
    if (report_path) { paths.push_back(*report_path); outputs.push_back(*report_path); }
    if (diagnostic_path) { paths.push_back(*diagnostic_path); outputs.push_back(*diagnostic_path); }
    if (template_path) paths.push_back(*template_path);
    ensure_distinct(paths);
    const bool force = args.flags.contains("--force");
    if (!force) for (const auto& path : outputs)
        if (std::filesystem::exists(std::filesystem::symlink_status(path)))
            throw Error("refusing to overwrite an existing output");
    auto key = read_limited(key_path, 32);
    detail::WipeBytes wipe_key(key);
    const auto max_input = args.number("--max-bytes", encrypting ? default_max_plain : default_max_cipher);
    const auto max_output = args.number("--max-output-bytes", encrypting ? default_max_cipher : default_max_plain);
    auto data = read_limited(input, max_input);
    detail::WipeBytes wipe_data(data);
    const auto start = std::chrono::steady_clock::now();
    Bytes result;
    detail::WipeBytes wipe_result(result);
    std::optional<Bytes> output_metadata;
    Json report;
    if (encrypting) {
        Options options;
        const auto profile = cli::positive(args.required("--profile"));
        if (profile > 2) throw Error("profile must be 1 or 2");
        options.profile = static_cast<int>(profile);
        options.budget = args.get("--budget", profile == 1 ? "0.25" : "0");
        options.layout = layout == "detached" ? Layout::detached : Layout::embedded;
        options.max_plain = max_input; options.max_cipher = max_output;
        options.max_expansion = args.number("--max-expansion", 64);
        if (template_path) options.public_template = load_template(*template_path);
        auto encrypted = encrypt(data, key, options);
        if (encrypted.sidecar && encrypted.sidecar->size() > args.number("--max-metadata-bytes", default_max_cipher))
            throw Error("sidecar exceeds configured metadata limit");
        output_metadata = std::move(encrypted.sidecar);
        result = std::move(encrypted.ciphertext); report = std::move(encrypted.report);
    } else {
        std::optional<Bytes> metadata;
        if (meta_path) metadata = read_limited(*meta_path,
            std::min(max_metadata_size(data.size()), args.number("--max-metadata-bytes", default_max_cipher)));
        auto decrypted = decrypt(data, key, metadata, max_output, max_input);
        result = std::move(decrypted.plaintext); report = std::move(decrypted.report);
    }
    report["operation"] = command;
    Json diagnostics;
    if (diagnostic_path) {
        const View plain = encrypting ? View(data) : View(result);
        const View cipher = encrypting ? View(result) : View(data);
        diagnostics = report;
        diagnostics["sensitive"] = true;
        diagnostics["plain_bytes"] = plain.size();
        diagnostics["plain_sha256"] = hex(sha256(plain));
        diagnostics["plain_entropy_bits_per_byte"] = entropy(histogram(plain));
        diagnostics["entropy_delta_bits_per_byte"] = entropy(histogram(cipher)) - entropy(histogram(plain));
        diagnostics["elapsed_seconds"] = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    }
    // A file pair cannot be one atomic transaction. A crash may leave an orphan sidecar.
    if (meta_path && output_metadata) atomic_write(*meta_path, *output_metadata, force);
    atomic_write(output, result, force);
    const auto json = report.dump(2) + "\n";
    if (report_path) atomic_write(*report_path, cli::encoded(json), force);
    if (diagnostic_path) atomic_write(*diagnostic_path, cli::encoded(diagnostics.dump(2) + "\n"), force);
    std::cout << json;
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
