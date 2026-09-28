#include "cli.hpp"
#include <chrono>
#include <iostream>

namespace {
using namespace ecl;
void help() {
    std::cout << "0xBOF " << version << " - entropy-constrained file encryption (ECLAB001)\n"
        "Usage:\n"
        "  0xbof keygen KEY\n"
        "  0xbof encrypt INPUT OUTPUT --key-file KEY --profile 1|2 [OPTIONS]\n"
        "  0xbof decrypt INPUT OUTPUT --key-file KEY [OPTIONS]\n"
        "  0xbof stats INPUT [--max-bytes N]\n"
        "Options:\n"
        "  --layout detached|embedded  Default: detached; embedded has no sidecar\n"
        "  --metadata PATH             Default: CIPHERTEXT.eclmeta\n"
        "  --budget DECIMAL            Entropy increase in [0,8], up to 12 decimals\n"
        "  --max-bytes N               Optional input size limit (default: unlimited)\n"
        "  --max-output-bytes N        Optional output size limit (default: unlimited)\n"
        "  --max-expansion N           Embedded encryption expansion limit, default 64\n"
        "  --report PATH               Save JSON report (includes plaintext SHA-256)\n"
        "  --force                     Replace outputs; never input/key\n"
        "Profiles: 1 entropy-budget, 2 exact-histogram. Profile 2 requires budget=0.\n"
        "Experimental composition; not independently audited. Ciphertext is not executable.\n";
}
int run(std::vector<std::string> argv) {
    if (argv.empty() || argv[0] == "--help" || argv[0] == "-h") { help(); return 0; }
    if (argv[0] == "--version" && argv.size() == 1) { std::cout << version << '\n'; return 0; }
    const auto command = argv.front(); argv.erase(argv.begin());
    if (argv.size() == 1 && (argv[0] == "--help" || argv[0] == "-h")) { help(); return 0; }
    if (command == "keygen") {
        cli::Arguments args(argv, {}, {});
        if (args.positional.size() != 1) throw Error("keygen requires one output path");
        atomic_write(cli::path(args.positional[0]), random_bytes(32));
        std::cout << "Created 32-byte key; keep it private.\n";
        return 0;
    }
    if (command == "stats") {
        cli::Arguments args(argv, {"--max-bytes"}, {});
        if (args.positional.size() != 1) throw Error("stats requires one input path");
        const auto data = read_limited(cli::path(args.positional[0]), args.number("--max-bytes", std::numeric_limits<std::size_t>::max()));
        std::cout << Json{{"bytes", data.size()}, {"shannon_bits_per_byte", entropy(histogram(data))},
                          {"sha256", hex(sha256(data))}}.dump(2) << '\n';
        return 0;
    }
    const bool encrypting = command == "encrypt";
    if (!encrypting && command != "decrypt") throw Error("unknown command: " + command);
    std::set<std::string> values{"--key-file", "--layout", "--metadata", "--max-bytes", "--max-output-bytes", "--report"};
    if (encrypting) values.insert({"--profile", "--budget", "--max-expansion"});
    cli::Arguments args(argv, values, {"--force"});
    if (args.positional.size() != 2) throw Error("encrypt/decrypt require input and output paths");
    const auto layout = args.get("--layout", "detached");
    if (layout != "detached" && layout != "embedded") throw Error("layout must be detached or embedded");
    if (layout == "embedded" && args.values.contains("--metadata")) throw Error("embedded layout does not use an external metadata file");
    const auto input = cli::path(args.positional[0]), output = cli::path(args.positional[1]);
    const auto key_path = cli::path(args.required("--key-file"));
    std::optional<std::filesystem::path> meta_path, report_path;
    if (layout == "detached") {
        if (args.values.contains("--metadata")) meta_path = cli::path(args.required("--metadata"));
        else { auto stem = encrypting ? output : input; stem += ".eclmeta"; meta_path = stem; }
    }
    if (args.values.contains("--report")) report_path = cli::path(args.required("--report"));
    std::vector<std::filesystem::path> paths{input, output, key_path}, outputs{output};
    if (meta_path) { paths.push_back(*meta_path); if (encrypting) outputs.push_back(*meta_path); }
    if (report_path) { paths.push_back(*report_path); outputs.push_back(*report_path); }
    ensure_distinct(paths);
    const bool force = args.flags.contains("--force");
    if (!force) for (const auto& path : outputs)
        if (std::filesystem::exists(std::filesystem::symlink_status(path))) throw Error("refusing to overwrite an existing output");
    const auto key = read_limited(key_path, 32);
    const auto max_input = args.number("--max-bytes", encrypting ? default_max_plain : default_max_cipher);
    const auto max_output = args.number("--max-output-bytes", encrypting ? default_max_cipher : default_max_plain);
    const auto data = read_limited(input, max_input);
    const auto start = std::chrono::steady_clock::now();
    Bytes result; Json report;
    if (encrypting) {
        Options options;
        const auto profile = cli::positive(args.required("--profile"));
        if (profile > 2) throw Error("profile must be 1 or 2");
        options.profile = static_cast<int>(profile);
        options.budget = args.get("--budget", "0");
        options.layout = layout == "detached" ? Layout::detached : Layout::embedded;
        options.max_plain = max_input; options.max_cipher = max_output;
        options.max_expansion = args.number("--max-expansion", 64);
        auto encrypted = encrypt(data, key, options);
        // A file pair cannot be one atomic transaction. A crash may leave an orphan sidecar.
        if (meta_path && encrypted.sidecar) atomic_write(*meta_path, *encrypted.sidecar, force);
        result = std::move(encrypted.ciphertext); report = std::move(encrypted.report);
    } else {
        std::optional<Bytes> metadata;
        if (meta_path) metadata = read_limited(*meta_path, sidecar_size);
        auto decrypted = decrypt(data, key, metadata, max_output, max_input);
        result = std::move(decrypted.plaintext); report = std::move(decrypted.report);
    }
    report["operation"] = command;
    report["elapsed_seconds"] = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    atomic_write(output, result, force);
    const auto json = report.dump(2) + "\n";
    if (report_path) atomic_write(*report_path, cli::encoded(json), force);
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
