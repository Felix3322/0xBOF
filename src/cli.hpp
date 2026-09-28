#pragma once
#include <ecl/ecl.hpp>
#include <charconv>
#include <map>
#include <set>
#include <string_view>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace ecl::cli {
inline std::filesystem::path path(const std::string& text) {
    return std::filesystem::u8path(text);
}
inline std::string path_utf8(const std::filesystem::path& value) {
    const auto text = value.u8string();
    return std::string(text.begin(), text.end());
}
inline std::size_t positive(const std::string& value) {
    std::size_t n = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), n);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !n)
        throw Error("expected a positive integer");
    return n;
}
struct Arguments {
    std::vector<std::string> positional;
    std::map<std::string, std::string> values;
    std::set<std::string> flags;
    Arguments(const std::vector<std::string>& args, const std::set<std::string>& value_names,
              const std::set<std::string>& flag_names) {
        bool literals = false;
        for (std::size_t i = 0; i < args.size(); ++i) {
            auto arg = args[i];
            if (!literals && arg == "--") { literals = true; continue; }
            if (!literals && arg.starts_with("--")) {
                const auto equals = arg.find('=');
                const auto name = arg.substr(0, equals);
                if (values.contains(name) || flags.contains(name)) throw Error("duplicate option: " + name);
                if (flag_names.contains(name) && equals == std::string::npos) flags.insert(name);
                else if (value_names.contains(name)) {
                    if (equals != std::string::npos) values[name] = arg.substr(equals + 1);
                    else {
                        if (++i == args.size() || args[i].starts_with("--")) throw Error("missing value for " + name);
                        values[name] = args[i];
                    }
                } else throw Error("unknown option: " + name);
            } else positional.push_back(arg);
        }
    }
    std::string get(const std::string& name, const std::string& fallback = "") const {
        const auto found = values.find(name);
        return found == values.end() ? fallback : found->second;
    }
    std::string required(const std::string& name) const {
        const auto value = get(name);
        if (value.empty()) throw Error("required option: " + name);
        return value;
    }
    std::size_t number(const std::string& name, std::size_t fallback) const {
        return values.contains(name) ? positive(get(name)) : fallback;
    }
};
inline Bytes encoded(const std::string& text) { return Bytes(text.begin(), text.end()); }
#ifdef _WIN32
inline std::vector<std::string> arguments(int argc, wchar_t** argv) {
    std::vector<std::string> result;
    for (int i = 1; i < argc; ++i) {
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
        if (!size) throw Error("invalid command-line encoding");
        std::string value(static_cast<std::size_t>(size), '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, value.data(), size, nullptr, nullptr))
            throw Error("cannot convert command line to UTF-8");
        value.pop_back(); result.push_back(std::move(value));
    }
    return result;
}
#else
inline std::vector<std::string> arguments(int argc, char** argv) {
    return {argv + 1, argv + argc};
}
#endif
} // namespace ecl::cli
