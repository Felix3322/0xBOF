#include <ecl/ecl.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <limits>
#include <system_error>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace ecl {
namespace fs = std::filesystem;
Bytes read_limited(const fs::path& path, std::size_t limit) {
    if (!fs::is_regular_file(path)) throw Error("input must be a regular file");
    if (fs::file_size(path) > limit) throw Error("file exceeds configured resource limit");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Error("cannot open input file");
    Bytes result;
    std::array<char, 65536> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto n = static_cast<std::size_t>(input.gcount());
        if (n > limit - result.size()) throw Error("file exceeds configured resource limit");
        result.insert(result.end(), buffer.begin(), buffer.begin() + n);
    }
    if (!input.eof()) throw Error("file read failed");
    return result;
}
void ensure_distinct(const std::vector<fs::path>& paths) {
    for (std::size_t i = 0; i < paths.size(); ++i) {
        const auto a = fs::weakly_canonical(fs::absolute(paths[i]));
        for (std::size_t j = i + 1; j < paths.size(); ++j) {
            const auto b = fs::weakly_canonical(fs::absolute(paths[j]));
#ifdef _WIN32
            const bool same_name = CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
#else
            const bool same_name = a == b;
#endif
            if (same_name || (fs::exists(paths[i]) && fs::exists(paths[j]) && fs::equivalent(paths[i], paths[j])))
                throw Error("input, output, metadata, key, and report paths must be different");
        }
    }
}
void atomic_write(const fs::path& path, View data, bool force) {
    const auto parent = path.has_parent_path() ? path.parent_path() : fs::path(".");
    fs::create_directories(parent);
    const auto temporary = parent / (".0xbof-" + hex(random_bytes(16)) + ".tmp");
    // Exclusive creation prevents following a pre-existing symlink or truncating another file.
#ifdef _WIN32
    HANDLE handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw Error("cannot create temporary output");
    try {
        std::size_t pos = 0;
        while (pos < data.size()) {
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - pos, 1U << 30));
            DWORD written = 0;
            if (!WriteFile(handle, data.data() + pos, chunk, &written, nullptr) || written != chunk)
                throw Error("output write failed");
            pos += written;
        }
        if (!FlushFileBuffers(handle)) throw Error("output flush failed");
        const auto closed = CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
        if (!closed) throw Error("output close failed");
        if (force) {
            if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw Error("cannot atomically replace output");
        } else {
            if (!CreateHardLinkW(path.c_str(), temporary.c_str(), nullptr))
                throw Error("refusing overwrite or filesystem lacks hard-link support");
        }
    } catch (...) {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        DeleteFileW(temporary.c_str());
        throw;
    }
    DeleteFileW(temporary.c_str());
#else
    int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) throw Error("cannot create temporary output");
    try {
        std::size_t pos = 0;
        while (pos < data.size()) {
            const auto chunk = std::min<std::size_t>(data.size() - pos, 1U << 30);
            const auto written = ::write(fd, data.data() + pos, chunk);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw Error("output write failed");
            pos += static_cast<std::size_t>(written);
        }
        if (::fsync(fd) != 0) throw Error("output flush failed");
        const auto closed = ::close(fd); fd = -1;
        if (closed != 0) throw Error("output close failed");
        if (force) {
            if (::rename(temporary.c_str(), path.c_str()) != 0) throw Error("cannot atomically replace output");
        } else {
            if (::link(temporary.c_str(), path.c_str()) != 0)
                throw Error("refusing overwrite or filesystem lacks hard-link support");
        }
    } catch (...) {
        if (fd >= 0) ::close(fd);
        ::unlink(temporary.c_str());
        throw;
    }
    ::unlink(temporary.c_str());
#endif
}
} // namespace ecl
