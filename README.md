# 0xBOF

[![C++ build and tests](https://github.com/Felix3322/0xBOF/actions/workflows/ci.yml/badge.svg)](https://github.com/Felix3322/0xBOF/actions/workflows/ci.yml)

0xBOF is a C++20 tool and library for entropy-constrained file encryption. It uses OpenSSL AES-256-GCM, HKDF-SHA256, and enumerative coding in the `ECLAB001` file format.

This is experimental cryptographic software and has not received an independent security audit. It constrains whole-file byte Shannon entropy, not entropy in every window. Frequency distributions and file lengths can reveal information. Ciphertext is not an executable, and the tool does not execute inputs or add runtime decryption code.

## Download

[GitHub Releases](https://github.com/Felix3322/0xBOF/releases) provides Windows x64 binaries and source archives. The Windows ZIP contains `0xbof.exe`, `0xbof-benchmark.exe`, the MIT license, dependency notices, and build documentation.

## Modes

| Profile | Behavior |
| --- | --- |
| 1 | Keep the output entropy increase within `--budget` (bits per byte, range 0–8). |
| 2 | Preserve the sorted normalized byte-frequency histogram exactly; requires `--budget 0`. |

Both profiles support `detached` and `embedded` layouts. The default detached layout keeps ciphertext the same size as the input and stores authenticated metadata in a 2,213-byte sidecar. Embedded mode stores the authenticated record in one file and can expand the input.

## Usage

```powershell
.\0xbof.exe keygen secret.key
.\0xbof.exe encrypt input.bin output.ecl --key-file secret.key --profile 2
.\0xbof.exe decrypt output.ecl restored.bin --key-file secret.key
.\0xbof.exe stats output.ecl
```

Keys are 32 bytes of random raw data and are not stored in ciphertext or metadata. `keygen` does not overwrite an existing file.

```powershell
.\0xbof.exe encrypt input.bin budget.ecl --key-file secret.key --profile 1 --budget 0.25
.\0xbof.exe encrypt input.bin self.ecl --key-file secret.key --profile 2 --layout embedded
.\0xbof.exe decrypt self.ecl restored.bin --key-file secret.key --layout embedded
```

File operations have no default byte limit. `--max-bytes` and `--max-output-bytes` optionally set explicit limits. Embedded mode also limits histogram expansion with `--max-expansion` (default 64). Enumerative coding has superlinear computational cost, so large files can require substantial time and memory.

Outputs are not overwritten by default. `--force` replaces output files while still rejecting aliases between input, output, key, metadata, and report paths. Authentication failures do not create or replace plaintext or reports. Operations process only explicitly named files and do not recursively scan directories.

`--report PATH` writes a JSON report containing the plaintext SHA-256; sharing a report can reveal file identity.

## Build

Requirements: CMake 3.24+, a C++20 compiler, Boost 1.74+, OpenSSL 3.0+, and nlohmann/json 3.10+. Dependency versions are pinned by the vcpkg baseline in the manifest.

### Windows / MSVC

```powershell
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/src/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>'
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
.\build\Release\0xbof.exe --version
```

### Linux / GCC

```sh
sudo apt-get install cmake ninja-build g++ libssl-dev libboost-dev nlohmann-json3-dev
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/0xbof --version
```

## Tests and benchmark

The native suite covers exhaustive and randomized enumerative coding, both entropy profiles and layouts, authentication failures, tampering, malformed inputs, resource limits, and file protection. Run it with CTest as shown above.

The benchmark emits JSON and CSV for both profiles and layouts. Use public test material only:

```powershell
.\0xbof-benchmark.exe --synthetic --output-dir benchmark-results
.\0xbof-benchmark.exe --input public-sample.bin --output-dir my-results
```

`--synthetic` uses a 4 KiB PE-shaped fixture; it does not claim to be a compiler-generated executable.

[Implementation and format](docs/DESIGN_CPP_zh.md) · [Release build notes](docs/VALIDATION.md)

## License

This project is licensed under the [MIT License](LICENSE). Third-party libraries retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
