# 0xBOF

0xBOF is a C++20 file-encryption tool and library with whole-file byte-entropy constraints.

**1.0.1** adds shared public entropy classes and privacy-preserving ECLAB002 records. The Windows x64 Release build and native test suite pass. Published 1.0.0 binaries do not implement the behavior described below.

## Shared distribution profiles

| Profile | Public template | Entropy policy |
| --- | --- | --- |
| 1 | Automatically selected from a fixed length/budget grid, or supplied with `--template` | `0 <= H(output) - H(input) <= budget`; default budget 0.25 bits/byte |
| 2 | Supplied with `--template` | Exactly equal Shannon entropy, checked with integer arithmetic |

A class shares its complete output histogram and padded authenticated-record length. The original histogram and permutation rank are encrypted together. Class selection does not shape an individual file's frequency spectrum. There is no fallback to the old per-file histogram when a public template cannot cover an input.

An explicit template is a public JSON document with `format: "0xBOF-template-v1"` and exactly 256 unsigned 64-bit integer `counts`. Choose it independently of individual secret files and reuse it for the intended class. The program can check entropy and length, but cannot prove that a user-provided template was chosen independently.

Profile 2 checks equality of `product(c^c)` at the same original length. Different histograms can therefore share a strict class. It does not provide a general search over all exact-entropy histograms: an appropriate shared template must be supplied. Profile 1 with a zero budget has the same requirement.

## Usage

```powershell
.\0xbof.exe keygen secret.key
.\0xbof.exe encrypt input.bin output.ecl --key-file secret.key --profile 1 --budget 0.25
.\0xbof.exe decrypt output.ecl restored.bin --key-file secret.key
```

Create a reusable template for 4,096-byte inputs. Its actual entropy is at most the requested target; integer counts do not realize every decimal entropy exactly.

```powershell
.\0xbof.exe template shared.json --bytes 4096 --entropy 5.5
.\0xbof.exe encrypt input.bin output.ecl --key-file secret.key --profile 1 --budget 0.25 --template shared.json
```

For strict mode, use a matching public template. The included eight-byte example supports both frequency shapes `[4,1,1,1,1]` and `[2,2,2,2]`, whose entropy is exactly 2 bits/byte:

```powershell
.\0xbof.exe encrypt eight-bytes.bin exact.ecl --key-file secret.key --profile 2 --template examples/templates/exact-eight-bytes.json
```

The default `detached` layout keeps the main ciphertext the same byte length as the input and requires a `.eclmeta` sidecar. Sidecar length is now variable across public classes; it is constant within a class.

```powershell
.\0xbof.exe encrypt input.bin self.ecl --key-file secret.key --profile 1 --budget 0.25 --layout embedded
.\0xbof.exe decrypt self.ecl restored.bin --key-file secret.key --layout embedded
```

Embedded mode scales the public template by the smallest integer factor with sufficient capacity for the complete authenticated record. The choice depends on the public class, not the source histogram or random ciphertext. Empty and zero-entropy templates have no embedded capacity; use detached mode. `--max-expansion` defaults to 64.

There is no default file-byte limit. Optional `--max-bytes`, `--max-output-bytes` and `--max-metadata-bytes` constrain a particular operation. Data and large integers remain memory-resident, and enumerative coding has substantial superlinear cost. Removing the size cap does not make large files inexpensive.

## Privacy and reports

Normal encryption/decryption output and `--report PATH` contain public parameters only. They omit the plaintext SHA-256, exact original entropy, entropy delta, filenames and elapsed time. `--diagnostics PATH` explicitly writes sensitive diagnostic details to a separate file; these details are never added to standard output. `stats` displays length and entropy; add `--sha256` to request a digest.

File length and the chosen public class remain visible. Strict entropy constraints expose original entropy; budget constraints expose an interval. A class may still contain only one plausible real-world candidate. Choosing a template per secret file can reintroduce fingerprint leakage. This custom composition has not received an independent security audit.

## Format and compatibility

New encryption writes `ECLAB002`. It uses OpenSSL AES-256-GCM-SIV, HKDF-SHA256, fixed 1 MiB authentication chunks and an authenticator over the entire encrypted record. Detached mode additionally authenticates the transport before costly rank decoding. Random file salts are generated internally; there is no CLI nonce override.

Reading 1.0.0 `ECLAB001` artifacts remains supported for profiles 1/2 and both layouts. Decrypting a legacy artifact does not improve its original privacy properties. Old binaries cannot read the new format.

Keys are random 32-byte files. Password-based key derivation and online key services are not implemented. The tool does not execute input files or insert a runtime decryptor.

## Build

Requirements: CMake 3.24+, C++20, OpenSSL **3.2+ with AES-256-GCM-SIV enabled**, Boost 1.74+, and nlohmann/json 3.10+. The vcpkg manifest pins dependencies. The Linux CI configuration also uses vcpkg because older system OpenSSL packages do not provide GCM-SIV.

```powershell
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/src/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>'
cmake --build build --config Release --parallel
```

Linux uses the same manifest with `-G Ninja`, `-DCMAKE_BUILD_TYPE=Release` and `-DVCPKG_TARGET_TRIPLET=x64-linux`.

The native test executable covers ECLAB001 compatibility and ECLAB002 roundtrips, shared entropy classes, strict entropy policy, authentication failures, tampering and embedded transport. Windows x64 Release was built with MSVC 19.44, OpenSSL 3.6.4, Boost 1.92.0 and nlohmann/json 3.12.0; CTest passed. Linux CI and performance benchmarks have not been run for this release. The benchmark source accepts `--template`; unsupported classes are reported explicitly. Its reports deliberately include measurements of public benchmark inputs.

[Format and implementation](docs/DESIGN_CPP_zh.md) · [Implementation status](docs/VALIDATION.md)

## License

[MIT License](LICENSE). Dependencies retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
