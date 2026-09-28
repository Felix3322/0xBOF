# Third-party notices

0xBOF is licensed under MIT; see LICENSE.

The Windows release statically links or compiles code from these dependencies:

| Dependency | Release build | License |
| --- | --- | --- |
| OpenSSL | 3.6.4 | Apache License 2.0 |
| Boost (Multiprecision and required headers) | 1.92.0 | Boost Software License 1.0; additional notices in package copyrights |
| nlohmann/json | 3.12.0 | MIT; bundled third-party notices included |

Their package copyright and license files are preserved in `licenses/` and distributed with the binaries. These libraries retain their own licenses; the project's MIT license does not replace them.

Windows dependencies use vcpkg baseline `07f4812200df3d3c931c0c8a6081d3b21fe2bf9f`. Linux builds use compatible system development packages.
