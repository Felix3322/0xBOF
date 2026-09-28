# 0xBOF C++ implementation and file format

0xBOF 1.0.0 is a C++20 application and library. The on-disk format is `ECLAB001`, format version 1. This document describes the current implementation.

Two profiles are supported. Profile 1 shapes the output histogram within a caller-selected entropy budget. Profile 2 preserves the sorted normalized histogram exactly and requires a zero budget. The profiles work with either detached or embedded storage.

Budget shaping transfers counts from high-frequency bins to low-frequency bins, breaking ties by byte value. The final policy check uses 100-digit decimal arithmetic. The exact profile checks an integer histogram certificate without floating point tolerance.

The 80-byte authenticated header contains magic and format version, profile, layout, plaintext and output lengths, budget, nonce, and output-histogram digest. AES-256-GCM authenticates the header and payload. HKDF-SHA256 derives separate keys for rank encryption, private metadata, and histogram relabeling. Detached mode stores private metadata in a fixed 2,213-byte sidecar. Embedded mode encodes the authenticated record in a single file and scales the histogram by an integer factor.

Rank/unrank use exact multinomial arithmetic and a Fenwick tree. The private record contains the original histogram and SHA-256 digest; decryption authenticates metadata before reconstructing plaintext and verifies the digest afterward.

The default file-size limit is unlimited; explicit limits remain available through the CLI and library. Enumerative operations can require significant compute and memory for large files.

The composition has not received an independent cryptographic audit. Entropy constraints cover the whole main output, not every window, and frequency distributions and lengths can leak information. Authentication does not provide replay protection or key rotation. The tool does not execute files or install a runtime loader.

Library references: [OpenSSL EVP](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/), [HKDF](https://docs.openssl.org/3.5/man3/EVP_PKEY_CTX_set_hkdf_md/), and [Boost.Multiprecision](https://www.boost.org/library/latest/multiprecision/).
