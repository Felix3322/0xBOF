# 0xBOF 1.0.0 release notes

This release supports two entropy profiles: a caller-bounded entropy increase and exact preservation of the normalized byte-frequency histogram. Each profile supports detached and embedded layouts. File operations have no default byte limit; callers may set limits explicitly.

The current source was compiled as a Windows x64 Release build with MSVC and the pinned vcpkg dependencies. The release package contains the CLI, benchmark executable, license, dependency notices, and documentation.

The native test suite was not run for this release. Earlier test and benchmark artifacts are not included in this repository.
