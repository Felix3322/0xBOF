# 0xBOF 1.0.1 验证记录

## Windows x64 Release

- 编译器：MSVC 19.44.35207，Visual Studio 2022 Build Tools
- 依赖：OpenSSL 3.6.4、Boost 1.92.0、nlohmann/json 3.12.0
- 构建：CMake configure 成功；Release 配置下 `ecl_core`、`0xbof.exe`、`0xbof-benchmark.exe` 与 `ecl_tests.exe` 均构建成功。
- 测试：CTest 1/1 通过。原生测试程序的 26 组用例全部通过，含 1,093 个穷举 rank、80 个随机 rank、ECLAB001 已知向量和兼容性，以及 ECLAB002 共享熵类别、严格熵策略、认证失败与拒绝、嵌入式传输往返。
- CLI 版本检查：`0xbof.exe --version` 输出 `1.0.1`。

## 尚未验证

- Linux 构建及 Linux CI 尚未运行。
- 性能基准尚未运行；大文件和 1 MiB 分块边界尚未专项测量。
- 未做独立密码学或隐私审计。
- 未生成 Windows 安装程序；发布包仅包含可执行文件、文档、许可证及 SHA-256 清单。

构建和测试使用仓库外的本地目录 `work/build-0xbof-1.0.0`；该目录仅是复用的构建缓存路径，不表示产物版本。发行清单中的二进制哈希按 1.0.1 Release 产物记录。
