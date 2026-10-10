# bxroot native v3.2 security release

本版本包含 native session 安全修复：读取端现在拒绝未封印或可写的 session fd，session 必须具备 `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`。新增未封印 memfd 回归测试。

验证：

- session 回归 `372/372 PASS`（平台对 `/proc/self/fd` 的 O_RDONLY 语义差异保留 2 个 skip）
- Android arm64 `libbxroot-runtime.so`、`libbxroot-enter.so` 已重建
- DSHA APK 不包含在本 release 中，仅提供 bxroot 源码、测试和运行库

安全边界：bxroot 是用户态兼容运行时，不是 Android root，也不是安全沙箱。fakeroot 只改变 guest 视图；静态 ELF、裸 syscall 和未覆盖内核接口可能绕过部分视图。不要把不可信代码或敏感宿主目录交给 bxroot。
