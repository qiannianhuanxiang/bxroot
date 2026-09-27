# 更新日志

本项目遵循语义化版本。日期为 UTC。

## v0.1.3

**主题：Android app 沙箱打通 + DNS/网络可用 + 功能扩展**

由 Termux 真机爆破测试驱动的一轮收敛，31 项真机用例全绿（vivo Android 16 /
kernel 6.1.145 / app seccomp 沙箱，launcher+LD_PRELOAD 路径）。

### 修复
- **DNS/网络解析（path-relay）**：glibc resolver 经 `_IO_fopen→_IO_file_open→__open`
  最终**内联 svc openat** 发出未翻译的 guest 路径 `/etc/resolv.conf`，库内 `bl`
  直跳不经 PLT/GOT/导出符号，符号钩子与 syscall 钩子全拦不到 → 内核按真实根
  解析 → 无 nameserver → `TEMP_FAIL`。新增 livepatch 第四部分 path-relay：把 libc
  里 openat(56) 的内联 svc（8 站点）改写成 `bl` 到翻译桩，桩里对绝对路径调
  `bxroot_translate_path` 加 rootfs 前缀再发裸 svc。带线程局部重入守卫、
  fail-open、bl 可达性检查、独立开关 `BXROOT_NO_PATHRELAY`。`getaddrinfo`/
  `gethostbyname`/`getent -s dns` 现全部可用。
- **statx AT_EMPTY_PATH**：`statx(fd,"",AT_EMPTY_PATH)` 作用于 fd 自身，空串被误
  判为相对路径 → `bxroot_absolutize("")`→`"cwd/"`，把对 fd 的 stat 误导到 CWD。
  修：空串既不绝对化也不翻译，按 fd 语义处理。
- **沙箱逃逸（BXR-ESC-4）**：相对 `..` 与 `*at` dirfd 相对 `..` 逐组件夹紧。
- **fakeroot chown 记账（BXR-FR-1）**：路径/fd chown 同时按 inode 记账，stat 家族
  读得回属主。
- **fakeroot 降权族（BXR-FR-2）**：语义对齐官方基线（146 组 setter 序列，
  51→0 mismatch）。
- **livepatch**：静态链接 guest 主映像扫描、扫描窗口中断判据收紧 + 对抗性审计。

### 新特性
- **任意身份映射**：`-i <uid>:<gid>` 支持任意 uid:gid（不再限于 0:0）。
- **只读 bind**：`-b host:guest:ro`，写入返回 EROFS。
- **/dev/shm**：提供可用的 POSIX 共享内存（shm_open/sem_open/named-sem），
  Python `multiprocessing` 可用。
- **livepatch 运行期指令扫描**：中和 set_robust_list(99)/rseq(293)，覆盖任意
  glibc 版本（不再依赖版本表）。
- **Android app 沙箱启动链**：用户态 exec 加载器 `ulx` + 早期 SIGSYS 处理器。

### 文档
- 新增 [`docs/竞品对标分析.md`](docs/竞品对标分析.md)：对标 proot / proot-distro /
  fakechroot / fakeroot·pseudo / bubblewrap，含能力矩阵与带优先级建议。

## v0.1.2

**主题：符号链接解析族收敛。** 裸 syscall 层三层解析、相对路径绝对化、
O_NOFOLLOW 双语义、errno 契约、16KB 页对齐（Android 15+ 内核要求）。
作为第三运行时接入 DSHA。

## v0.1.1

早期迭代（见 git 历史）。

## v0.1.0

首个可用版本。
