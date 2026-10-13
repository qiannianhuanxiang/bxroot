# 更新日志

本项目遵循语义化版本。日期为 UTC。

## v0.2.4 — 2026-10-13

**主题：文档与可验证性修正，运行库行为不变。**

- `libbxroot.so -V` 此前仍打印 `0.1.4`，现与发行版本一致。v0.2.3 的 tag 与附件里的 launcher 仍显示 `0.1.4`，那是已发布产物，不改写。
- README 重构：新增快速开始（选项取自 launcher `--help`）、环境要求、安全边界、Android 集成、文档索引；长篇开发笔记迁到 [`docs/DEVELOPMENT-NOTES.md`](docs/DEVELOPMENT-NOTES.md)，内容未删减。
- 更正 README 里过时的数字：runtime 导出符号为 460 个（此前写 385）；上游 issue 回归标注为 2026-10-02 快照，未重跑。
- 新增 `test/host/bench_backends.py`：proot(ptrace) / 官方 proroot / bxroot 三后端对照基准。每项先校验操作成功，proot 须自证有 tracer，各后端 `find /usr` 条目数须一致，否则该项作废。**本版本不发布任何性能倍数**：首轮实测只有 `find /usr` 一项可信，其余因官方后端配置不对等或 runtime 版本不符而作废，修正后的脚本尚未复跑。

## v0.2.3 — 2026-10-12

**主题：SHM 生命周期硬化 + 静态 ELF 进程内执行 + SIGSYS 影子槽 + native session v3 回入口。**

本仓库发行物是源码、测试与运行库。不含 DSHA APK / DSHA 源码。

### 运行时
- **官方启动器配置块**：读取 `PROROOT_CFG_FD`（bind / `-0` / `--link2symlink`）。有配置块时不注入 `STUB_ROOTFS`。
- **进程内执行静态 ELF**（`static_exec.c`）：mmap 无 `PT_INTERP` 的目标、把路径类 `svc` 接到跳板；跳板保全 v0–v31 / NZCV，入口 `bti c`。坏 ELF 在改状态前拒绝。多线程 / ET_EXEC 冲突回退 stub-loader。
- **posix_spawn** 子进程不再继承父进程 `GUEST_EXE` / `ORIG_COMM`。
- **livepatch**：收集 libc **全部** r-x 段再扫描；版本表补丁后复位 r-x，避免把 libc 劈碎后漏掉 99/293 站点。
- **SIGSYS 影子槽**：guest 对 SIGSYS 的设置只记影子槽，runtime 处理器常驻；自发 SIGSYS 吞掉。交互 bash 不再 `rc=139/159`。
- **native session v3**：只读封印 memfd（四 seal）；`BXROOT_REENTRY` / `BXROOT_SESSION_FD` / `BXROOT_ENTER`。拒绝未封印或可写 session fd。
- **SysV SHM 硬化**：
  - 默认 profile 两个 gate 强制 0：拒绝 keyed 与 `IPC_PRIVATE` 新建；copyout 不盲发 `process_vm_writev(271)`。
  - verified profile 要求两个 gate 显式为 1，产物在 `build/verified/`，不覆盖默认 so。
  - 持久 `.claim-lock` + OFD `F_OFD_SETLK`；持久 `.id-ID` 防分配器 ABA。
  - 非等待 fork 事务门：SHM 活动时 fork 返回 `-EAGAIN`，反之亦然。raw `clone` / `_Fork` 不在保证内。
  - 官方 proroot 混合并发不协调；不是完整 Linux 延迟 `IPC_RMID`。

### 验证
- 22 编译单元零告警。
- 原生 Termux（UID 10399，`TracerPid: 0`）：copyout / claim / ID ABA / fork gate / static reset / static SHM trap（`nr=194`）/ l2s mock / l2s native 153 checks / fakeroot 协同 47 checks。
- 共存测试包（独立 applicationId，**不在本仓库**）真机：`BXROOT_REENTRY=1`、`ldconfig.real` 无 EROFS、node v24 + 4 worker、`exit 7` 透传。可与官方包同时安装运行。两个 App 都能开 ≠ SHM 混合并发已协调。

### 已知仍不宣称
- verified runtime 未作为默认 APK 部署（guest 完整过滤矩阵未用 `run-as` 扫完）。
- Docker 隔离审计环境当前不可用。
- bxroot 不是安全沙箱。

## v0.2.2 / v0.2.1 / v0.2.0

native session v3 系列（tag `v0.2.2-native-v3.2` 等）。只读封印 session fd、guest 回入口、Android arm64 核心矩阵。详见 [`docs/RELEASE-v0.2.2-native-v3.2.md`](docs/RELEASE-v0.2.2-native-v3.2.md) 与 [`docs/ANDROID-NATIVE-V3-RELEASE.md`](docs/ANDROID-NATIVE-V3-RELEASE.md)。

## v0.1.4

**主题：爆破压测驱动的一轮缺陷收敛（7 类真缺陷）+ 真实项目端到端验证**

以"基于 bxroot 做项目、直接爆破玩到崩"为目标，5 路子代理在 bxroot 运行时里
对照官方基线（`/tmp/off-rt.so`）压测（编译型负载 / 文件系统折磨 / 进程·exec
风暴 / 真实应用端到端 / 网络·DNS），逐条以基线区分"bxroot 缺陷"与"环境限制"，
共修复 7 类"bxroot 错、基线对"的缺陷，全部附带判别力回归并接入 RUN_ALL。

### 修复
- **statx(fd, NULL, AT_EMPTY_PATH) 整进程 SIGSEGV**：glibc `<bits/statx-generic.h>`
  的 `__nonnull((2,5))` 让编译器认定钩子体内 `path` 恒非空、删掉所有 `path!=NULL`
  守卫（`-fno-delete-null-pointer-checks` 也挡不住这个基于 attribute 的假设），
  合法的 NULL 调用（作用于 fd 自身）在 runtime 内解空指针。修：钩子入口用
  `volatile` 洗掉 nonnull 假设，NULL 守卫恢复 → 返回 EFAULT。官方基线本就返回
  EFAULT。回归 `RUN_STATX_NULL.sh`。
- **只读 bind 被 fd 版写钩子击穿并真写穿宿主**：路径版 `open`/`truncate`/`chmod`
  正确 EROFS，但 `fchmod`/`fchown`/`ftruncate`/`futimes`/`futimens` 这些 **fd 版**
  完全不判只读——先 `open(O_RDONLY)`（读打开放行）再 `fchmod(fd)` 即可改宿主
  backing file（权限 644→700、mtime 被改）。新增 `ro_guard_fd()`（readlink
  `/proc/self/fd` → 剥 rootfs → 反 bind → 前缀匹配只读 bind），5 个 fd 钩子接入。
  回归 `RUN_RO_BIND.sh` 新增 a2c。
- **DNS：绝对符号链接布局的 resolv.conf 导致全部解析静默失败**：guest 的
  `/etc/resolv.conf` 是指向绝对路径的符号链接（**systemd-resolved 默认布局**
  `→ /run/systemd/resolve/stub-resolv.conf`）时，resolver 经库内内联 svc openat
  走 path-relay，而 relay 只做前缀拼接、缺 exported open 钩子的
  `resolve_abs_symlink` 重定向腿 → 符号链接的绝对目标从外层内核根解析、落不进
  rootfs → ENOENT → `res_init` 退化成 `nscount=1/127.0.0.1` → `getaddrinfo`/
  `getent` 恒 gaierror -3。最阴险的是 `cat` 读文件看着正常、唯独 resolver 挂。
  修：把 `resolve_abs_symlink` 经导出桥暴露给 livepatch，relay 在 openat 返回
  -ENOENT 时重定向重发。回归 `RUN_DNS.sh` 新增 G 项（res_init 探针 +
  `BXROOT_NO_ABSSYM` 判别力）。
- **execve 家族丢失调用方 argv[0]**：`px_do_execve` 保存了 `raw_argv0`（注释写明
  trampoline `--argv0` 用它），但调用点传的是解析后的 guest 路径 → guest 的 `$0`
  变成路径。posix_spawn 路径（传 raw_argv0）正确、同 runtime 内不一致。影响
  busybox 多调用分派、登录 shell（-bash/-sh）、按 argv[0] 改行为的程序。修：
  调用点改传 `raw_argv0`（空时回退 guest）。回归 `RUN_EXEC_ARGV0.sh`。
- **mkfifo/mkfifoat/mknod/mknodat/utime/utimes/lutimes 未 hook**：走未翻译字面
  guest 路径 → rootfs 内路径 ENOENT（基线正常）。补齐这些路径版钩子（路径翻译
  + 只读 bind 守卫），`futimes`/`futimens` 为 fd 版守卫。
- **mknod 设备节点非特权 errno 不是 EPERM**：非特权建字符/块设备，POSIX/基线恒为
  EPERM(1)，bxroot 照透翻译落点的内核 errno 返回 EACCES/ENOENT/EROFS，父目录明明
  存在却报 ENOENT，误导 `errno==EPERM ? skip` 的程序（dpkg mkdev）。修：设备节点
  非特权失败归一化为 EPERM。mkfifo/mknod/utime 合并回归 `RUN_MKNOD_UTIME.sh`。
- **裸 syscall stat 的 nlink 与属主伪装缺失**：node/libuv、静态程序绕过 libc 的
  stat 符号钩子直接发 `syscall(newfstatat=79)/statx(291)`，只经 syscall_guard，
  而 guard 此前只翻译路径、不补结果（且只给 statx 补了 l2s nlink 一半、
  newfstatat 完全没补）。结果 l2s 模拟硬链接的 `nlink` 停在 1、文件属主停在磁盘
  真实 Android app uid（如 10665）。node `fs.statSync`、tar、find、ls 全中招。修：
  guard 给 79 补 l2s nlink + fakeroot 属主、给 291 补属主、statx 冷进程 lazy_enable
  改用 leaf_pre，带 `__thread` 重入守卫防 probe 递归打穿。真实硬链接 vs l2s 模拟
  链接由现有 `probe_fake_link()` 区分、不误伤。回归 `RUN_RAW_STAT.sh`。

### 验证
- 容器内 `RUN_ALL --quick` 59/0 全绿，`WARN_GATE` 零告警（14 编译单元）。
- 端到端：一个 DSHA 风格的 TypeScript/Express 设备桥接 harness（DSHA-mini）在
  bxroot 运行时里跑通完整生命周期——`npm install`（192 包，含 esbuild native
  postinstall）、`tsc` 构建、`vitest` 12/12、启动服务 + 8 类 `/app/*` 端点 curl
  全通，全程无 bxroot 缺陷（原担心的 native postinstall / 大量小文件 IO / node
  多层子进程链 / 网络装包 / http self-fetch 均扛住）。

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
