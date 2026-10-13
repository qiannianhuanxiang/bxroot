# bxroot

用 `LD_PRELOAD` 在用户态做路径翻译的开源容器运行时。主战场是 **Android arm64**：不依赖 root、`chroot`、`mount` 或 `ptrace`，在应用私有目录里跑完整的 Ubuntu 用户态（apt / dpkg / node / pnpm / git）。

当前版本 **v0.2.4**，MIT 许可。[更新日志](CHANGELOG.md) · [发行说明](docs/RELEASE-v0.2.4.md) · [架构](docs/ARCHITECTURE.md)

> **先读这条：bxroot 是兼容性运行时，不是安全沙箱，也不是 Android root。**
> fakeroot 只改变 guest 看到的 uid/gid；静态 ELF、裸 syscall 和未覆盖的内核接口可能绕过部分视图；bind 的源路径由启动参数决定。不要把不可信代码或敏感宿主目录交给 bxroot。详见 [安全边界](#安全边界)。

## 目录

- [它做什么](#它做什么)
- [快速开始](#快速开始)
- [环境要求](#环境要求)
- [能力一览](#当前状态)
- [原生执行 bx-host](#原生执行bx-host实验)
- [性能](#性能)
- [安全边界](#安全边界)
- [Android 集成](#android-集成)
- [构建](#构建) · [测试](#测试) · [架构](#架构) · [环境变量](#环境变量)
- [已知限制](#已知限制)
- [文档索引](#文档索引)
- [许可](#许可)

## 它做什么

Android 的应用沙箱不允许 `chroot` / `mount`。想在应用私有目录里跑完整 Ubuntu 用户态，只能靠用户态路径翻译：

```
客户程序 open("/etc/passwd")
        ↓  bxroot 在进程内改写路径
内核    open("/data/.../ubuntu/etc/passwd")
```

bxroot 在客户进程内直接改写路径参数，不产生额外的内核往返。ptrace 方案（proot）对每个被跟踪的系统调用要停两次；现代 proot 可用 seccomp 过滤只跟踪部分调用，Termux 自带版是否启用本仓库未核实。

> 性能：有一组限定条件下的实测，见 [性能](#性能)。更早的数字因对照组无 ptrace、且一轮 `stat` 全部失败而作废，复核过程见 [开发笔记](docs/DEVELOPMENT-NOTES.md#性能说法的复核记录)。

### 与其他方案

| | 机制 | 开销 | 说明 |
|---|---|---|---|
| chroot | 内核 | 零 | Android 上不可用（需要特权） |
| proot | `ptrace` | 视负载而定（见 [性能](#性能)） | 成熟稳定；被跟踪的系统调用每次要停两次 |
| proroot | `LD_PRELOAD` + 活体补丁 | 低 | **闭源** |
| **bxroot** | `LD_PRELOAD` | 低 | 本项目，开源（MIT） |


## 快速开始

下面的选项取自 launcher 的 `--help`，不是示例性写法。`<rootfs>` 是 Ubuntu rootfs 的宿主路径。

```sh
# 最小形态：路径翻译 + fakeroot（-0）+ 硬链接模拟（-l）
libbxroot.so -r <rootfs> -0 -l -w /root /bin/bash

# 带 bind：-b 宿主路径:guest 路径（可多次）；只读用 host:guest:ro
libbxroot.so -r <rootfs> -0 -l \
  -b /sdcard:/sdcard \
  -b /data/ro-src:/mnt/src:ro \
  /usr/bin/node --version

# proot 兼容别名：-R = -r + 推荐 bind；-S = -0 -r + 精简推荐 bind
libbxroot.so -R <rootfs> -0 /usr/bin/node --version

# 任意身份映射（0:0 与 -0 等价）、伪造内核版本、退出时清理容器内进程
libbxroot.so -r <rootfs> -i 1000:1000 -k 6.1.0 --kill-on-exit /bin/sh
```

常用选项：

| 选项 | 作用 |
|---|---|
| `-r, --rootfs <path>` | rootfs 宿主路径 |
| `-w, --cwd <dir>` | guest 内工作目录（默认 `/`） |
| `-b, --bind <h>:<g>[:ro]` | bind mount，可多次；`:ro` 写入返回 `EROFS` |
| `-0, --root-id` | fakeroot：guest 看到 uid/gid 为 0 |
| `-i, --change-id <uid>:<gid>` | 任意 guest 身份 |
| `-l, --link2symlink` | 用符号链接模拟硬链接（Android 应用目录禁 `link(2)`，**强烈建议开**） |
| `-k, --kernel-release <r>` | 伪造 `uname` 的 release |
| `--kill-on-exit` | 退出时结束容器内全部进程 |
| `-V, --version` / `-h` | 版本 / 帮助 |

明确未实现、传入会**报错而不是静默忽略**：`-H -p -q/--qemu --sysvipc --ashmem-memfd`。

在已经跑在 proroot 容器内的环境里测试时，**不要**直接用 `LD_PRELOAD`，请用 `tools/bxroot-run`，原因见 [非 Android 环境](docs/DEVELOPMENT-NOTES.md#非-android-环境请先读这段)。

## 环境要求

| 项 | 要求 |
|---|---|
| 架构 | **aarch64**（syscall 表与寄存器上下文为 arm64 硬编码，不支持 armv7 / x86_64） |
| 内核 | **≥ 4.11**（`statx` 无回退依赖；各项回退见下表） |
| 页大小 | 全部产物 **16KB 页对齐**（`-Wl,-z,max-page-size=16384`），满足 Android 15+ 16KB 页设备 |
| 编译器 | aarch64 gcc 13（Makefile 默认 `aarch64-linux-gnu-gcc-13`）；`libbxroot-enter.so` 针对 bionic 链接 |
| 非 Android | 次要目标，验证程度明显更低；需要 `BXROOT_NO_LIVEPATCH=1` 或确保无 seccomp 过滤器 |

### 最低内核要求：**4.11**（有实测依据，非照搬上游）

> 这条数字来自对 bxroot **自身依赖**的逐项实测，脚本可复跑：
> `sh test/RUN_KERNEL_MIN.sh`（在 CI 与本地都跑）。

运行时真正**无回退**依赖的最新系统调用是 `statx`（291，内核 **4.11** 引入）：
裸 `syscall()` 客户的路径翻译与结果补丁都走它。其次是 `execveat`（281，**3.19**），
fd/dirfd 形态的 exec 用它。所以最低门槛由 `statx` 决定 = **4.11**。

下面这些号**都有回退**，因此不抬门槛（各自的源码注释里有实测依据）：

| 调用 | 内核引入 | 回退策略 |
|---|---|---|
| `faccessat2` (439) | 5.8 | 拿不到就用 `faccessat`(48) 重放（`sigsys.c`） |
| `accept` (202) | 始终可用 | 白名单外时用 `accept4(…,0)` 重放（`sigsys.c`） |
| `clone3` (435) | 5.3 | 被拦时 glibc 自动回退 `clone(2)` |
| `rseq` (293) | 4.18 | livepatch 站点中和（`livepatch.c`） |

★ 清单里原先写的 "kernel 4.19" 是从上游 #417 的**症状描述**里抄来的，
不是对 bxroot 依赖的分析结果。上游那条 issue 讲的是**它的**失败现象，
与我们的门槛无关 —— 以实测为准。


## 当前状态

**v0.2.4 可用**（Android arm64；native session v3 + SHM 硬化 + 静态 ELF 进程内执行）。

> 相对 v0.1.x：**guest → host → guest 回入口**、官方启动器 `PROROOT_CFG_FD`、进程内执行无 `PT_INTERP` 的静态 ELF、SIGSYS 影子槽、livepatch 扫 libc 全部 r-x 段、SysV SHM 生命周期硬化。详细条目见 [`CHANGELOG.md`](CHANGELOG.md) 与 [`docs/RELEASE-v0.2.3.md`](docs/RELEASE-v0.2.3.md)。
>
> 真机（共存测试包，独立 applicationId，不在本仓库发行）：guest `BXROOT_REENTRY=1`、`TracerPid: 0`、`ldconfig.real` 无 EROFS、`node v24` 单进程与 4 worker+pbkdf2、`exit 7` 透传。原生 Termux 源码回归覆盖 SHM copyout/claim/ABA/fork/static trap 与 l2s。
>
> 已作为第三运行时接入 DSHA 类启动器（契约见 [`docs/DSHA-适配说明.md`](docs/DSHA-适配说明.md)）。**本仓库发行物不含任何 DSHA APK 或 DSHA 源码。**
>
> 更早的 v0.1.3 沙箱打通 / DNS path-relay / fakeroot 收敛见 CHANGELOG。竞品对标见 [`docs/竞品对标分析.md`](docs/竞品对标分析.md)。

| 能力 | 状态 |
|---|---|
| 路径翻译（含 bind mount、特殊路径透传；**含裸 syscall 与相对路径形态**） | ✅ |
| fakeroot（伪装 uid=0，含身份账本：setter/getter 自洽） | ✅ |
| l2s 硬链接模拟（含 `st_nlink` 契约 + **目录项 `d_type` 契约**；`link()` 失败时**自动启用**；裸 statx 同样伪装） | ✅ |
| 符号链接矩阵（libc open/open64/openat 与裸 openat 同答案；stat 与裸 statx 同答案；O_NOFOLLOW 双语义） | ✅ |
| 子进程派生（`fork`/`vfork`/`exec`/`posix_spawn` 全套 + trampoline + 账本） | ✅ |
| `system()`/`popen()`（子进程带钩子 + 路径翻译） | ✅ |
| seccomp 中和（Android 沙箱禁止的系统调用 + livepatch；站点表按 glibc 版本登记，不匹配时回退到运行期指令扫描） | ✅ |
| shebang 脚本直接 exec | ✅ |
| NSS 用户/组查询（by-name 与 by-id 全套直解回退 + fakeroot 合成） | ✅ |
| libaudit 符号（passwd/login/chage 等 20 个程序依赖） | ✅ |
| `dpkg -l` / `dpkg -S` / `dpkg-deb --build` / `dpkg -i`（unpack+configure） | ✅ |
| `dlerror`/`dl_iterate_phdr`/`pthread_create`（栈下限与官方一致） | ✅ |
| `syscall(174..177/148/150/158)` 身份查询（裸 syscall 层） | ✅ |
| 运行 `node` + `dsh` | ✅ 早期实测 `dsh --version` → `0.1.5-rc.2`；v0.2.3 真机：`node v24.19.0` 单进程与 4 worker |
| AF_UNIX 地址双向翻译（bind/connect/**sendto/sendmsg** 正向；getsockname/getpeername/accept/recvfrom/recvmsg 回填反向） | ✅ |
| glibc `accept()`（syscall 202，Android 白名单外）→ SIGSYS 层 `accept4(…,0)` 精确重放 | ✅ |
| launcher 设 `$PWD` = guest 视角 workdir（上游 #64） | ✅ |
| `--kill-on-exit` 覆盖任何退出方式（`_exit`/exit_group/信号致死；launcher 作 subreaper 监督者） | ✅ |
| `execveat`/`fexecve`（含 AT_EMPTY_PATH、dirfd 相对、#! 脚本 fd）经 trampoline 执行 | ✅ |
| exec 失败给出具体原因（缺解释器/CRLF/无执行位/外部架构…），退出码 127/126 | ✅ |
| 静态链接 / static-PIE 程序、`ld.so` 直接调用、`ldd` | ✅ 优先进程内 `static_exec`（路径类 svc 翻译）；失败回退 stub-loader。多线程 / ET_EXEC 冲突回退 |
| 降权族内联 svc（glibc `initgroups()`、nptl setxid 广播）→ SIGSYS 层接 fakeroot 账本 | ✅ |
| SIGSYS 影子槽（guest `sigaction(SIGSYS)` 不顶掉 runtime；自发 SIGSYS 吞掉） | ✅ 真机交互 bash `exit` 码透传 |
| livepatch 扫 libc **全部** r-x 段，版本表补丁后复位 r-x | ✅ node worker / rseq / set_robust_list |
| native session v3（只读封印 memfd，`BXROOT_REENTRY` / `BXROOT_ENTER`） | ✅ |
| SysV 共享内存（shmget/shmat/shmctl/shmdt；文件式模拟） | ⚠️ 默认构建 **gate 关闭**：拒绝 keyed 与 `IPC_PRIVATE` 新建，copyout 不盲发 `process_vm_writev`。verified profile 才打开。官方 proroot 混合并发**不协调**；不是完整 Linux 延迟 `IPC_RMID` |

**导出符号 460 个**（`nm -D --defined-only build/libbxroot-runtime.so` 中 T/W 类，v0.2.3 默认 profile 实测）。历史对照：闭源 proroot 为 259 个（见 [parity 补齐报告](docs/parity-补齐报告.md)，是当时快照，未重测）。


## 上游 24 个 issue 回归

> 这是 **2026-10-02 的快照**（`tests-upstream/ISSUE-TEST-MATRIX.md` 最后更新），v0.2.3 没有重跑。

将上游 coderredlab/proroot 的全部 issue 转成 **25 个可执行用例**（双基线判定，
bxroot vs proot 对照）：

```
PASS  14    FAIL  0    NOCTL 7    SKIP 4
```

**上游 issue 无一在 bxroot 上重现**（详见 `tests-upstream/ISSUE-TEST-MATRIX.md`）。

★ **别把这一行读成"25 个全过"** ★ 其中 **12 个并非真实通过的验证**：

| 判定 | 数量 | 含义 |
|---|---|---|
| PASS | 14 | 真的在这个环境里验证过 |
| **NOCTL** | **7** | **无对照** —— 官方在同条件下行为相同，无法判定优劣 |
| **SKIP** | **4** | **被跳过** —— 环境不满足（缺依赖/需要真机），**没有跑** |
| FAIL | 0 | — |

所以准确说法是：**"14 项通过，7 项无对照，4 项未测，0 项失败"**。


## 性能

2026-10-13 在原生 Termux 上对 proot(ptrace) 和 bxroot 做了对照，同一 rootfs、同样的 bind / fakeroot / link2symlink，每项先校验操作成功再计时，5 轮取中位数。两边 `find /usr` 都遍历到 8413 项，是同一棵树。

| 负载 | proot | bxroot | proot ÷ bxroot |
|---|---|---|---|
| `find /usr` | 2.82 s | 0.163 s | 17.3 |
| 外部 `stat` ×2000 | 41.1 s | 12.2 s | 3.4 |
| 小文件写后读回 ×300 | 6.40 s | 1.96 s | 3.3 |
| 硬链接 ×200 | 1.63 s | 1.07 s | 1.5 |
| fork+exec ×300 | 1.70 s | 1.39 s | 1.2 |

读这张表要注意：

- 只有一台设备、一个 rootfs，每项 5 次。五项里 proot 的最小值都大于 bxroot 的最大值，但倍数**不是常数**：同一台手机早一轮用旧构建实测，`find` 是 9.4 倍，fork+exec 反而是 proot 更快。
- 负载是 shell 循环，"外部 `stat`" 是启动 2000 个进程，不是系统调用微基准。路径密集的单进程负载（`find`）差距最大，进程创建为主的负载（fork+exec）差距最小。
- **没有和官方 proroot 比**：自拼的配置块没被官方 runtime 接受，该后端被自检剔除。

环境、原始输出和复现命令见 [`docs/BENCH-2026-10-13.md`](docs/BENCH-2026-10-13.md)。

## 安全边界

bxroot 是用户态兼容运行时，**不是安全沙箱**，也不是 Android root：

- `-0` / `BXROOT_FAKEROOT=1` 只伪造 guest 看到的 uid/gid，内核真实属主不变。依赖真实 uid 的检测（部分 `make install` 属主断言、npm 安全校验）可能与真 root 有出入。
- 静态 ELF、裸 `syscall()` 和未覆盖的内核接口可能绕过部分 `LD_PRELOAD` 视图。进程内 `static_exec` 只补 `mov x8,#imm` 后紧跟 `svc` 的路径类站点。
- bind 源路径由启动参数决定。不可信 guest 不应获得敏感宿主目录。
- guest 能读到运行库和环境配置时，不要把 bxroot 当权限边界。
- `bx-host` 进入 Android bionic world，但身份仍受应用 UID 和 SELinux 约束。
- native session v3 的 session fd 必须是只读封印 memfd（`F_SEAL_SEAL|SHRINK|GROW|WRITE` 四个 seal 齐全），读取端拒绝其他形态。
- **SysV 共享内存默认关闭新建**：默认构建把 `BXROOT_SHM_CLAIM_VERIFIED` 和 `BXROOT_SHM_COPYOUT_VERIFIED` 编成 0，`shmget` 新建返回错误。这是保守策略，见 [Runtime 构建发布说明](docs/RELEASE-runtime-gates.md)。

## Android 集成

把 bxroot 打进 APK 时的硬约束：

1. 多个 `.so` 放同一目录（`jniLibs/arm64-v8a/`，安装后即 `nativeLibraryDir`），launcher 用自身路径找兄弟库，不可拆目录。
2. launcher 必须能被 exec：`nativeLibraryDir` 满足 SELinux 的执行例外，任意 app data 目录不行。
3. rootfs 放应用私有目录，首次启动从 assets 解压。
4. SELinux 禁 `link(2)`：必须 `--link2symlink`。
5. 产物必须 16KB 页对齐。

详见 [Android / bionic 集成指南](docs/ANDROID-INTEGRATION.md)、[DSHA 适配说明](docs/DSHA-适配说明.md)、[真机验证清单](docs/真机验证清单.md)。

### 构建配置：default 与 verified

| | default（发行） | verified |
|---|---|---|
| 命令 | `sh BUILD_RUNTIME.sh -O1` | `BXROOT_BUILD_PROFILE=verified BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 sh BUILD_RUNTIME.sh -O1` |
| 产物 | `build/libbxroot-runtime.so` | `build/verified/libbxroot-runtime.so` |
| SHM 新建 / `IPC_STAT` copyout | 关闭，明确返回错误 | 开启 |
| 何时用 | 默认 | 目标 guest 的 seccomp 链已实测支持 `process_vm_writev(271)` 与 `fcntl(25)` |

两个 profile 的产物互不覆盖，`build/BUILD-METADATA` 记录实际 gate。

## 原生执行：`bx-host`（实验）

### 第一版：显式进入 Android bionic world

bxroot 的 guest 是 Ubuntu/glibc 用户空间，而 `/system/bin`、`/apex` 下的 Android 程序由 bionic linker 加载。不要把两种 libc 的动态库混进同一进程；第一版提供显式的 `bx-host` 入口，在 guest 中切换到 Android bionic world：

```sh
bx-host /system/bin/getprop ro.product.model
bx-host toybox uname -a
bx-host /system/bin/sh -c 'getprop ro.product.model'
```

`bx-host` 是无 libc 的静态 AArch64 程序，读取目标 ELF 的 `PT_INTERP`，只接受 Android linker 的 bionic ELF，并通过 raw `execve` 直接进入宿主程序。它清理 guest 的 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`BXROOT_*` 和 `PROROOT_*`，设置最小 Android 环境，同时保留原始 `argv[0]`、stdio、PTY、信号和退出状态。

Termux 中的 v4 guest 已实测 `getprop`、`toybox`、宿主 shell 链和环境清洗均通过。`bx-host` 不改变 UID 或 SELinux 权限。

### 第二版：可选自动分流

```sh
BXROOT_AUTO_HOST=1 BXROOT_HOST_PATH=/system/bin:/system/xbin:/vendor/bin bxroot ...
```

启用后 guest 同名程序优先，exec/spawn 自动根据 ELF interpreter 分流，宿主候选和脚本解释器遵守 rootfs/bind。guest PATH 后追加宿主目录，宿主进程清理 glibc loader 环境，保留应用变量、argv0、stdio、PTY、信号和退出状态。默认不开启；显式 `BXROOT_HOST_PATH=""` 禁止宿主名字 fallback。

Termux 中通过真实 bridge/linker + 匿名 memfd 加载完成 **25/25** 回归；分类/环境 **77** 检查、真实分流 **175** 检查全部通过。设计、运行方式和剩余边界见 [第二版说明](docs/bx-host-第二版.md)。这是实验实现，全量回归尚未通过；源码提交不等同于更新 DSHA APK 或发布 Release。

### 第三版：双向执行与会话交接

启用 `BXROOT_AUTO_HOST=1 BXROOT_REENTRY=1` 后，Android 原生侧可经 `$BXROOT_ENTER` 回到同一 guest。session 为只读封印 memfd，读取端强制检查四个 seal。启用方式、回入口命令和边界见 [第三版说明](docs/bx-host-第三版.md)。

## 构建

```sh
./BUILD_RUNTIME.sh          # 默认 profile：两个 SHM gate 强制为 0
make                        # 构建组件
make test                   # 跑测试
# 仅在目标 guest 过滤链已核过时：
# BXROOT_BUILD_PROFILE=verified \
# BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 \
# ./BUILD_RUNTIME.sh -O1
```

★ 全部产物带 **16KB 页对齐**（`-Wl,-z,max-page-size=16384`）——
Android 15+ 的 16KB 内存页内核设备硬要求，且 DSHA 集成要求 jniLibs
内的原生库满足此对齐。交叉编译时链接 flag 已内置，无需手工加。

产出文件（名字沿用原 proroot 的布局，便于替换）：

| 文件 | 作用 |
|---|---|
| `libbxroot.so` | 启动器（静态可执行，伪装成 `.so`） |
| `libbxroot-runtime.so` | 运行时：全部 `LD_PRELOAD` 钩子。默认 profile 与 `build/verified/` 隔离 |
| `libbxroot-linker.so` | 自研 ELF 加载器 |
| `libbxroot-bridge.so` | 宿主/客户桥接 |
| `libbxroot-stub-loader.so` | 静态二进制的 `PT_INTERP` 修补器（**非独立 ELF 加载器**：为静态二进制补上 PT_INTERP 后 `execve`，交给内核加载；不做 mmap/段加载/跳 `_start`。定位见 `src/stub-loader/stub-loader.c` 注释） |
| `libbxroot-enter.so` | native v3 guest 回入口 |


## 架构

```
libbxroot-bridge.so  libbxroot-linker.so --argv0 node \
    --preload libbxroot-runtime.so <guest-exe> [args...]
```

运行时由这几层组成（各自独立、可单独测试）：

| 层 | 职责 |
|---|---|
| `preload.c` | 主体：路径翻译 + 全部系统调用钩子 |
| `l2s/` | 硬链接模拟（符号链接 + 中间层，含 `st_nlink` 契约） |
| `fakeroot.c` | 伪造 root 身份（含身份账本：setter 写 / getter 读） |
| `crash.c` | 崩溃现场捕获（寄存器/回溯打印） |
| `sigsys.c` | SIGSYS 兼容层（含信号屏蔽防护；accept/降权族/SysV shm 的模拟，shm 在 `sysvshm.c`） |
| `syscall_guard.c` | `syscall()` 接管：seccomp 中和 + 路径翻译 + 身份改写 |
| `livepatch.c` | 运行时指令补丁（seccomp 中和；版本表 + 运行期指令扫描） |

### 一个非显而易见的要点

`syscall_guard.c` 里的**路径翻译**是必需的，不是冗余。

Node 静态链接的 libuv **不经 libc 的 `stat`/`statx` 符号**，而是用
`syscall(291, AT_FDCWD, path, ...)` 直接发起。所以只 hook 符号的话，
Node 的所有文件操作**都会绕过翻译** —— 现象是 C 程序一切正常、
Node 全部 `ENOENT`。


## 环境变量

| 变量 | 说明 |
|---|---|
| `BXROOT_ROOTFS` | 根文件系统路径（由 `-r` 派生） |
| `BXROOT_WORKDIR` | 工作目录（由 `-w` 派生） |
| `BXROOT_FAKEROOT` | 伪装 uid=0（由 `-0` 派生） |
| `BXROOT_LINK2SYMLINK` | 启用 l2s（由 `--link2symlink` 派生；`link()` 失败时也会自动启用） |
| `BXROOT_L2S_DIR` | l2s 中间层目录。**未设** → `<rootfs>/.l2s`（集中布局，所有启用路径一致）；**设为空** → 散落布局（中间层落在客户文件旁，git 等会报损坏，仅供测试）；容器/宿主视角路径均可 |
| `BXROOT_BINDS` | bind 列表（`src:dst;src:dst`） |
| `BXROOT_LIB_PATH` | 显式指定 runtime `.so` 路径 |
| `BXROOT_TMP_DIR` | 临时目录 |
| `BXROOT_VERBOSE` | 排障日志（**部分日志为 debug 构建编译期开关**：release 包中仅 proc 等运行期日志生效，`preload.c` 的 LOG 需 `make debug`/`-DBXROOT_VERBOSE=1` 重编才完整） |
| `BXROOT_SCG` | `syscall` 层追踪 |
| `BXROOT_RAW_SYSCALL` | 置 1 时对「因 Android 策略而中和」的调用（io_uring 家族 425/426/427）**真透传**，不再恒定回 `ENOSYS`，由真实内核/宿主 seccomp 给出答案 —— 适用于非 Android 环境（如通用 seccomp profile 的普通容器）。身份/降权伪装与路径翻译不受影响；`0` 或未设时行为不变 |
| `BXROOT_NO_AUTORUN` | 置 1 跳过 runtime 构造链（源码级单元测试专用，正常使用勿设） |
| `BXROOT_REENTRY` / `BXROOT_ENTER` / `BXROOT_SESSION_FD` | native session v3：guest 回宿主入口与封印 session fd |
| `PROROOT_CFG_FD` | 官方启动器配置块路径；有此文件时不注入 `STUB_ROOTFS`。显式 `BXROOT_ROOTFS` / `BXROOT_BINDS` 仍优先 |
| `BXROOT_NO_CRASH` | 置 1 不安装崩溃处理器，由客户程序自管 SIGSEGV/SIGBUS |
| `BXROOT_CRASH_CHAIN` | 置 1 打印现场后链式调用更早注册的 handler（默认关，开启会有双方各一段输出） |
| `BXROOT_NO_LIVEPATCH` | 置 1 跳过 libc 站点活体补丁（非 Android 环境兜底；正常有 `PR_GET_SECCOMP` 自动门控） |
| `BXROOT_FORCE_NO_LDSO_SERVICE` | 置 1 强制走"无 ldso 服务"降级分支（**测试专用**：让该分支可在开发环境真实执行） |

> 提示：检测到 `PROROOT_*`（旧名/官方名）环境变量但未设对应 `BXROOT_*` 时，启动会向 stderr 打一行拼写/迁移防呆警告（每进程最多一次）。


### 已知行为边界（如实告知）

- **crash 处理器**：runtime 默认安装 SIGSEGV/SIGBUS 现场打印处理器
  （崩溃时留现场而不是无声退出）。客户在 `main()` 之后注册的 handler
  会覆盖它（后装者胜）。若需完全自管崩溃处理，置 `BXROOT_NO_CRASH=1`；
  若需在打印现场后把控制权交给**更早注册**的 handler（如嵌套容器的
  外层运行时），置 `BXROOT_CRASH_CHAIN=1`（默认关闭 —— 链式会导致
  双方各输出一段现场）。
- **fakeroot 不等于真 root**：uid/gid/chmod 是用户态视图伪装，
  内核真实属主不变。依赖真实 uid 的检测（`make install` 的属主
  断言、部分 npm 安全校验）可能与真 root 有出入 —— 与官方 proot
  同样的边界。
- **架构死绑 aarch64**：syscall 编号表、寄存器上下文均为 arm64
  硬编码（另见上方限制表：O_NOFOLLOW 等 ABI 常量按本机实测写入，
  换架构必须重测）。armv7/x86_64 需要独立的参数表工作，当前不支持，
  也不在 v0.x 路线图内。


## 测试

```sh
sh test/RUN_ALL.sh --quick      # 主回归（35 项，一键全跑；本容器内 2 项按环境 SKIP）
```

分项：

```sh
sh test/RUN_TESTS.sh            # 纯逻辑（不需真机）
sh test/RUN_CONCUR.sh           # fakeroot 账本多线程并发（8线程×400键）
sh test/RUN_L2S_E2E.sh          # l2s 端到端（对照官方）
sh test/RUN_ID_SYSCALL.sh       # 身份 syscall（47 用例）
sh test/RUN_DL_TESTS.sh         # dl 家族契约
sh test/RUN_SYSTEM_POPEN.sh     # system/popen 子进程
sh test/RUN_PTHREAD_CREATE.sh   # pthread_create 栈
sh test/RUN_PRIVDROP.sh         # 降权族（真实 chage 验收）
sh test/RUN_SHEBANG.sh          # shebang 直接 exec
sh test/RUN_WARN_GATE.sh        # 编译零告警门禁
sh test/RUN_CLI_COMPAT.sh       # proot CLI 语义（38 项）
sh test/RUN_UPSTREAM_CLI.sh     # 上游选项表全覆盖（35 项）
sh test/RUN_PATH_FORMS.sh       # 路径形态（裸相对名/dirfd+相对/…）
sh test/RUN_SYSCALL_TABLE_AUDIT.sh  # 路径参数表实测审计（裸 svc 逐号对内核）
sh test/RUN_RAW_SYSCALL.sh      # 非 Android 透传开关
sh test/RUN_REALPATH_FIXUP.sh   # realpath 返回值反向翻译
sh test/RUN_D3_FIXUP.sh         # /proc 泄漏反向翻译
sh test/RUN_UNIX_SOCKADDR.sh    # AF_UNIX 地址双向翻译 + accept 重放（带官方对照）
sh test/RUN_TRAP_PARITY.sh      # seccomp TRAP 号逐号对照官方（审计型）
sh test/RUN_SYSVSHM.sh          # SysV 共享内存（对照官方 + 互通 + 并发）
sh test/RUN_L2S_GIT.sh          # l2s × 真实 git，三种 L2S_DIR 形态
sh test/RUN_KILL_ON_EXIT.sh     # --kill-on-exit 监督进程（6 种退出方式，带对照）
sh test/RUN_EXEC_DIAG.sh        # execveat/fexecve + exec 失败诊断 + 127/126
sh test/RUN_STATIC_ELF.sh       # 静态/static-PIE/ld.so/ldd 经 stub-loader（带官方对照）
sh test/RUN_STUB_PATCH.sh       # stub-loader PT_INTERP 补丁：临时目录 + 产物结构
bash issue-regression-test.sh   # 上游 24 issue 的 25 用例回归
```

> ★ 最后一行必须是 `bash` 而不是 `sh` ★ 该脚本是 bash 脚本
> （`#!/usr/bin/env bash`，并用了 `set -o pipefail`）。在 Debian/Ubuntu
> 上 `sh` 是 dash，它不支持 `pipefail`，会直接
> `set: Illegal option -o pipefail` 退出（rc=2）—— **一条用例都没跑**，
> 而 README 此前写的正是 `sh`。用 `sh` 跑等于静默不执行。

其中三项是「会主动发现问题」的审计型测试，不只是防回归：

- **`RUN_TRAP_PARITY.sh`**：枚举本环境被 seccomp TRAP 的全部真实调用，
  逐号比较官方与 bxroot 的返回值。2026-09-25 首跑即发现 `accept(202)`
  与 glibc `initgroups()` 内联的 `setgroups(159)` 在 bxroot 下是 ENOSYS
  （官方可用），顺带揪出 `syscall_guard.c` 把 143/145（setregid/setreuid）
  写反 —— 而单测表与源码**抄了同一份错误**，一直把缺陷钉成"正确"。

- **`RUN_SYSCALL_TABLE_AUDIT.sh`**：用裸 `svc` 对内核逐号实测哪些系统
  调用的哪个参数是路径，再与我们源码里的表比对。2026-09-18 用它发现
  25 个路径型调用（xattr 族 / chdir / truncate / openat2 等）**未列入
  表** —— 走裸 `syscall()` 的程序（如 node 的静态 libuv）对这些调用
  拿不到翻译。补齐后遗漏归零。
- **`RUN_CONCUR.sh`**：并发压测 fakeroot 账本。它曾直接暴露无锁下的
  堆破坏（`double free`），促成加锁修复。

判定口径：所有端到端测试都采用**双基线**——bxroot 与官方 proroot
对照，逐行比对输出，"比官方差"才算 FAIL。


## 已知限制

详见 [`docs/已知限制与架构能力边界.md`](docs/已知限制与架构能力边界.md)。

| 限制 | 影响 | 说明 |
|---|---|---|
| ~~`make` 配方子进程~~ | 构建链 | **已修复**（曾是"架构级"误判，现纳入回归） |
| ~~绝对目标的符号链接~~ | 依赖绝对链接的软件 | **已修复**（v0.1.2 全链路收敛：libc 四入口 + 裸 syscall 层 + 相对形态；内核内联解析的边界仍由 svc 前叶子展开覆盖）。详见 [`docs/缺陷-裸syscall-statx末端符号链接逃逸.md`](docs/缺陷-裸syscall-statx末端符号链接逃逸.md) |
| NSS `getpwnam_r` 内部分派 | `df` 标签 | 已用 /etc/passwd 直解回退修复主流程；仅 `df` 的挂载点标签显示差异（数值正确） |
| `dpkg -i` 的 timestamp | 非致命 | 包内容/状态/配置全正确，仅 mtime 为当前时间（`AT_EMPTY_PATH` 需要 CAP，fakeroot 无真实 CAP） |
| livepatch 站点表版本绑定 | 换 glibc 时 | 站点偏移针对特定 glibc 版本；已加运行期版本断言，不匹配时**打印告警并跳过**（原先会静默失效） |
| `-H`/`-p`/`-q` 等 CLI 选项 | 少数用户 | 官方 proroot 同样未实现；bxroot **明确报错**而非静默忽略 |
| 架构死绑 aarch64 | 其他架构 | syscall 编号表与寄存器上下文 arm64 硬编码（O_NOFOLLOW 等常量也按本机实测）；armv7/x86_64 需要独立工作 |


## 文档索引

`docs/` 下文件很多，按用途分组：

| 想了解 | 看这里 |
|---|---|
| 整体设计 | [ARCHITECTURE](docs/ARCHITECTURE.md) · [已知限制与架构能力边界](docs/已知限制与架构能力边界.md) |
| 本版本发行与变更 | [CHANGELOG](CHANGELOG.md) · [RELEASE-v0.2.4](docs/RELEASE-v0.2.4.md) · [RELEASE-runtime-gates](docs/RELEASE-runtime-gates.md) · [当前收口状态](docs/CLOSEOUT-current.md) |
| Android 集成 | [ANDROID-INTEGRATION](docs/ANDROID-INTEGRATION.md) · [DSHA 适配说明](docs/DSHA-适配说明.md) · [真机验证清单](docs/真机验证清单.md) |
| native v3 / bx-host | [第一版](docs/bx-host-第一版.md) · [第二版](docs/bx-host-第二版.md) · [第三版](docs/bx-host-第三版.md) · [ANDROID-NATIVE-V3-RELEASE](docs/ANDROID-NATIVE-V3-RELEASE.md) |
| SysV SHM | [TEST-shm-final-closure](docs/TEST-shm-final-closure.md) · [TEST-shm-closeout](docs/TEST-shm-closeout.md) · [BUILD-runtime-capability-matrix](docs/BUILD-runtime-capability-matrix.md) |
| 真机 / 原生证据 | [TEST-termux-native](docs/TEST-termux-native.md) · [TEST-native-ci](docs/TEST-native-ci.md) · [TEST-isolated-audits](docs/TEST-isolated-audits.md) |
| 排查与缺陷报告 | [SIGSYS 机制](docs/SIGSYS机制破解报告.md) · [LD_PRELOAD 在 proroot 内失效](docs/调查-LD_PRELOAD在proroot容器内失效.md) · [杀进程安全规则](docs/杀进程安全规则.md) |
| 竞品 | [竞品对标分析](docs/竞品对标分析.md) |
| 开发笔记 | [DEVELOPMENT-NOTES](docs/DEVELOPMENT-NOTES.md)（性能复核、非 Android 修复历史、路径视角陷阱、同一功能多入口、内部直调、sigaction 布局） |

## 贡献与验证

提交前至少跑：

```sh
sh test/RUN_WARN_GATE.sh        # 编译零告警门禁
sh test/RUN_ALL.sh --quick      # 主回归（复用已有产物，不重新编译）
```

GitHub Actions：`ci.yml`（build / 全量回归 / 告警门禁）与 `native-arm64.yml`（`ubuntu-24.04-arm` 原生 ARM64 回归，只读权限，PR 与手动触发）。CI 判红只看退出码，不看项数。

在 Termux 原生环境复核 SHM / l2s：`test/RUN_TERMUX_NATIVE.sh`（须在原生 Termux 执行，脚本会拒绝 PRoot 或被 ptrace 的进程）。

推送请用 `tools/push-verified.sh`，不要 `git push --force`，原因见 [开发笔记](docs/DEVELOPMENT-NOTES.md#开发工具受保护推送)。

## 许可

MIT，见 `LICENSE`。

### 与 PRoot 的关系

`src/l2s/` 实现的硬链接模拟遵循 PRoot `link2symlink` 扩展建立的
**磁盘命名约定**（`.l2s.<name><GGGG>[.<NNNN>]`），目的是让两边准备的
rootfs 可以互相读取。

共享的是**格式**，不是实现：

| | 上游 PRoot | bxroot |
|---|---|---|
| 机制 | `ptrace` 拦截 | 纯函数 + 可注入的 FS 操作 |
| 依赖 | `talloc`、PRoot 内部 tracee API | 无（仅 libc） |
| 代码重合 | — | **无共享代码** |

命名约定属于思想/格式，不受版权保护；本项目未复制上游代码。
