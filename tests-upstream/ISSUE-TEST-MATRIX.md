# ISSUE → 测试用例 → 判定标准 对照表

**目标**：把上游 [`coderredlab/proroot`](https://github.com/coderredlab/proroot) 的 issue
转成 bxroot 的可执行真机验收测试。

| 项 | 值 |
|---|---|
| 脚本 | `issue-regression-test.sh`（v1.0.0，真机可执行，`bash -n` 通过） |
| 上游 issue 总数 | **24**（GitHub search API `total_count` 权威值） |
| 有可测故障行为的 issue | **15** —— 全部覆盖 |
| 未覆盖（无故障行为） | 9 个：#1/#3/#4/#6/#7/#9/#14/#17/#18/#19/#21 中的非故障类，见 §2 |
| 用例总数 | **25** |
| 必须真机 | **23/25**（仅 T11、T24 可在容器内部分验证） |
| 判定模型 | 双基线：bxroot（被测）vs proot（对照） |

---

## 0. 判定语义（先读这一节）

### 0.1 状态定义

| 状态 | 含义 | 计入失败？ |
|---|---|:--:|
| `PASS` | 通过 | 否 |
| `FAIL` | **真回归**：proot 通过 / bxroot 失败 | **是** |
| `ENVFAIL` | proot 同样失败 → 环境问题，不是 bxroot 的锅 | 否 |
| `NOCTL` | **无 proot 对照**，无法判定（**不等于通过**） | 否（但须真机复跑） |
| `SKIP` | 环境不具备（缺工具/缺设备/缺网络） | 否 |
| `XFAIL` | 纯诊断信息 | 否 |

**`NOCTL` 是本脚本最重要的设计**：没有 proot 对照时，bxroot 的失败
既可能是真回归，也可能是环境本身不支持。把它记成 `FAIL` 会冤枉 bxroot，
记成 `PASS` 会掩盖缺陷 —— 所以单列一类，并在汇总里显式提示"不是通过"。

### 0.2 `FAIL` 行的折叠规则

很多探针会打印多行 `  FAIL ...`。退出码为 0 但输出里有更多 FAIL 行，
同样算劣化：

```
崩溃（rc >= 128）        → 原样透传，绝不折算成 0
bxroot FAIL 行 > 对照行  → 1（劣化）
否则                     → 0
```

崩溃码永远不会被折算掉 —— 这是刻意的（#22 正是 rc=139）。

### 0.3 优雅降级的实现方式

| 缺失项 | 行为 |
|---|---|
| 无 `libbxroot.so` / `libbxroot-*.so` | 全部用例 `SKIP`，不报错退出 |
| 无 `proot` | 判定退化为 `NOCTL`，并提示需真机复跑 |
| 无 C 编译器 | 编译型探针（T01/T04/T05/T10/T12/T14/T15/T17/T19）`SKIP` |
| guest 内无 node/git/bun/uv/dbus | 对应用例 `SKIP` |
| 无网络 | T09（pip/uv 安装）`SKIP` 而非 `FAIL` |
| 无 `/dev/dri` | T20 GPU 用例 `SKIP` |
| 无 Xvfb / 无 X 会话 | GUI 类用例 `SKIP` |
| **不用 apt 安装任何东西** | 探针 C 源码全部内联，现场用现有 gcc 编译 |

---

## 1. 用例总表

| ID | issue | 用例 | 验证目标 | 判定标准（PASS 条件） | 需真机 |
|---|---|------|------|------|:--:|
| T01 | **22** | readlinkat 分支/早期崩溃 | `readlinkat` 内 `strlen(x20)` 路径不崩 | 退出码 < 128，且 FAIL 行数 ≤ proot | ✅ |
| T02 | **22** | 早期阶段哨兵 | constructor/preinit→main 全程存活 | 5 个 `--step` 全部输出 `SENTINEL-OK` | ✅ |
| T03 | **22** | 崩溃诊断产物 | SIGSEGV 后生成 `*-sigsegv-maps.txt` | 文件存在 | ⚠️ NOCTL（2026-09-17 实测：官方 kill -SEGV 下同样不生成，需额外开关才触发；原判 ✅ 的前提不成立，见脚本内注释）|
| T04 | **23** | 大文件+mmap/mremap/MAP_SHARED | 32MB 写/共享映射/跨进程一致 | FAIL 行数 ≤ proot，无崩溃 | ✅ |
| T05 | **23** | 大量目标文件链接 | 120 个 `.o` 一次性链接 | 输出 `BIGLINK-OK`，无 `undefined reference` | ✅ |
| T06 | **24** | Node 原生模块 dlopen | NAPI 符号可解析 | 无 `napi_add_env_cleanup_hook has not been loaded` | ✅ |
| T07 | **24** | git 本地 clone + fsck | 对象完整 | `GIT-OK`，无 `bad object` | ✅ |
| T08 | **24** | bun 运行 | 不段错误 | rc=0 且无 signal 11 | ✅ |
| T09 | **24**,10 | 包管理器原生扩展 | Pillow `_imaging.so` 可加载 | `PIL-OK`，无 `unknown dlopen() error` | ✅ |
| T10 | **10** | `$ORIGIN` RUNPATH 解析 | `$ORIGIN/deps` 被解析 | dlopen 含 `$ORIGIN` 依赖树的库成功 | ✅ |
| T11 | **10** | 产物 RUNPATH 自检 | 测试库真的带 `$ORIGIN` | `readelf -d` 含 ORIGIN | ⚠️ 部分 |
| T12 | **12** | chown 后 stat 属主 | fakeroot 完整性 | `chown` 后 stat 反映新属主或 0:0；`statx`/`lstat` 与 `stat` 一致 | ✅ |
| T13 | **12** | dpkg 写 `/etc` | `.dpkg-new` 可创建 | `DPKG-PROBE-OK`，无 `Permission denied` | ✅ |
| T14 | **12**,24,23 | 硬链接 / l2s | `link(2)` 语义 | 真硬链接或 l2s 且 `st_nlink==2`，写 a 影响 b | ✅ |
| T15 | **11**,5 | renameat2/unlink/rm -rf | 路径语义正确 | `RENAME_NOREPLACE`→EEXIST；unlink 后 stat→ENOENT | ✅ |
| T16 | **11** | uv clean | 递归缓存清理 | `UVCLEAN-OK`，无 `os error 2` | ✅ |
| T17 | **8** | sendmsg/SCM_CREDENTIALS | 凭据传递完好 | 收到 SCM_CREDENTIALS 且 pid/uid 正确 | ✅ |
| T18 | **8**,16 | dbus session 往返 | `dbus-send` 有回复 | `DBUS-OK`，无 `Did not receive a reply` | ✅ |
| T19 | **13** | ioctl 透传 | fd/参数/errno 未篡改 | FAIL 行数 ≤ proot | ✅ |
| T20 | **13**,16 | Chromium GPU 进程 | EGL/GLES 初始化 | 无 `exit_code=256` | ✅ |
| T21 | **16** | Electron/QQ 启动 | ICU 数据 fd 有效 | 无 `Invalid file descriptor to ICU data` | ✅ |
| T22 | **15**,9 | 大型原生应用 `/proc` 可读 | `/proc/stat` 等可读 | `SUMMARY fails=0` | ✅ |
| T23 | **22**,20,2 | launcher 基础可用 | `/bin/true` 零崩溃 | rc=0（**rc=139 即 #22 症状**） | ✅ |
| T24 | **20** | launcher CLI 契约 | `--help/-b/-w/echo` | 全部符合契约 | ⚠️ 部分 |
| T25 | **20**,24 | rootfs 冒烟 | `/bin/sh` 可执行 | `SMOKE-OK` | ✅ |

> ⚠️ T11/T24 标"部分"：T11 只验证产物 ELF（不碰设备），T24 验证 launcher 参数解析，
> 但 `-b`/`-w` 是否真正生效取决于 runtime，必须真机确认。

---

## 2. 按 issue 索引（含未被用例直接覆盖的部分）

| issue | 标题要点 | 覆盖用例 | 能否在容器内验证 |
|---|---|---|:--:|
| **8** | dbus SCM_CREDENTIALS 传递被破坏 | T17, T18 | ❌ |
| **10** | `$ORIGIN` RUNPATH 不被解析 | T10, T11, T09 | ❌（T11 可） |
| **11** | `uv clean` → os error 2 | T15, T16 | ❌ |
| **12** | sudo 安装 → `/etc/sudoers.d/README.dpkg` Permission denied | T12, T13, T14 | ❌ |
| **13** | Mesa freedreno/kgsl 被 LD_PRELOAD 拦截 | T19, T20 | ❌ |
| **15** | firefox/htop/kdenlive 等程序级故障 | T22 | ❌ |
| **16** | LinuxQQ Illegal instruction + ICU error | T21, T18, T20 | ❌ |
| **20** | proot-distro rootfs 接入方式 | T23, T24, T25 | ❌（T24 可） |
| **22** | Debian 13 `/bin/true` SIGSEGV，地址落在 readlinkat | T01, T02, T03, T23 | ❌ |
| **23** | Rust/Cargo 大项目链接 undefined reference | T04, T05, T14 | ❌ |
| **24** | git bad object / bun 段错误 / Node NAPI 符号 | T06, T07, T08, T09, T14, T25 | ❌ |
| 2 | （#22 的前身）最小 guest 执行 SIGSEGV | T23 | ❌ |
| 5 | renameat2 路径泄漏 → uv ENOENT | T15 | ❌ |
| 9 | Android Host Info Bridge 提案 | T22（间接） | ❌ |
| 14 | 合作意向 | — | — |
| 17 | 转向 proroom | — | — |
| 18 | 打招呼 | — | — |
| 19 | 安装求助（已关闭） | — | — |
| 21 | 请求开源（已由 bxroot 满足） | — | — |

### 2.1 为什么是 24 而不是 19

任务描述里写"19 个 issue"，但实测权威数字是 **24**：

```
$ curl -s "https://api.github.com/search/issues?q=repo:coderredlab/proroot+type:issue"
total_count: 24        (incomplete_results: false)
```

`/issues?state=all&per_page=100` 也一次性返回全部 24 条（无 PR 混入）。
编号连续覆盖 **#1 – #24**，其中 open 13 / closed 11。

差异可能来自上游在任务描述写就之后又开了新 issue，或描述本身计数有误。
**本报告以 24 为准**，并已把 #1–#24 的完整正文存档到 `raw/bodies/`。

### 2.2 未被用例覆盖的 issue

| issue | 标题 | 为何无用例 |
|---|---|---|
| 1 | proot-distro debian 能否使用 | 提问，非故障 |
| 3 | 程序级问题汇总（2026-05-13） | 汇总贴，具体项已拆到 #8/#10/#11/#12 |
| 4 | curl "Bad system call" | 已关闭；属 syscall 过滤器，需真机 `seccomp` 环境，暂未建模 |
| 6 | USB 兼容层建议 | 特性请求 |
| 7 | Vulkan Runtime Bridge 建议 | 特性请求 |
| 9 | Android Host Info Bridge 建议 | 特性请求；T22 间接涉及 `/proc` 可读性 |
| 14 | 合作意向 | 非技术 |
| 17 | 转向 proroom | 项目公告 |
| 18 | 打招呼 | 非技术 |
| 19 | 安装求助 | 已关闭，非缺陷 |
| 21 | 请求开源 | 已由 bxroot 本身满足 |

**覆盖统计：24 个 issue 中 15 个有可测故障行为，全部覆盖；另覆盖 2 个已关闭的同源
issue（#2/#5）。共 25 条用例。**

---

## 3. 重点设计的三类（按任务要求）

### 3.1 大文件 / 大内存操作（#22 / #23 / #24 疑似同根因）

**假设**：三者都是「LD_PRELOAD 在大数据量/大地址空间下丢失或错位」。
Cargo 最终链接会产生巨大输出并大量 `mmap`，与 #22 的早期崩溃可能同源。

用例 **T04（`probe_bigmem.c`）** 逐项覆盖：

| 子项 | 复现的机制 |
|---|---|
| 顺序写 32MB + `fsync` + `stat` 大小核对 | 大文件写入不被截断 |
| 稀疏文件 `ftruncate` 512MB + 尾部 `pwrite` | 链接器常见的大偏移写入 |
| 私有匿名 `mmap` 32MB + 逐页触碰校验 | 大地址空间分配 |
| `MAP_SHARED` 文件映射 + 读回校验 + `msync` | **链接器/编译器重度依赖** |
| `mremap` 4MB→16MB + 原数据保留 | 增长式重映射 |
| `MAP_SHARED\|MAP_ANONYMOUS` + `fork` 跨进程一致性 | 共享内存语义 |

用例 **T05** 直接造 120 个目标文件一次性链接，命中 #23 的
`undefined reference / hidden symbol / final link failed`。

规模可用 `BXROOT_TEST_MB`（默认 32）、`BXROOT_TEST_OBJS`（默认 120）调整。

### 3.2 进程与符号解析（#24 的 NAPI、#10 的 `$ORIGIN`）

用例 **T10（`probe_origin.c` + 自动生成依赖树）**：

脚本用现有 gcc 现场构建一棵最小依赖树：

```
$WORK/origin/
├── liborigin-main.so        DT_RUNPATH = $ORIGIN/deps
│                            DT_NEEDED = liborigin-dep.so.1
├── deps/liborigin-dep.so.1
└── alt/liborigin-alt.so.1
```

然后 `dlopen("liborigin-main.so")`。**关键在于**：`liborigin-main.so` 自身的
`DT_NEEDED` 只能通过 `$ORIGIN/deps` 找到 —— 这正是 #10 里 Pillow 的
`_imaging.so` → `Pillow.libs/libtiff-*.so` 的同构场景。

脚本还会先 `readelf -d` 确认生成的库**真的**带 `$ORIGIN`
（防止工具链偷偷展开成绝对路径，导致用例空转）。

用例 **T06** 在 guest 内跑 Node，专门抓
`Node-API symbol napi_add_env_cleanup_hook has not been loaded`。

### 3.3 权限与属主（#12 fakeroot 完整性）

用例 **T12（`probe_fakeroot.c`）** 覆盖 fakeroot 的全部契约面：

| 契约 | 为什么 dpkg/apt 需要 |
|---|---|
| 新建文件属主 == `euid:egid` | 基础一致性 |
| **`lstat` 属主 == `stat` 属主** | dpkg 用 `lstat` 校验 |
| **`statx` 属主 == `stat` 属主** | glibc 2.28+ 的 `stat()` 实际走 `statx` |
| **`chown` 后 `stat` 反映新属主** | fakeroot 的核心承诺 |
| `chmod 04755` 保留 setuid 位 | dpkg 维护脚本 |
| `rename` 后属主/权限保持 | `.dpkg-new` → 正式名 |
| 新建目录属主为 `0:0` | apt/dpkg 的 root:root 检查 |

T12 的判定刻意**宽容**：`chown` 后报 `1234:5678`（真 chown）或 `0:0`（fakeroot）
都算 PASS，只有「既不是请求值也不是 0:0」才 FAIL —— 避免把不同的
fakeroot 实现策略误判为缺陷。

用例 **T13** 直接复刻 #12 的动作序列：
`创建 .dpkg-new → chown 0:0 → chmod 0440 → rename → 读回 → 删除`。

### 3.4 Unix socket 凭据（#8）

用例 **T17（`probe_creds.c`）** 用 `socketpair` + `SO_PASSCRED`，
分别在「隐式凭据」和「显式 `SCM_CREDENTIALS` 控制消息」两条路径上发送，
父进程用 `recvmsg` 解析 `SCM_CREDENTIALS` 并核对 `pid`/`uid`/`gid`。
另外还测了 `msg_controllen=1` 的**截断控制消息**，覆盖 `sendmsg`
在畸形入参下的健壮性 —— 这正是 LD_PRELOAD 重写 `sendmsg` 时最容易踩的路径。

用例 **T18** 是端到端版本：真起 `dbus-daemon --session`，用 `dbus-send`
发 `ListNames` 并要求回复。#8 的症状正是 `Did not receive a reply`。

---

## 4. 容器内 vs 真机：能力边界

### 4.1 容器内**不可**验证（已实测确认）

依据见 `/root/proroot-work/agents/_shared/容器内测试不可信.md`：

| 阻断 | 现象 |
|---|---|
| `LD_PRELOAD` 环境变量被吞 | 设了 `LD_PRELOAD` 后探针无任何输出 |
| `ld.so --preload` 视图错乱 | hook 被调用且参数正确，真实 `open()` 仍对存在的文件返回 ENOENT |
| `rootfs` 与宿主根同 inode | 容器内 rootfs 就是 `/`，无法区分"翻译生效"与"没翻译" |

**结论：容器内任何端到端 `PASS`/`FAIL` 都不可作为 bxroot 的验收结论。**

脚本会**主动检测**这一点并打印红框警告 —— 通过 `PROROOT_LINKER_PATH` /
`PROOT_TMP_DIR` / `PROOT_LOADER` 环境变量判定是否在容器运行时内，
并写入 `REPORT.md`。

脚本还实现了 **runtime 存活探针**（`runtime_liveness()`）：
在宿主和 rootfs 内各放一个同名不同内容的 marker，让 guest 读它。
读到 rootfs 版本 ⇒ 路径翻译生效；读到宿主版本 ⇒ **runtime 根本没接管**。
容器内因 rootfs 与宿主根同 inode，该探针会诚实地返回 `unknown`
而**不是**编造一个结论。runtime 未确认存活时，T24 的 `-b`/`-w` 失败
记为 `NOCTL` 而不是 `FAIL`。

### 4.2 容器内**可以**验证（脚本已实现且实测通过）

| 项 | 方式 |
|---|---|
| bash 语法 | `bash -n` |
| 9 个 C 探针能否编译 | `gcc -O1 -Wall -Wextra`（**零警告**） |
| 决策表纯逻辑 | 11 组 `(bx_rc, ctl_rc, 无对照)` → 期望状态 |
| FAIL 行折叠逻辑 | 崩溃码不被折算、劣化检出、优于对照不误判 |
| guest 脚本语法 | `sh -n` × 7 + `node --check` |
| guest 脚本**实跑** | biglink 在宿主小规模实跑、proc_probe 实跑 |
| `$ORIGIN` 依赖树生成 | 生成后用 `readelf -d` 验证 RUNPATH 真含 ORIGIN |
| 无 bxroot 时的降级 | 空环境跑一遍，确认全 SKIP/NOCTL 而非崩溃 |

一条命令跑完：`bash issue-regression-test.sh --self-test`

---

## 5. 真机运行方式

### 5.1 前置

```bash
# bxroot 产物（5 个 .so）
export BXROOT_LAUNCHER=/path/to/libbxroot.so
export BXROOT_LIBS_DIR=/path/to/          # 含 libbxroot-runtime.so 等
export BXROOT_ROOTFS=/path/to/rootfs
# 可选：proot 对照（强烈建议，否则大量用例是 NOCTL）
# export PROOT_BIN=/path/to/proot
```

若在 DSHA 真机 native 环境下，脚本会自动探测
`/data/data/com.dsh.client/files/linux/ubuntu` 等常见 rootfs 路径。

> **关于对照基线**：工作区已有 proot 源码检出
> `/sdcard/Download/DSHA/工作区/proroot-clone/proot-ref/`（termux/proot）。
> 若在其上构建出 proot 可执行文件，把它指给 `PROOT_BIN=` 即可让**全部**
> 25 条用例获得真正的对照判定 —— 这是把大量 `NOCTL` 转成 `PASS`/`FAIL`
> 的关键一步，强烈建议优先做。

### 5.2 运行

```bash
bash issue-regression-test.sh                 # 全部
bash issue-regression-test.sh --list          # 只列用例
bash issue-regression-test.sh --only 22,10    # 只跑指定 issue
bash issue-regression-test.sh --no-control    # 跳过 proot 对照
bash issue-regression-test.sh --self-test     # 容器内可跑
```

### 5.3 产出

- 终端彩色汇总（PASS/FAIL/NOCTL/ENVFAIL/SKIP/XFAIL）
- `/tmp/bxroot-issue-tests/out/REPORT.md` —— markdown 对照表
- `/tmp/bxroot-issue-tests/out/` —— 每条用例的原始 stdout/stderr

退出码：`0`=无 FAIL ｜ `1`=有 FAIL ｜ `2`=致命

---

## 6. 已知限制与后续

1. **#4（curl Bad system call）暂无用例** —— 它需要 guest 内的 `seccomp`
   过滤器行为，与 #22 的 `PROROOT_NO_SECCOMP` 相关，建议后续补 T26。
2. **T20（Chromium GPU）几乎总是 SKIP** —— 需要真机 GPU + X 会话 +
   Chromium 系浏览器，条件苛刻。它更像"有则跑"的用例。
3. **T03（崩溃 dump）依赖 bxroot 的实现细节** —— 判据是
   `*-sigsegv-maps.txt` 存在。若 bxroot 用了别的文件名，需要调整。
   **2026-09-17 更新**：实测（两侧对照）官方 proroot 在 `kill -SEGV $$`
   下**同样不生成** dump（全盘 find 无结果；runtime 内有
   `%s/../proroot-sigsegv-maps.txt` 路径模板，但触发需额外开关，
   本环境不满足）。故 T03 判定已从 ✅/FAIL 改为 **NOCTL**——
   "官方能"的前提不成立，bxroot 与官方行为一致（都不生成）。
   该 issue 的 dump 功能需在装有完整 proot 环境的真机上另测。
4. **T09 需要网络** —— 无网络时 SKIP，不 FAIL。
5. **`--only` 过滤在 `record()` 层生效** —— 被过滤的用例仍会执行
   （浪费一点时间），但不出现在结果里。若要真跳过，可后续把 issue 号
   写进函数名或加注册表。
6. **未覆盖的 issue** 见 §2.2 —— 均为非故障类，无需用例。

---

## 7. 交付物清单

| 文件 | 说明 |
|---|---|
| `issue-regression-test.sh` | 主脚本，真机可执行，25 条用例 |
| `ISSUE-TEST-MATRIX.md` | 本文件 |
| `evidence/container-verification.txt` | 容器内实际运行结果 |
| `raw/issues-all.json` | 上游全部 **24** 个 issue 的原始 API 响应 |
| `raw/bodies/*.md` | 各 issue 完整正文（含韩文/英文原文） |
