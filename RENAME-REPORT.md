# proroot-clone → bxroot 重命名报告

工作目录：`/root/proroot-work/agents/rename-bxroot/`
源基线：`/root/proroot-work/`（只读，未改动）
DSHA 主项目：`/sdcard/Download/DSHA/工作区/DSHA/`（**只读，未改动**，仅在本报告中列出待改位置）

---

## 0. 摘要

| 项 | 结果 |
|---|---|
| 改动文件数 | **10**（9 个源码/Makefile + 1 个文档） |
| 标识符替换处数 | **136 处**（机械替换）+ **10 处**上下文语义修正 = **146 处** |
| 改动行数 | 261 行 |
| 编译 | ✅ `make CC=gcc BUILD_DIR=build` 退出码 0，**0 error**，19 warning（与改名前基线**逐条一致**） |
| 产物 | ✅ 5 个 `libbxroot*.so`，产物内 `proroot` 字符串计数 **全部为 0** |
| DSHA Java 侧待改 | **4 个主文件 + 3 个测试 + 1 个调试文件 + 资源文件**，详见第 4 节 |
| 最严重的坑 | `WebProcSel.java` 不改 → **DSHA 会误杀自己的容器启动器进程**（机制见 4.2） |

---

## 1. 交付物

```
/root/proroot-work/agents/rename-bxroot/
├── Makefile                     ← 已改（target 名 + 依赖 + install/clean）
├── RENAME-REPORT.md             ← 本报告
├── docs/ARCHITECTURE.md         ← 已改
├── src/
│   ├── config.h                 ← 已改
│   ├── preload.c                ← 已改
│   ├── launcher/launcher.c      ← 已改（改动最多）
│   ├── linker/linker.c          ← 已改
│   ├── bridge/bridge.c          ← 已改
│   ├── runtime/config.h         ← 已改
│   ├── runtime/preload.c        ← 已改
│   └── stub-loader/stub-loader.c← 已改
└── build/                       ← 编译产物（5 个 libbxroot*.so）
```

---

## 2. 完整改动清单

### 2.1 逐文件替换统计

替换规则（**按顺序**应用，长 token 优先，避免 `proroot`→`bxroot` 破坏 `libproroot`）：

```
libproroot → libbxroot      LIBPROROOT → LIBBXROOT      PROROOT → BXROOT
proroot    → bxroot         Broot      → Bxroot         broot   → bxroot
```

| # | 文件 | 行数 | 替换处数 | 明细 |
|---|---|---|---|---|
| 1 | `Makefile` | 92 | **29** | `libproroot`×24, `PROROOT`×1, `proroot`×2, `Broot`×1, `broot`×1 |
| 2 | `docs/ARCHITECTURE.md` | 88 | **20** | `libproroot`×14, `PROROOT`×3, `proroot`×3 |
| 3 | `src/config.h` | 28 | **6** | `PROROOT`×5, `proroot`×1 |
| 4 | `src/preload.c` | 222 | **2** | `PROROOT`×2 |
| 5 | `src/launcher/launcher.c` | 343 | **43** | `libproroot`×5, `LIBPROROOT`×6, `PROROOT`×20, `proroot`×3, `broot`×9 |
| 6 | `src/linker/linker.c` | 93 | **6** | `libproroot`×2, `PROROOT`×3, `proroot`×1 |
| 7 | `src/bridge/bridge.c` | 158 | **6** | `libproroot`×1, `PROROOT`×3, `proroot`×2 |
| 8 | `src/runtime/config.h` | 49 | **8** | `PROROOT`×5, `proroot`×2, `broot`×1 |
| 9 | `src/runtime/preload.c` | 585 | **9** | `PROROOT`×8, `proroot`×1 |
| 10 | `src/stub-loader/stub-loader.c` | 290 | **7** | `libproroot`×3, `PROROOT`×2, `proroot`×2 |
| | **合计** | **1 948** | **136** | |

> 替换经程序化校验：`rename(原文件) == 改名后文件` 逐字节成立，且改名后源码树内 `proroot/PROROOT/broot/Broot` 残留 **0** 处（第 2.4 节的有意保留除外）。

### 2.2 约束 A：5 个 .so 文件名（Makefile）

| 旧 | 新 |
|---|---|
| `libproroot.so` | `libbxroot.so` |
| `libproroot-runtime.so` | `libbxroot-runtime.so` |
| `libproroot-linker.so` | `libbxroot-linker.so` |
| `libproroot-stub-loader.so` | `libbxroot-stub-loader.so` |
| `libproroot-bridge.so` | `libbxroot-bridge.so` |

**Makefile 同步改动**（target 名与依赖）：

| 位置 | 旧 | 新 |
|---|---|---|
| L18–22 | `TARGETS = build/libproroot*.so ×5` | `TARGETS = build/libbxroot*.so ×5` |
| L29 | `$(BUILD_DIR)/libproroot.so: src/launcher/launcher.c` | `$(BUILD_DIR)/libbxroot.so: ...`（脚本自动变量 `$@` 一并生效） |
| L34 | `$(BUILD_DIR)/libproroot-runtime.so: src/runtime/preload.c src/runtime/config.h` | `libbxroot-runtime.so` |
| L39 | `$(BUILD_DIR)/libproroot-linker.so: src/linker/linker.c` | `libbxroot-linker.so` |
| L44 | `$(BUILD_DIR)/libproroot-bridge.so: src/bridge/bridge.c` | `libbxroot-bridge.so` |
| L49 | `$(BUILD_DIR)/libproroot-stub-loader.so: src/stub-loader/stub-loader.c` | `libbxroot-stub-loader.so` |
| L54 | `INSTALL_DIR = /data/local/tmp/broot` | `INSTALL_DIR = /data/local/tmp/bxroot` |
| L58–62 | `install:` 5 条 `cp` 源文件名 | 改为 `libbxroot*.so` |
| L70–76 | `install-dsha:` 5 条 `cp` + `ls .../libproroot*` | 改为 `libbxroot*.so` / `libbxroot*` |
| L80–81 | `clean:` `rm -f libproroot.so` / `libproroot-*.so` | `libbxroot.so` / `libbxroot-*.so` |
| L85 | `debug: CFLAGS += -DPROROOT_VERBOSE=1 -g` | `-DBXROOT_VERBOSE=1` |

> ⚠️ `debug` target 的 `-DBXROOT_VERBOSE=1` 必须与 `src/runtime/config.h`、`src/linker/linker.c`、`src/bridge/bridge.c` 里的 `#ifndef BXROOT_VERBOSE` 同步，否则 debug 构建打了宏也不出日志。

**C 侧文件名字符串常量**：

| 文件:行 | 旧 | 新 |
|---|---|---|
| `src/launcher/launcher.c:39` | `#define LIBPROROOT_RUNTIME "libproroot-runtime.so"` | `LIBBXROOT_RUNTIME "libbxroot-runtime.so"` |
| `src/launcher/launcher.c:40` | `#define LIBPROROOT_LINKER "libproroot-linker.so"` | `LIBBXROOT_LINKER "libbxroot-linker.so"` |
| `src/launcher/launcher.c:41` | `#define LIBPROROOT_STUB_LOADER "libproroot-stub-loader.so"` | `LIBBXROOT_STUB_LOADER "libbxroot-stub-loader.so"` |
| `src/linker/linker.c:52` | `strstr(filename, "libproroot-runtime")` | `strstr(filename, "libbxroot-runtime")` |
| `src/stub-loader/stub-loader.c:66` | `"%s/libproroot-runtime.so"` | `"%s/libbxroot-runtime.so"` |
| `src/stub-loader/stub-loader.c:280` | `"%s/libproroot-runtime.so"` | `"%s/libbxroot-runtime.so"` |

### 2.3 约束 B：环境变量 `PROROOT_*` → `BXROOT_*`

**全部 14 个 token 已改**（`grep -rhoE 'BXROOT_[A-Z_]+' src/` 实测）：

| 旧名 | 新名 | 由谁 **写入** | 由谁 **读取** |
|---|---|---|---|
| `PROROOT_ROOTFS` | `BXROOT_ROOTFS` | launcher `:225`（值来自 `-r`） | `runtime/preload.c:92`、`src/preload.c:20` |
| `PROROOT_TMP_DIR` | `BXROOT_TMP_DIR` | launcher `:227-228`；**DSHA Java** | `runtime/preload.c:96` |
| `PROROOT_GUEST_EXE` | `BXROOT_GUEST_EXE` | launcher `:229` | `runtime/preload.c:100` |
| `PROROOT_WORKDIR` | `BXROOT_WORKDIR` | launcher `:230` | `runtime/preload.c:108` |
| `PROROOT_FAKEROOT` | `BXROOT_FAKEROOT` | launcher `:233/235` | `runtime/preload.c:112` |
| `PROROOT_VERBOSE` | `BXROOT_VERBOSE` | launcher `:238/240`；Makefile `-D` | `runtime/config.h:20/24`、`runtime/preload.c:104`、`linker.c:18/22`、`bridge.c:27/31` |
| `PROROOT_BINDS` | `BXROOT_BINDS` | launcher `:259` | `runtime/preload.c:53` |
| `PROROOT_LIB_PATH` | `BXROOT_LIB_PATH` | **DSHA Java** | launcher `:205` |
| `PROROOT_LINKER_PATH` | `BXROOT_LINKER_PATH` | **DSHA Java**；launcher `:244` | （仅 launcher 写出） |
| `PROROOT_STUB_LOADER` | `BXROOT_STUB_LOADER` | **DSHA Java**；launcher `:246` | `stub-loader.c:253`（写入 `"1"`） |
| `PROROOT_RUNTIME_LIB` | `BXROOT_RUNTIME_LIB` | （当前无人设置） | `stub-loader.c:63` |
| `PROROOT_DEFAULT_ROOTFS` | `BXROOT_DEFAULT_ROOTFS` | 编译期宏（launcher `:34-36`） | launcher `:95` |
| `PROROOT_RUNTIME` | `BXROOT_RUNTIME` | 编译期宏（launcher `:39`） | launcher `:211` |
| `PROROOT_LINKER` | `BXROOT_LINKER` | 编译期宏（launcher `:40`） | launcher `:217` |

**非环境变量的标识符**：

| 文件:行 | 旧 | 新 |
|---|---|---|
| `src/runtime/config.h:43` | `} proroot_config_t;` | `} bxroot_config_t;` |
| `src/runtime/config.h:46` | `extern proroot_config_t g_config;` | `extern bxroot_config_t g_config;` |
| `src/runtime/preload.c:18` | `proroot_config_t g_config = {0};` | `bxroot_config_t g_config = {0};` |
| `src/bridge/bridge.c:38` | `#define BRIDGE_SOCKET "/tmp/.proroot-bridge-%d.sock"` | `"/tmp/.bxroot-bridge-%d.sock"` |
| `src/stub-loader/stub-loader.c:139` | `"/tmp/.proroot_stub_%ld_%s"` | `"/tmp/.bxroot_stub_%ld_%s"` |

### 2.4 约束 C：日志前缀 / 错误信息 / 注释

| 文件:行 | 旧 | 新 |
|---|---|---|
| `src/launcher/launcher.c` ×9 | `[broot-launcher]` | `[bxroot-launcher]` |
| `src/runtime/config.h:26` | `[broot]` | `[bxroot]` |
| `src/config.h:22` | `[proroot-clone]` | `[bxroot]`（见 2.5 修正） |
| `src/linker/linker.c:23` | `[proroot-linker]` | `[bxroot-linker]` |
| `src/bridge/bridge.c:32` | `[proroot-bridge]` | `[bxroot-bridge]` |

**默认 rootfs 路径**：`/data/local/tmp/rootfs` 本身**不含** `proroot` 字样，路径值**保持原样未动**（3 处 `#define`）。只有 Makefile 的安装目录 `/data/local/tmp/broot` → `/data/local/tmp/bxroot` 变了。

> 如果你希望默认 rootfs 也改名（例如 `/data/local/tmp/bxroot/rootfs`），需要额外改 3 处（`launcher.c:35`、`config.h:9`、`runtime/config.h:10`）**并且**同步 `ContainerRuntime.java:147` 传的 `-r` 值 —— 我**没有**做这个改动，因为它是数据路径而非命名标识，改了会找不到既有 rootfs。

### 2.5 机械替换后的人工语义修正（10 处）

机械替换会把「**指代上游 proroot 项目**」的文字也改成 `bxroot`，产生自指错误（"对标 bxroot 的 libbxroot.so"）。已逐一修正：

| 文件:行 | 机械替换后（错误） | 修正为 |
|---|---|---|
| `launcher.c:5` | `对标 bxroot 的 libbxroot.so` | `原名 libproroot.so / proroot-clone，现更名 libbxroot.so / bxroot` + `对标上游闭源项目 proroot 的同名入口库` |
| `launcher.c:8` | `bxroot-clone [options] ...` | `bxroot [options] ...` |
| `launcher.c:265` | `避免与系统 bxroot 冲突` | `避免与系统原有 proroot 冲突` |
| `config.h:22` | `[bxroot-clone]` | `[bxroot]` |
| `stub-loader.c:15` | `参考：bxroot 的 stub-loader 实现` | `参考：上游 proroot 的 stub-loader 实现` |
| `docs/ARCHITECTURE.md:1` | `# bxroot-clone 架构设计` | `# bxroot 架构设计` |
| `docs/ARCHITECTURE.md:5` | `对标 bxroot 的 5 个 .so` | `对标上游闭源项目 proroot 的 5 个 .so` |
| `docs/ARCHITECTURE.md:83` | `（对标 bxroot）` | `（对标上游 proroot）` |
| `Makefile:2` | `（兼容 DSHA bxroot 接口）` | `（DSHA bxroot 原生库接口）` |
| `Makefile:66` | `（替换原 bxroot）` | `（替换原 proroot 库）` |

**有意保留的 `proroot` 字样（5 处，均为上游溯源，不是标识符）**：

- `src/launcher/launcher.c:5-6`（历史沿革注释）
- `src/launcher/launcher.c:265`（"避免与系统原有 proroot 冲突"）
- `src/stub-loader/stub-loader.c:15`（参考上游实现）
- `Makefile:66`（部署注释）
- `docs/ARCHITECTURE.md:5, 83`（对标上游项目）

> 这些是**散文里对上游项目的指称**，不是文件名/变量名/日志前缀，保留才不会丢失溯源信息。若你要求源码树内 `proroot` 字样绝对为零，删掉这 5 处即可，不影响编译。

---

## 3. 编译验证

### 3.1 命令与结果

```bash
cd /root/proroot-work/agents/rename-bxroot && make CC=gcc BUILD_DIR=build
```

| 项 | 结果 |
|---|---|
| 退出码 | **0** |
| error | **0** |
| warning | **19**（与改名前基线**完全一致**，见 3.3） |
| gcc | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| 二次 `make` | `make: Nothing to be done for 'all'.`（依赖关系正确，无重复构建） |

### 3.2 产物（约束 A 验证通过）

| 文件 | 大小 | 类型 | MD5 |
|---|---|---|---|
| `build/libbxroot.so` | 706 544 | ELF 64-bit LSB **executable**, ARM aarch64, **static** | `bae3d078e9cb56b035b193f27d8d6b21` |
| `build/libbxroot-runtime.so` | 70 680 | ELF 64-bit LSB shared object, ARM aarch64 | `bb7306735c3b25febae4afce62905ba9` |
| `build/libbxroot-linker.so` | 67 840 | ELF 64-bit LSB shared object, ARM aarch64 | `261bee426d6d5737ceeda16c71ae2ce4` |
| `build/libbxroot-bridge.so` | 68 632 | ELF 64-bit LSB shared object, ARM aarch64 | `2f3b15d4aa7b7040ed21c1b326627a2a` |
| `build/libbxroot-stub-loader.so` | 68 704 | ELF 64-bit LSB shared object, ARM aarch64 | `dea508255e0b7bff99571c38a49448f8` |

- `build/` 内**无**任何 `*proroot*` 残留文件名。
- 5 个产物 `strings | grep -ci proroot` **全部为 0**（改名前为 13/7/0/3/1）。
- `libbxroot.so` 内嵌 `BXROOT_ROOTFS/TMP_DIR/GUEST_EXE/WORKDIR/FAKEROOT/VERBOSE/BINDS/LIB_PATH/LINKER_PATH/STUB_LOADER` 共 10 个变量名 + 9 条 `[bxroot-launcher]` 日志，全部为新名。
- `libbxroot-runtime.so` 内嵌 7 个 `BXROOT_*` 变量名。

### 3.3 无回归证据

与改名前基线（`/root/proroot-work/src` + 原 Makefile，同一 gcc）对照：

| 指标 | 改名前 | 改名后 |
|---|---|---|
| 退出码 / error | 0 / 0 | 0 / 0 |
| warning 总数 | 19 | 19 |
| warning 逐条归一化 diff | — | **仅 2 条的文案内文件名不同**（`'/libproroot-runtime.so' directive output may be truncated` → `'/libbxroot-runtime.so' ...`），其余 17 条**逐字节相同** |

> 说明：这 19 条 warning 是**既有代码问题**（`_GNU_SOURCE` 重定义、`launcher.c:291` format 参数个数不匹配、`stub-loader.c` 未使用函数/悬垂指针等），**不是本次改名引入的**。
> 额外佐证：`libbxroot-linker.so` 与仓库中既有的 `libproroot-linker.so` **MD5 完全相同**（`261bee42…`）——因为 `linker.c` 里所有含 `proroot` 的字符串都只出现在被 `#if BXROOT_VERBOSE`（默认 0）编译掉的 `LOG()` 宏里，改名后代码生成完全等价。

---

## 4. ⚠️ DSHA Java 侧需要同步修改的精确位置

> 行号基于当前 `/sdcard/Download/DSHA/工作区/DSHA/` 树快照。

### 4.1 【必须改】`ContainerRuntime.java` —— 5 个文件名 + 4 个环境变量

**路径**：`app/src/main/java/com/deepseekharness/app/runtime/ContainerRuntime.java`

| 行号 | 现在是什么 | 应该改成什么 | 类别 |
|---|---|---|---|
| **99** | `"libproroot.so",` | `"libbxroot.so",` | 约束 A · LIBS 数组 |
| **100** | `"libproroot-runtime.so",` | `"libbxroot-runtime.so",` | 约束 A |
| **101** | `"libproroot-linker.so",` | `"libbxroot-linker.so",` | 约束 A |
| **102** | `"libproroot-stub-loader.so",` | `"libbxroot-stub-loader.so",` | 约束 A |
| **103** | `"libproroot-bridge.so",` | `"libbxroot-bridge.so",` | 约束 A |
| **146** | `argv.add(new File(dir, "libproroot.so").getAbsolutePath());` | `argv.add(new File(dir, "libbxroot.so").getAbsolutePath());` | 约束 A · 启动器路径 |
| **171** | `pb.environment().put("PROROOT_TMP_DIR", tmpDir.getAbsolutePath());` | `put("BXROOT_TMP_DIR", ...)` | **约束 B · 破坏性** |
| **172-173** | `put("PROROOT_LIB_PATH", new File(dir, "libproroot-runtime.so")...)` | `put("BXROOT_LIB_PATH", new File(dir, "libbxroot-runtime.so")...)` | **约束 B · 破坏性** |
| **174-175** | `put("PROROOT_LINKER_PATH", new File(dir, "libproroot-linker.so")...)` | `put("BXROOT_LINKER_PATH", new File(dir, "libbxroot-linker.so")...)` | **约束 B · 破坏性** |
| **176-177** | `put("PROROOT_STUB_LOADER", new File(dir, "libproroot-stub-loader.so")...)` | `put("BXROOT_STUB_LOADER", new File(dir, "libbxroot-stub-loader.so")...)` | **约束 B · 破坏性** |

**📌 对你原始任务描述的一处事实更正**：你说"这些变量名同时被 DSHA 的 Java 代码设置（`ContainerRuntime.java` 第 171-177 行）"，其中 **`PROROOT_ROOTFS` 并不在 Java 侧设置**。实测 Java 只设置 4 个变量：`PROROOT_TMP_DIR`、`PROROOT_LIB_PATH`、`PROROOT_LINKER_PATH`、`PROROOT_STUB_LOADER`。
`ROOTFS` 是由 **launcher 自己**从命令行 `-r` 解析后 `setenv` 的（C 侧 `launcher.c:225`，值来自 Java 的 `baseArgv()` 第 147-148 行 `-r rootfsDir`）。
**结论**：改名后 DSHA **不会**因为 `ROOTFS` 对不上而退回 `/data/local/tmp/rootfs`（因为 ROOTFS 从不经 Java 的环境变量传递）；真正的断点在下面 4 个变量。

**仅改注释（不影响行为，可选）**：L10、L15、L18、L95、L122、L124、L183、L192。

---

### 4.2 【必须改，否则会误杀自己】`WebProcSel.java` —— 进程自杀保护

**路径**：`app/src/main/java/com/deepseekharness/app/util/WebProcSel.java`

| 行号 | 现在是什么 | 应该改成什么 |
|---|---|---|
| **87** | `if (argv.length > 0 && basename(argv[0]).equals("libproroot-bridge.so"))` | `.equals("libbxroot-bridge.so")` |
| **89** | `if (cmdline.contains("libproot.so") \|\| cmdline.contains("libproroot")` | `... \|\| cmdline.contains("libbxroot")` |
| **106** | `!basename(argv[1]).equals("libproroot-linker.so")` | `.equals("libbxroot-linker.so")` |
| **108** | `!basename(argv[5]).equals("libproroot-runtime.so")` | `.equals("libbxroot-runtime.so")` |
| **126** | `basename(args[0]).equals("libproroot-bridge.so")` | `.equals("libbxroot-bridge.so")` |
| 15、84 | 注释里的 `libproroot` | `libbxroot`（可选） |

#### 🔴 不改会怎样（这是本次改名最危险的一处）

`WebProcSel.looksLikeWeb()` 的第 89-92 行是**唯一**识别并排除「容器启动器」的关卡：

```java
if (cmdline.contains("libproot.so") || cmdline.contains("libproroot") || cmdline.contains("proot")) {
    return false;   // ← 是启动器，绝不当作 Web 进程
}
```

换成 bxroot 库后，启动器 cmdline 变成 `.../libbxroot.so -r <rootfs> -0 -w /root -b ... --link2symlink /usr/local/bin/node .../lib/bin.js web`：

- `libbxroot.so` 不含子串 `proot`（`l-i-b-b-x-r-o-o-t`，无 `p`），**也不含 `libproroot`** → 上面 3 个条件**全部不命中**；
- 于是继续往下走到 L94：`cmdline.contains("bin.js") && cmdline.contains("web")` → **命中**（启动器 argv 里原样带着 guest 的 `node ... bin.js web`）；
- `looksLikeWeb()` 返回 `true` → **承载整个容器的启动器进程被判定为 Web 进程并被结束**。

这与 `docs/proroot-startup-fix-2026-09-09.md` 记录的历史事故是同一类根因（判据关键字不匹配 → 自杀保护失效）。

> 注意：**不要**删掉 L90 的 `cmdline.contains("proot")` —— 它仍然负责 `libproot.so` 那条路径。只需把 L89 的 `"libproroot"` 换成 `"libbxroot"`（保留三者并存的写法）。

---

### 4.3 【必须改】`nativeLibraryDir` 里的 5 个 .so 实体文件

**路径**：`app/src/main/jniLibs/arm64-v8a/`

```
libproroot.so              →  libbxroot.so
libproroot-runtime.so      →  libbxroot-runtime.so
libproroot-linker.so       →  libbxroot-linker.so
libproroot-bridge.so       →  libbxroot-bridge.so
libproroot-stub-loader.so  →  libbxroot-stub-loader.so
```

- Android 打包对 `jniLibs` 的命名要求是 `lib*.so`，`libbxroot*.so` **满足**，不影响 APK 打包与 `nativeLibraryDir` 解压。
- 新库 MD5 见 3.2。注意 `libbxroot-linker.so` 的 MD5 与既有 `libproroot-linker.so` **相同**（见 3.3 说明），这是正常的，不是复制错误。

### 4.4 【必须改】`THIRD_PARTY_NOTICES.md`

**路径**：`THIRD_PARTY_NOTICES.md`

| 行号 | 现在是什么 | 应该改成什么 |
|---|---|---|
| **30-31** | `在包内的位置：`lib/arm64-v8a/libproroot.so`、`libproroot-runtime.so`、`libproroot-linker.so`、`libproroot-stub-loader.so`、`libproroot-bridge.so`` | 改为 `libbxroot*.so` 五个新名 |
| **38-42** | 5 行 `MD5  libproroot*.so` | 文件名改新名 + **哈希替换为 3.2 表中的新 MD5** |

> L24-L26（上游项目 `## proroot` / `coderredlab/proroot` 来源）与 L64 是**许可证溯源**，**不要改** —— 闭源上游的署名必须保留。

### 4.5 【不改会导致单测失败】测试文件

| 文件 | 行号 | 现在是什么 | 应该改成什么 |
|---|---|---|---|
| `app/src/test/java/com/deepseekharness/app/util/WebProcSelTest.java` | **11** | `"libproroot-bridge.so /data/app/.../libproroot-linker.so "` | `libbxroot-bridge.so` / `libbxroot-linker.so` |
| 同上 | **12** | `"--preload /data/app/.../libproroot-runtime.so "` | `libbxroot-runtime.so` |
| 同上 | **21** | `"libproroot.so -r /rootfs "` | `libbxroot.so` |
| 同上 | **29** | `command.replace("libproroot-linker.so", "other.so")` | `libbxroot-linker.so` |
| 同上 | **31** | `"libproroot-bridge.so dsh web"` | `libbxroot-bridge.so` |
| 同上 | **56** | `"libproroot-runtime.so -r ..."` | `libbxroot-runtime.so` |
| 同上 | 51 | 注释 `proot/proroot 命令行`（可选） | `proot/bxroot` |
| `app/src/test/java/com/deepseekharness/app/util/DeviceAppPolicyTest.java` | **34** | 进程名样本 `... libproroot-bridge.so\n` | `libbxroot-bridge.so` |
| `app/src/test/java/com/deepseekharness/app/util/ProcessIdentityTest.java` | **57** | `"/lib/libproroot.so"` | `"/lib/libbxroot.so"` |

### 4.6 【调试构建】`app/src/debug/`

| 文件 | 行号 | 现在是什么 | 应该改成什么 | 是否必须 |
|---|---|---|---|---|
| `runtime/MaintenanceFixtureInstrumentation.java` | **353** | `"/app/libproroot.so -r /fixture ..."` | `"/app/libbxroot.so ..."` | ✅ 必须（fixture 用例会失配） |
| 同上 | 354 | 断言文案 `包含完整 dsh 参数的 proroot launcher 仍被排除` | 文案改为 bxroot（可选） | 可选 |
| `runtime/RuntimeStartupAudit.java` | **251, 253, 254** | `PROROOT_CHILD=` / `PROROOT_GROUP_TIMEOUT_CLEANED` | **不是环境变量**，只是 printf 标记串，脚本内自洽 → 可不改 | 可选 |
| 同上 | 284, 303, 312, 317 | `runtime.equals("proroot")`、`{"proot", "proroot"}` | 见 4.7（这是**持久化 id**，见风险 R4） | ⚠️ 见 R4 |
| `core/RuntimeFallbackAudit.java` | 20 | `DSHA_TEST_PROROOT_EXIT` | 仅为标记串，自洽 → 可不改 | 可选 |

### 4.7 【⚠️ 持久化契约，别乱改】运行时 id 字符串 `"proroot"`

`ContainerRuntime.java:122` 的 `id()` 返回 `"proroot"`，这个**不是文件名**，而是**写进 SharedPreferences 的持久化值**：

- `ConfigStore.java:175` → `return "proroot".equals(text(Constants.KEY_CONTAINER_RUNTIME, "proot"));`
- `ConfigStore.java:179` → `prefs.edit().putString(Constants.KEY_CONTAINER_RUNTIME, v ? "proroot" : "proot")`
- `ProotBootstrap.java:754` → `"proroot".equals(ctx.getSharedPreferences("deepseekharness", ...))`
- `ProotBootstrap.java:914`、`1196`、`857` → `new ContainerRuntime.Proroot(...)`
- `HarnessController.java:241 / 487 / 503`、`WebRuntimeFallback.java:8`、`StartupText.java:35` 都以 `"proroot"` 字面量做判断
- `Constants.java:63` → `/** 容器运行时：proroot / proot。 */`

**如果你把 `id()` 改成 `"bxroot"`，必须同时提供 SharedPreferences 迁移**，否则已升级用户的偏好值 `"proroot"` 会匹配不上 → `isProroot()` 返回 false → **静默降级回 proot**（用户以为在用 bxroot，实际跑的是 proot）。
另外 `StartupText.java:35` 的正则 `^(proot|proroot)(?: 进程退出…)` 与 `HarnessController.java:487` 的退出识别，也依赖这个字面量。
**最小风险做法**：本次只改文件名与环境变量，**`id()` 保留 `"proroot"`**（或用 `"proroot"` 作为存量值 + `"bxroot"` 作为新值并写迁移）。

### 4.8 【仅显示文案，可选】UI 字符串

| 文件 | 行号 | 内容 |
|---|---|---|
| `app/src/main/res/values/ui_strings.xml` | 56 | `使用 proroot 运行时`（`ui_m0054`） |
| 同上 | 113 | `尝试使用 proroot 加快容器运行…`（`ui_m0111`） |
| `app/src/main/res/values-en/ui_strings.xml` | 61、118 | 英文对应项 |
| `tools/i18n/messages.json` | 487-488、947-948、8930-8963 | i18n 源表（改 `ui_strings.xml` 后需同步重生成） |
| `app/src/main/java/.../runtime/ContainerRuntime.java` | 124 | `displayName()` = `"proroot（实验，零 ptrace 开销）"` |

> 这些只影响界面显示，不影响功能。若要改，注意 `ui_strings.xml` 与 `tools/i18n/messages.json` 是生成关系，需一起改。

### 4.9 【文档，可选】

`docs/proroot-experiment-plan.md`（35 处）、`docs/proroot-startup-fix-2026-09-09.md`（1 处）：L27 的 `PROROOT_TMP_DIR`、L136-140 的 5 个文件名 + MD5、L107 的启动器文件名、L242 的 `PROROOT_LIB_PATH`/`PROROOT_LINKER_PATH` 属于**接口描述**，建议同步；其余是对上游项目的叙述，建议保留。

---

## 5. 风险提示

### R1 🔴 环境变量改名是破坏性变更（最高风险）

Java 侧（`ContainerRuntime.java:171-177`）与 C 侧是**跨进程契约**，只改一边必然对不上。

| 如果只改了 C 侧，Java 仍传 `PROROOT_*` | 新库的实际行为 | 严重度 |
|---|---|---|
| `BXROOT_TMP_DIR` 取不到值 | 回退 `strdup("/tmp")`（`runtime/preload.c:97`）。**Android app 沙箱内 `/tmp` 不可写** → stub-loader 临时文件创建失败 | 🔴 高 |
| `BXROOT_LIB_PATH` 取不到值 | 回退 `dirname(/proc/self/exe)/libbxroot-runtime.so`（`launcher.c:211`）—— 5 个库同在 `nativeLibraryDir` 时**恰好能work** | 🟡 中（侥幸可用，但掩盖问题） |
| `BXROOT_LINKER_PATH` / `BXROOT_STUB_LOADER` 取不到值 | launcher 用 `lib_dir` 自动探测（`launcher.c:217-222`）→ 通常可用 | 🟢 低 |
| `BXROOT_ROOTFS` 取不到值 | ⚠️ **不会发生**：该变量从不由 Java 设置，由 launcher 从 `-r` 自行 `setenv` | — |

**反向（Java 改了、库没换）**：`Proroot.available()` 检查 `libproroot*.so` 是否存在 → 返回 false → `ProotBootstrap.java:754-762` 打印「proroot 不可用，本次降回 proot」。**有降级保护，不会崩，但会静默失去 bxroot**。

### R2 🔴 `WebProcSel` 不更新 → 误杀启动器

机制见 4.2。后果不是"功能降级"而是"**容器刚起来就被自己杀掉**"，且现象（Web 进程莫名退出）与根因（关键字不匹配）距离很远，极难排查。历史同类事故见 `docs/proroot-startup-fix-2026-09-09.md`。

### R3 🟡 旧版本 DSHA + 新库 / 新版本 DSHA + 旧库 都不兼容

本次是**全量原子改名**，没有保留旧名别名。双向都不兼容，必须**同版本一起发**。`available()` 的文件存在性检查是一道安全网（会降级到 proot 而不是崩溃），但用户会感知为「bxroot 用不了」。

### R4 🟠 持久化 runtime id（见 4.7）

`id()` 的 `"proroot"` 存在 SharedPreferences 里。改它必须写迁移，否则存量用户静默降级。

### R5 🟡 `proot` 是 `proroot` 的子串 —— 批量替换时的反向陷阱

`proroot` → `bxroot` 是安全的（`proot` 中不含 `proroot`）。但**反过来** `s/proot/bxroot/` 会把 `libproot.so`、`libprootloader.so`、`libprootloader32.so`、`--kill-on-exit` 相关逻辑、以及 `"proot"` 这个持久化值全部破坏。
本次 C 侧只替换了 `proroot`/`broot` 系 token，**未触碰任何 `proot`**（`proot` 相关标识符在源码树内保持原样）。你在 DSHA 侧改的时候也要**逐 token 替换，不要用 `s/proot/`**。

### R6 🟡 APK 校验与署名哈希

`THIRD_PARTY_NOTICES.md:38-42` 与 `docs/proroot-experiment-plan.md:136-140` 记录了 5 个 .so 的 MD5。换文件后这些哈希全部失效，属于"文档与实物不一致"，需要同步（新 MD5 见 3.2）。

### R7 🟢 编译告警未清理

19 条 warning 是既有的（含 `launcher.c:291` 的 printf 参数个数不匹配这种**真实 bug**：格式串 `"...命令 %s (实际路径: %s) errno=%d %s"` 有 **4** 个占位符，但只传了 `cmd, resolved_path` **2** 个实参 → `errno` 与错误串会读到垃圾栈值。该分支正是「rootfs 内找不到命令」这条最常触发的报错路径）。本次**未修复**（超出改名范围），但建议后续单独处理。

### R8 🟢 本次未经验证的部分

- 只做了**编译验证**，**未做运行时验证**（容器内嵌套 proot，跑不了 LD_PRELOAD 真机语义 —— 参见 `/root/proroot-work/agents/_shared/容器内测试不可信.md`）。
- 未改动 `/sdcard/Download/DSHA/工作区/proroot-clone/` 与 `/sdcard/Download/DSHA/工作区/DSHA/`（遵守只读约束）。
- `Makefile` 里 `DSHA_PID = 862` 是硬编码 PID，`install-dsha` target 依赖它，与本改名无关但已失效风险。

---

## 6. 兼容方案建议（⚠️ **均为建议，本次未实现**）

> 明确标注：以下**一条都没有落地**。当前交付是**纯全量改名**，即"破坏性变更"版本。

### 方案 A：C 侧双读（推荐，成本最低）

在 `runtime/preload.c` / `launcher.c` 加一层取值辅助函数，先读 `BXROOT_*`，未命中再读 `PROROOT_*` 并打一条 deprecation warning：

```c
static const char *env_dual(const char *new_name, const char *old_name) {
    const char *v = getenv(new_name);
    if (v && v[0]) return v;
    v = getenv(old_name);
    if (v && v[0]) fprintf(stderr, "[bxroot] 警告: %s 已弃用，请迁移到 %s\n", old_name, new_name);
    return v;
}
```

- 收益：新旧 DSHA 都能启动新库，可灰度。
- 成本：约 12 个 `getenv` 调用点；`setenv` 侧建议**同时写两套**（`BXROOT_*` + `PROROOT_*`）以兼容旧 runtime。
- 注意：`runtime/config.h` 的 `BXROOT_VERBOSE` 是编译期宏，无法双读，需要 `#if defined(BXROOT_VERBOSE) || defined(PROROOT_VERBOSE)`。

### 方案 B：文件名保留双份（一个版本周期）

`jniLibs` 里同时放 `libbxroot*.so` 与 `libproroot*.so`（硬链接或同一份拷贝），Java 端 `LIBS` 数组按新名优先探测。下一个版本删掉旧的。
- 收益：`available()` 双向兼容，回滚零成本。
- 成本：APK 增大约 960 KB（5 个 .so 合计 982 400 字节 ≈ 959 KB，双份后翻倍）。

### 方案 C：版本协商

launcher 支持 `--abi-version 2`，或读取 `BXROOT_API_LEVEL`；Java 侧据此决定传哪套变量名。
- 收益：最干净，长期可维护。
- 成本：最高，需要两端同时改协议，且要处理"旧 launcher + 新 Java"的探测失败路径。

### 方案 D：只改内部标识，保留 5 个 .so 文件名（零风险）

放弃约束 A，只改环境变量、日志前缀、注释。这样 APK 侧改动面从 8 个文件缩到 2 个。
- **不推荐**：与"摆脱对 proroot 名字的依附"的初衷冲突，用户可见的仍是 `libproroot.so`。

### 推荐组合

**方案 A（环境变量双读）+ 方案 B（文件名双份，一个版本周期）**，随后在下一个大版本收敛为纯 `BXROOT_*`。

---

## 7. 附：验证命令留档

```bash
# 编译
cd /root/proroot-work/agents/rename-bxroot && make CC=gcc BUILD_DIR=build

# 产物名（应为 5 个 libbxroot*.so）
ls -la build/

# 产物内无旧名
for f in build/*.so; do echo "$f: $(strings $f | grep -ci proroot)"; done   # 应全为 0

# 源码树无旧标识符（仅第 2.5 节 5 处溯源注释除外）
grep -rn "PROROOT\|libproroot" src/ Makefile     # 应为空

# 新环境变量契约
grep -rhoE 'BXROOT_[A-Z_]+' src/ | sort -u
```
