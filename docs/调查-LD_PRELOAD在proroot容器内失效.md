# 调查：`LD_PRELOAD` 在 proroot 容器内静默失效（影响测试可信度）

> **结论**：在本项目当前所处的官方 proroot 容器内，**`LD_PRELOAD` 机制
> 完全不生效**（三种传入方式全部实测无效）。因此凡是用"launcher + 
> `LD_PRELOAD`"做加载的测试，**测的都不是 bxroot，而是外层 proroot**。
>
> 这是**测试可信度**问题，比功能缺陷更严重 —— 它会让"全绿"变成假象。
> 已定位受影响范围并给出可靠的替代加载路径。

---

## 一、现象

### 1.1 最小复现：连空构造函数都不执行

```sh
cat > mini.c <<'EOF'
#include <stdio.h>
__attribute__((constructor)) static void c(void){ fprintf(stderr,"[MINI] loaded!\n"); }
EOF
gcc -shared -fPIC -o /tmp/libmini.so mini.c

LD_PRELOAD=/tmp/libmini.so /bin/true
# 期望输出：[MINI] loaded!
# 实际输出：（空）
```

### 1.2 三种传入方式全部无效

| 方式 | 结果 |
|---|---|
| `LD_PRELOAD=... /bin/true`（shell） | ❌ 无输出 |
| `env LD_PRELOAD=... /bin/true` | ❌ 无输出 |
| `os.execve(..., {'LD_PRELOAD': ...})`（Python 直接 exec） | ❌ 无输出 |

★★ 第三条是最关键的证据 ★★

它排除了"shell 吞掉变量"这类解释：`execve` 的 `envp` 是**内核直接收到**的，
shell 层根本没有机会干预。变量确实进了内核，但 loader 没理它。

### 1.3 用 `/proc/<pid>/maps` 确认库未加载

```sh
BXROOT_LIB_PATH=$PWD/build/libbxroot-runtime.so bxroot-bin -r / -w / /bin/sleep 2 &
tr '\0' '\n' < /proc/$!/environ | grep LD_PRELOAD
#   LD_PRELOAD=/root/…/build/libbxroot-runtime.so     ← 环境变量**是对的**

grep -o 'libbxroot[a-z.-]*' /proc/$!/maps
#   （空）                                            ← 但库**没有被加载**
```

环境变量正确、库未加载 —— 这两条同时成立，就把"路径写错"这个解释也排除了。

---

## 二、根因

**官方 proroot 用自研 ELF 加载器（`libproroot-linker.so`）接管了 `execve`，
它不实现 `LD_PRELOAD` 语义。**

旁证（本项目早已知晓、但当时没意识到它对本测试的影响）：

| 证据 | 说明 |
|---|---|
| 官方自己的 runtime 也不走 `LD_PRELOAD` | 它用 `bridge + linker + --argv0 + --preload` 四件套（见 `test/RUN_E2E.sh` 开头的长注释） |
| 当前 shell 的 `LD_PRELOAD` 为空，而 maps 里有官方 runtime | 说明官方是**另一个机制**加载的 |
| `readelf --dyn-syms` 里 ldso 服务符号不在 linker 的导出表 | 它们是运行时注入的，与标准 ELF 加载流程不同 |

也就是说：**这不是 bug，是架构选择。** proroot 为了在 Android 上做
路径翻译，自己写了一套加载器，代价就是放弃标准 loader 的部分行为。

---

## 三、影响范围（★ 这是本节最重要的部分 ★）

### 3.1 受影响的测试

用 `launcher + LD_PRELOAD` 加载的，**在容器内跑测的都是 proroot**：

| 测试 | 影响 |
|---|---|
| `RUN_PATH_FORMS.sh` | B 基线（bxroot 侧）**测的是 proroot** |
| `RUN_FALLBACK.sh` | 同上（前提检查已正确地 SKIP，未产生假绿） |
| `RUN_L2S_E2E.sh` | 需逐条确认它用的是哪条路径 |
| `RUN_CLI_COMPAT.sh` | **不受影响** —— 它只测 CLI 参数解析，不加载 runtime |
| `RUN_UPSTREAM_CLI.sh` | **不受影响** —— 同上 |

### 3.2 不受影响的测试

用 `bridge + linker + --preload` 的（这是真实加载路径）：

`RUN_DL_TESTS.sh`、`RUN_E2E.sh`、`RUN_ID_SYSCALL.sh`、`RUN_PRIVDROP.sh`、
`RUN_PTHREAD_CREATE.sh`、`RUN_SHEBANG.sh`、`RUN_SYSTEM_POPEN.sh`、
`RUN_WAIT_TESTS.sh`

★ 判据是"跑的时候能在 maps 里看到 `libbxroot-runtime.so`" ★

### 3.3 一个反直觉的点

受影响的那几个测试**恰恰是最近新增的**（`RUN_PATH_FORMS.sh` 是我这次
为了钉住"路径形态"这个维度才加的）。它们的设计意图是对的，但**加载方式
选错了**，所以在容器内跑出来的"通过"没有意义。

而它们**在真机上**（DSHA 场景，无 proroot 外层）会是有效的 ——
因为那时 `LD_PRELOAD` 走的是标准 glibc loader。所以问题不在测试逻辑，
而在**"在 proroot 容器内跑 launcher 路径"这个组合本身**。

---

## 四、可靠的加载路径

### 4.1 推荐：`bridge + linker + --preload`（真机与容器内都可用）

```sh
L=/data/app/~~…/lib/arm64          # 官方库目录（动态探测，见 RUN_E2E.sh）
RF=/data/data/com.dsh.client/files/linux/ubuntu    # rootfs 的**内核视角**路径

# ① runtime 必须放在 rootfs 内（linker 只认内核视角路径）
mkdir -p /tmp/bxroot-detect                       # 容器视角建目录
cp build/libbxroot-runtime.so /tmp/bxroot-detect/ # 容器视角写文件
# 此时 $RF/tmp/bxroot-detect/ 也可见（同一 inode）

# ② 用内核视角路径 --preload
BXROOT_ROOTFS=$RF \
"$L/libproroot-bridge.so" "$L/libproroot-linker.so" --argv0 node \
  --preload "$RF/tmp/bxroot-detect/libbxroot-runtime.so" \
  "$RF/usr/local/bin/node" "$RF/tmp/bxroot-detect/p.js"
```

**怎么确认它真的生效了**（不要只看"程序跑起来了"）：

```sh
BXROOT_VERBOSE=1 … 2>&1 | grep '\[bxroot\]'
# 必须看到 [bxroot] proc: init inject=1 have_preload=1 rootfs=…
#   inject=1 说明注入成功
```

实测输出：

```
[bxroot] proc: 已修复 glibc 线程链表未初始化 (pd=0x75971de8c0 list=0x75971de980)
[bxroot] proc: init inject=1 have_preload=1 rootfs=/data/data/com.dsh.client/files/linux/ubuntu
probe-alive
```

### 4.2 双视角陷阱（复用 `RUN_E2E.sh` 的既有结论）

- `mkdir` / `cp` **只认容器视角**（`/tmp/x`）
- `--preload` **只认内核视角**（`$RF/tmp/x`）
- 两者 inode 相同，但**两个操作分别只认其中一个**

给它内核视角路径的 `mkdir` 会**返回 0 却不创建**（静默失败）——
本次调查中正是踩了这个：`mkdir -p "$RF/tmp/..."` 成功返回，
随后 `cp` 报 `No such file or directory`。

### 4.3 不要用这些

| 方式 | 为什么不行 |
|---|---|
| `LD_PRELOAD` | 见本文 —— proroot 容器内架构性失效 |
| 静态二进制 + `--preload` | `loader: map …: failed no PT_DYNAMIC` —— 静态可执行没有 PT_DYNAMIC，linker 无法接管 |
| `ld.so --preload` | 本例中报 `cannot open shared object file`；它对"当前已在 proroot 下"的进程不适用 |

---

## 五、对"降级路径"修复的影响（澄清一个混淆）

调查过程中一度把两件事混在一起，这里分清楚：

| 事项 | 状态 |
|---|---|
| **`ldso_service_*` 强引用导致加载失败**（用户报告 P0-2.1） | ✅ 真实缺陷，已修（改 `__attribute__((weak))`，4 个符号全部） |
| **`dlsym` 无服务分支 `return NULL`**（用户报告 P0-2.2） | ✅ 真实缺陷，已修（改用 `dlvsym` 取 libc 真身并转发） |
| **`LD_PRELOAD` 在本容器内失效** | ⚠️ **不是缺陷**，是 proroot 的架构行为；但它让本容器的 launcher 路径测试失效 |

★ 两件事的**证据来源不同**，不要互相"证明" ★

- 前者有直接证据：`readelf --dyn-syms` 显示符号是 `GLOBAL` 而非 `WEAK`；
  用户在纯 glibc 环境实测报 `symbol lookup error`。
- 后者有直接证据：最小 `.so` 的构造函数不执行、`execve` 的 envp 正确但
  maps 里没有库。

**但**：因为本容器内 `LD_PRELOAD` 失效，我们**无法在本容器内复现**
用户报告 P0-2.1 的原始现象（"加载即崩"）。那一条的验证只能在纯 glibc
环境（用户那边）或在真机上做。本容器能验证的是**符号绑定强度已改对**
（`readelf` 可查）与**降级分支的逻辑正确性**（用
`BXROOT_FORCE_NO_LDSO_SERVICE=1` 强制走那条分支）。

---

## 六、给测试套件的硬规则（本次教训的固化）

1. **任何"加载了 runtime"的测试，必须先证明 runtime 真的在 maps 里。**
   证明不了就 **SKIP，不要 PASS** —— 宁可不测，也不要测一个假的东西。
2. **不要用 `LD_PRELOAD` 在 proroot 容器内加载 bxroot runtime。**
   用 `bridge + linker + --preload`。
3. **判据要取"被测对象自己的痕迹"**，不能只看"程序跑起来了"。
   bxroot 的痕迹是 `BXROOT_VERBOSE=1` 时的 `[bxroot]` 日志，
   或 maps 里的 `libbxroot-runtime.so`。

★ 第 3 条是被本次调查直接逼出来的：我在修 `dlsym` 降级时，
第一次"验证成功"用的是裸跑探针，后来查 maps 才发现**探针压根没加载
runtime** —— 那次"通过"测的是 libc 自己。★

---

## 七、遗留

- `RUN_PATH_FORMS.sh` 的 B 基线需要改成 `--preload` 路径（或明确标注
  "本容器内 SKIP，仅真机有效"）。
- `RUN_L2S_E2E.sh` 需逐条确认加载方式。
- 尚未确认：真机上 `LD_PRELOAD` 是否也失效？（理论上不应该 ——
  真机上没有 proroot 外层，走标准 glibc loader。但**没有实测过**，
  所以此处只作为待验证项，不作为结论。）
