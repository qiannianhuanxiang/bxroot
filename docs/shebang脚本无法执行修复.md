# shebang（`#!`）脚本无法直接 exec —— 已修复

> 缺陷由子代理在修 `LD_PRELOAD` 时**顺带发现**并如实登记。
> 两个子代理先后接手均因运行时故障中断（**未改动任何生产代码**），
> 最终由我本人实现并验证。

---

## 一、现象（两侧对照实测）

```
########## 官方 ##########                    ########## bxroot（修前）##########
$ ./s1.sh                                     $ ./s1.sh
SHEBANG-OK                                    loader: reject .../s1.sh: bad read
rc=0                                          proroot-ldso: failure rc=5
                                              rc=2

$ ./s2.py   (#!/usr/bin/env python3)          $ ./s2.py
PY-SHEBANG-OK                                 loader: reject .../s2.py: bad read
rc=0                                          proroot-ldso: failure rc=5
                                              rc=2

$ sh s1.sh   ← 显式指定解释器                  $ sh s1.sh
SHEBANG-OK  rc=0                              SHEBANG-OK  rc=0   ← 两侧相同！
```

**关键**：`sh script.sh` 两侧**都是好的** —— 所以这不是"脚本内容/权限"问题，
而是**"直接 exec 脚本文件"这条路径**没被覆盖。

## 二、根因

execve 一个 shebang 脚本时，**内核**会自己解析 `#!` 行并按语义改写 argv：

```
execve("./s1.sh", ["./s1.sh", "arg1"], env)
  → 内核改写为 →
execve("/bin/sh",  ["/bin/sh", "./s1.sh", "arg1"], env)
```

但 bxroot 的 exec 路径是「**把 guest 路径翻译成宿主路径 → 交给官方 linker 加载**」：

```
src/proc/proc.c: px_do_execve()
  → px_runtime_translate(path)         把 ./s1.sh 翻成 <rootfs>/.../s1.sh
  → px_trampoline_exec(host, ...)      交给 linker 加载 host
                                        ★ linker 只认 ELF
```

linker 打开脚本看到的是**文本**，ELF magic 校验失败 → `bad read`。
**内核那段 shebang 逻辑被我们整条绕过去了。**

## 三、修法

在把目标交给 linker **之前**，自己做内核等价的 shebang 解析与 argv 改写
（`src/proc/proc.c` 新增 `px_parse_shebang()` / `px_rewrite_shebang()`）。

### 复刻的内核语义（逐条，不是凭直觉）

| # | 规则 | 备注 |
|---|---|---|
| 1 | 只认**偏移 0/1** 的 `#!` | 前面有 BOM/换行/空格都不算 |
| 2 | `#!` 后**允许空格/Tab** | `#! /bin/sh` 合法 |
| 3 | 解释器 = 到空白/换行为止 | 可为空 → 内核回 ENOEXEC |
| 4 | **单个**可选参数 = 之后到行尾的**整串** | `#!/usr/bin/env python3` 里 `python3` 是**一个**参数；`#!/bin/sh -u` 里 `-u` 是一个参数。**不按空格切分** |
| 5 | 行长上限 `BINPRM_BUF_SIZE` = **256** | 与内核同取 |
| 6 | 改写后 argv = `[解释器, (可选参数,) 脚本, 原argv[1..]]` | 客户看到的 `argv[0]` 是**解释器**；脚本路径挪到 argv[1] |
| 7 | **只解析一层** | 解释器若又是脚本，那是**新的一次 execve**，由 execve 钩子再次进入 → 天然递归且与内核同构 |

### 与内核的**唯一有意偏离**

`\r` 处理：内核**不**特殊对待 CR（它只是行内容），于是 `#!/bin/sh\r\n`
的解释器会变成 `/bin/sh\r`（那个文件不存在）。本实现把行尾 `\r` 当终止符。
**理由**：CRLF 脚本在本平台极常见，照搬内核会让它们全部失败且报错极难懂。

### 代码位置

- `px_parse_shebang()` —— 解析 `#!` 行，返回 1/0/-1
- `px_rewrite_shebang()` —— 改写 argv，做解释器的路径翻译
- `px_do_execve()` —— 在路径解析之后、argv 计划之前调用

## 四、★ 实现中踩到的两个坑（都写进代码注释了）★

### 坑 1：改写结果放进了块作用域 → 野指针

第一版把 `sb_argv` 声明在 `if` 块里，而 `argv` 要一直被用到函数末尾的
trampoline exec。块一结束那些栈内存就失效 → **野指针**。
症状会是"大多数时候正常、偶发读到垃圾 argv"，极难定位。
**已把改写缓冲全部提到函数作用域**并注释原因。

### 坑 2：`sb_argv[1]` 指向了会被覆写的缓冲

调用方在 shebang 命中后会执行：

```c
px_cfg_str(guest, sizeof(guest), sb_guest);   /* guest 被覆写成解释器 */
```

而 `sb_argv[1]`（脚本路径）原本指向 `guest` → **脚本路径被替换成解释器**。
实测症状极具误导性：

```
$ ./s2.py
  File "/usr/bin/env", line 1
    ELF
SyntaxError: source code cannot contain null bytes
```

看起来像"python 把 ELF 当源码读"，实际是 `argv[1]` 指错了地方。
**修法**：脚本路径拷进**独立**缓冲 `sb_script`。

> 这两个坑都是"第一版看着对、跑起来错得莫名其妙"的类型。
> 值得记录的是：**坑 2 的错误信息完全指向了错误的方向**
> （读起来像 python/解释器的问题，实际是调用方的缓冲区复用）。

## 五、验证

### 判别力（硬要求）

用 `git` 镜像里的**旧源码**重建产物，跑**同一份测试**：

```
########## 修前（旧产物）##########          ########## 修后 ##########
❌ bxroot 缺少 'S1-OK args=[arg1 arg2]'      ✅ S1-OK args=[arg1 arg2] 一致
❌ bxroot 缺少 'S2-OK argv0='                ✅ S2-OK argv0= 出现
❌ bxroot 缺少 'S3-OK unset-var-guard=...'   ✅ S3-OK unset-var-guard=[unset] 一致
❌ A 段 rc=2（应为 rc=0）                     ✅ A 段 rc=0
❌ B 段 rc=2（应为 rc=0）                     ✅ B 段 rc=0
❌ C 段 rc=2（应为 rc=0）                     ✅ C 段 rc=0
✅ D 段 rc=0        ← ★ 修前也绿           ✅ D 段 rc=0
❌ bxroot 仍报 loader 拒绝                    ✅ 无 loader 拒绝
RESULT: FAIL                                  RESULT: PASS
```

**`D 段`（`sh` 显式调用）修前修后都是绿的** —— 这精确证明了测试抓的是
"直接 exec 脚本"这条路径，而不是"脚本能不能跑"。

### 两侧对照（修后）

```
########## 官方 ##########                    ########## bxroot（修后）##########
S1-OK args=[arg1 arg2] argv0=.../s1.sh        S1-OK args=[arg1 arg2] argv0=.../s1.sh
S2-OK argv0=.../s2.py                         S2-OK argv0=.../s2.py
S3-OK unset-var-guard=[unset]                 S3-OK unset-var-guard=[unset]
D 段 rc=0                                      D 段 rc=0
```

**`argv0` 两侧都是脚本路径** —— 证明解释器改写的 argv 语义与官方一致
（python 看到 `sys.argv[0]` 是脚本而非解释器）。

### 回归

`sh test/RUN_ALL.sh --quick` → **17/17**（新增本项；既有 16 项一项没红）。
门禁零告警（11 个编译单元）。

## 六、新增测试

`test/RUN_SHEBANG.sh`，已纳入 `RUN_ALL.sh`（第 9e 项）。四条判据：

- A 段：`./s1.sh arg1 arg2` 直接 exec，参数传递正确
- B 段：`#!/usr/bin/env python3`（验证"解释器+单个参数"语义）
- C 段：`#!/bin/sh -u` 带解释器参数
- D 段：**对照** `sh s1.sh`（修前也应为绿 —— 用来区分"是不是 shebang 路径的问题"）
- 外加：不得再出现 `bad read` / `bad magic` / `proroot-ldso: failure`

## 七、不确定项

1. **`AT_*` 语义**：本实现不处理 `execveat(AT_EMPTY_PATH, fd)` 传脚本 fd 的情况
   （shebang 解析要读内容，而 fd 路径未知）。**未实测**。
2. **解释器为相对路径**：内核要求 shebang 的解释器必须是**绝对路径**，
   否则 ENOEXEC。本实现把相对路径也做翻译并尝试执行 ——
   **与内核行为不同**，但实测未遇到（常见解释器都是绝对路径）。**未修**。
3. **`\r` 偏离**是否需要进一步确认（见上文第三节）。
4. **权限/`nosuid` 等**：内核 execve 对脚本有一层额外检查（脚本本身需要
   `+x`，解释器需要可执行）。本实现依赖后续环节报错，**未显式复刻**。
