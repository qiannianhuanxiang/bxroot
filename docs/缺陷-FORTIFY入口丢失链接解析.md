# 缺陷：FORTIFY 入口（`__open_2` 族）丢失链接解析 —— 默认 `-O2` 下静默错

> **状态：已修复。** 由第八轮验收子代理发现。**这是"探针全绿但真实项目失败"
> 的根因之一**：`-O2` 是默认优化级别，glibc 会把**不在 main TU 里**的
> `open()` 调用路由到 `__open_2` —— 而 bxroot 的 `__open_2` 只做了
> 路径翻译 + l2s，**没接链接解析**。

---

## 一、现象（同一进程，同一路径，三种入口三种答案）

```
open()      in main TU : 40 (ELOOP)     ✅
open()      other TU   : 40 (ELOOP)     ✅
__open_2()  other TU   :  2 (ENOENT)    ❌   ← 仅 bxroot
```

宿主三种入口**全是 40**。

## 二、为什么危险

1. **`-O2` 是默认优化级别**，而"open 调用不在 main 的 TU 里"在正常项目里
   **到处都是** —— 任何库函数、任何多文件程序。
2. 也就是说：**默认编译的真实程序会静默丢掉 errno 语义**，
   而用 `-O0` 或把调用写在 `main` 里的探针**测不出来**。
3. 这直接解释了本项目反复出现的**"我的探针全绿、子代理的真实项目报错"**：
   探针 `/tmp/accept`、`/tmp/loopfix` 都在 main 里用裸 `open`，
   恰好走了被修好的那条路。

★ 这是"**探针集合本身是假绿**"的典型 ★ 比单个缺陷更值得警惕 ——
它让每一轮自测都失去意义。

## 三、同族入口清单（本轮共发现 **6 个**漏网的）

| 入口 | 缺陷 | 现在 |
|---|---|---|
| `__open_2` | ❌ 无链接解析 | ✅ |
| `__open64_2` | ❌ | ✅ |
| `__openat_2` | ❌ | ✅ |
| `__openat64_2` | ❌ | ✅ |
| `__realpath_chk` | ❌ 完全无解析 → `-O2` 下 realpath 泄漏外层 | ✅ |
| `readlink` / `readlinkat` / `__readlink_chk` / `__readlinkat_chk` | ❌ **中间组件**未解析 | ✅ |

### 3.1 `__realpath_chk`：同一份源码，只差优化级别

```
gcc -O0 … && bxroot-run -- prog    → realpath=/etc          ✅
gcc -O2 … && bxroot-run -- prog    → realpath=/system/etc   ❌（外层）
```

`-O2` + `_FORTIFY_SOURCE` 下 glibc 用 `__realpath_chk` **取代** `realpath`。
`readelf --dyn-syms` 一眼可证：

```
UND __realpath_chk@GLIBC_2.17
```

这解释了为什么 `accept` 探针（当时用 `-O0` 编）一直绿，
而**真实项目（`-O2`，Makefile 默认）**会失败 ——
**探针的编译选项本身就是一个盲区**。

### 3.2 `readlink` 家族：叶子不动、**中间必须动**

```
宿主 : readlink("/tmp/rly/dirlink/leaf") = /tmp/acc-d/f
bxroot: FAIL errno=2                      ❌
```

`readlink` 的契约是"读这个链接**本身**"，所以**叶子绝不能跟随**；
但**中间**目录若是链接，内核会按真实根展开 → ENOENT。

★ 修的时候必须只解析中间、保留叶子 ★ 这跟 `lstat` 是同一条判据。

四处结构一致，因此**抽出一个共享辅助** `fortify_open_common()` ——
避免"修了三个漏一个"（本项目已在 `eaccess`、`stat64`、`open64`
上各栽过一次）。

语义与 `open()`/`openat()` 严格对齐：
- 只解析**中间组件**（叶子由调用方语义决定）
- `O_NOFOLLOW` 时**一律不动**
- 链接环 → `errno=ELOOP`（`resolve_symlink_full` 返回 `-2`）
- 失败后重试**只在 `ENOENT`**（不得改写 `ENOTDIR`/`ELOOP` 等语义）

## 四、顺带修的第二个缺陷：成功的 `open` 改写了 errno

```
调用方 errno=12345 → 成功 open("/etc/passwd")
  宿主 : errno 仍是 12345      ✅（POSIX：成功的调用不得改动 errno）
  bxroot: errno 变成 22 (EINVAL) ❌
```

**根因**：`resolve_intermediate_symlinks()` 为判断"这一段是不是链接"，
对路径的每一段做 `readlink` 探测 —— 而"不是链接"时 `readlink` 返回
`EINVAL`。那是**正常的探测结果**，但它把 errno 留给了调用方。

**修法**：进入函数时保存 errno，**所有返回点恢复**。

★ 这类缺陷的性质 ★ 它不改变任何返回值，只**污染带外信道**（errno）。
C 里"先设 errno 再判成功/失败"是常见写法，这种污染会让人读到假错误。
Kernel 与 glibc 对"成功不改 errno"有明确约定，翻译层必须遵守。

## 五、我修这次时**自己引入又修掉**的一个回归（记录在案）

为给 11 个返回点加 errno 恢复，我用了正则批量替换，把：

```c
if (cond)
    return 0;              /* ← return 受 if 保护 */
```

改成了**单行**：

```c
if (cond)
    errno = saved_errno; return 0;   /* ← 仍受保护，但 -Wmisleading-indentation 报警 */
```

随后为消警又"展开"成两行，结果：

```c
if (cond)
    errno = saved_errno;
    return 0;              /* ★ return 脱离 if → 变成无条件返回！★ */
```

**后果**：`accept` 探针从 12/0 掉到 **11/1**
（"读中间目录链接读到外层文件"那项失败）——
因为函数变成**无条件提前返回**，链接展开整个失效。

**谁发现的**：告警门禁 + 我自己的 accept 探针。两者**同时**报警，
才让我意识到不是"探针问题"而是"真回归"。

**修法**：给 11 处统一加**花括号**，让 `return` 明确在 `if` 作用域内。

★ 教训 ★
1. **概率批量替换 `return` 是危险的** —— `if` 无花括号时，换行会改变语义；
2. **`-Wmisleading-indentation` 正是为这种缺陷存在的**，本项目的零告警
   门禁把它拦下了 —— 如果门禁放宽，这个回归会**静默进入交付**；
3. **修完必须立刻跑探针** —— 我是靠 accept 探针发现降级的。
   "改完只看编译通过"会漏掉这类语义回归。

## 六、验证

| 检查 | 修复前 | 修复后 | 宿主 |
|---|---|---|---|
| `__open_2(symlink-loop)` | ❌ ENOENT(2) | ✅ ELOOP(40) | 40 |
| `__open_2` 族四入口 | ❌ | ✅ | ✅ |
| 成功 `open` 后的 errno | ❌ 被改成 22 | ✅ 保持 12345 | 保持 |
| `accept` 探针（12 项） | 12/0 | ✅ 12/0 | 12/0 |
| 中间目录链接 / 环 / `/bin` 家族 | ✅ | ✅ 未回归 | ✅ |

回归：`test/RUN_ALL.sh` **24 通过 / 1 失败**（既有项）；
告警门禁**零告警**。

## 七、给后续验收的硬要求

**探针必须覆盖 FORTIFY 路径**，否则永远是假绿：

```c
/* 关键：调用点不能放在 main 的 TU 里，且必须 -O2 编译 */
gcc -O2 -D_FORTIFY_SOURCE=2 main.c other.c -o probe
/* 在 other.c 里 open() 一个符号链接环，期望 errno==ELOOP */
```

现成复现件：`/tmp/fp8/tfx`（三入口对照）、`/tmp/fp8/errno2`（errno 保持）。
