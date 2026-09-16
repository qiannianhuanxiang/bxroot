# l2s stat 伪装失效 —— 三个缺陷的完整分析

> 现象：bxroot 下 `link()` 成功但 `st_nlink` 停在 1、`lstat` 仍报符号链接，
> 而官方 proroot 正确（`nlink=2`、`islink=false`）。
>
> 本文记录定位过程与三个**互相独立**的缺陷。之所以值得单独成文，是因为
> 其中两个属于「**同一个功能在两套不同的调用路径上分别实现，只做了一半**」
> 这一类问题 —— 它在本项目里反复出现，且有明确的架构根源。

## 症状

```
官方 proroot:  link() → nlink=2  islink=false  content="hello"   ✅
bxroot:        link() → nlink=1  islink=true   content="hello"   ❌
```

连跑 3 次稳定复现。

**关键中间观察**：l2s 的**创建**那半完全正常 —— 目录里能看到它的中间文件：

```
[".l2s.a0001", ".l2s.a0001.0002", ".l2s.a0001.0002.cnt", "a", "b"]
```

宿主视角确认磁盘布局正确（两级结构 + 正确的 `.cnt`）：

```
lrwxrwxrwx .l2s.a0001 -> /data/.../tmp/l2s-host-1/.l2s.a0001.0002
-rw------- .l2s.a0001.0002
-rw------- .l2s.a0001.0002.cnt
lrwxrwxrwx a -> /data/.../tmp/l2s-host-1/.l2s.a0001     ✅
lrwxrwxrwx b -> /data/.../tmp/l2s-host-1/.l2s.a0001     ✅
```

所以：**写是对的，读（伪装）不对。**

---

## 缺陷 1：scheme 自相矛盾（`src/l2s/l2s-runtime.c`）

`l2s_rt_init()` 忠实采用调用方给的 `cfg.scheme`，而 `preload.c` 传的是
`L2S_SCHEME_PROROOT`。但 l2s-runtime 层**只会写 PROOT 式名字** ——
于是「写出来的中间层，自己认不出来」。

纯逻辑 A/B（同一份代码，只换这一个字段）：

```
scheme=PROOT   → nlink=2  islink=false   ✅
scheme=PROROOT → nlink=1  islink=true    ❌
```

**修法**：在 `l2s_rt_init` 里归一化为 PROOT。无损 —— `l2s_classify` 的
PROOT 分支是严格超集（`parse_l2s_name` 失败会落到 `parse_proroot_meta_name`）。

---

## 缺陷 2：`fstatat` 钩子漏了 l2s（`src/runtime/preload.c`）

逐个入口实测 `st_nlink`（纯 C 探针，`BXROOT_LINK2SYMLINK=1`）：

```
stat(a)               nlink=2  islnk=0    ✅
lstat(a)              nlink=2  islnk=0    ✅
fstatat(AT_FDCWD,a)   nlink=1  islnk=0    ❌
fstatat(dirfd,"a")    nlink=1  islnk=0    ❌
```

产物里的调用点统计证实：

| 钩子 | `l2s_rt_patch_stat` 调用数 |
|---|---|
| `stat` | 3 |
| `lstat` | 1 |
| **`fstatat`** | **0** ← 唯一漏掉的 |
| `stat64` | 1 |
| `lstat64` | 1 |

`fstatat` 是 **glibc 现代程序的主路径**，`stat`/`lstat` 那些老入口基本不会被调到。
所以这个遗漏的危害是「按调用者不同而表现不同」—— 用老工具（`ls`/`grep`）测
看到的是**正确**的 `nlink=2`，用 node 测全错。**探针选错就永远看不见。**

**修法**：在 `fstatat` 钩子里补上与 `lstat` 同构的一行（路径用翻译后的宿主路径 `p`）。

---

## 缺陷 3：node 根本不走 libc 的 `statx()`（`src/runtime/syscall_guard.c`）

这是**最隐蔽**的一个，也是前两个修完仍不生效的原因。

libuv 的 `uv__fs_statx()` **故意绕开 libc**：

```c
int ret = syscall(SYS_statx, fd, path, flags, mask, &statxbuf);
```

实测证据：

- node 二进制里 **24 条 `svc` 指令**，**0 处引用 `newfstatat`/`statx` 符号**
- 开 `BXROOT_SCG=1` 时 guard 日志大量出现：
  ```
  [bxroot] syscall_guard: 翻译 a1 /usr -> /data/data/.../ubuntu/usr
  [bxroot] syscall_guard: 翻译 a1 /usr/local -> /data/data/.../ubuntu/usr/local
  ```
  说明 node **确实在 `syscall()` 符号层上**
- 而 `preload.c` 里那个 `statx()` 钩子**一次都没被调用**

也就是说：**我们把 `l2s_rt_patch_statx` 接在了客户不走的路上。**

### 这不是新发现 —— 项目文档早有记录

`syscall_guard.c` 文件头第 15 行：

> 【问题二】node 静态链接的 libuv **不经 libc 的 stat/statx 符号**，
> 而是用 `syscall(291, AT_FDCWD, path, ...)` 直接发起。实测证据：
> 开 `BXROOT_SCG=1` 时 node 的 statSync 产生"转发 291"，却**不产生任何
> translate 日志** —— 它完全绕过了 stat 钩子。

**当初写 guard 时只做了「路径翻译」那一半**（`翻译 a1 ...` 日志就是它），
**没做「结果伪装」那一半**（`stx_nlink` / `stx_mode`）。

**修法**：在 guard 的 `syscall()` 里，对 `number == 291 && ret == 0 && a4 != 0`
的返回结果调用 l2s 的结果补丁。

⚠️ `a4` 必须判空 —— `statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...)` 是**合法入参**
（见文件头"实现要点 2"的踩坑记录）。

### 决定性对照

```
当前源码（缺陷 1+2 已修）              → nlink=1  islink=true    ❌
当前源码 + 唯一增补 syscall(291) 补丁  → nlink=2  islink=false   ✅
```

---

## 这一类问题的架构根源

三个缺陷里，**缺陷 2 与缺陷 3 属于同一类**：

> **同一个功能（stat 结果伪装）需要在多条调用路径上分别实现，
> 而只做了一部分。**

本项目的 hook 架构天然会产生这个风险：同一个"读取文件元数据"的操作，客户可能经由

```
libc 符号层：  stat / lstat / stat64 / lstat64 / fstatat / statx / __xstat / __lxstat / __fxstat
裸 syscall 层： syscall(79/newfstatat) / syscall(291/statx)
```

**至少 11 条路径**。每加一个功能（fakeroot、l2s），都要在**所有**路径上接一遍 ——
漏一条的表现就是「换个调用者/换个工具就失效」。

### 本项目里同类问题的历史

| 时间 | 问题 | 表现 |
|---|---|---|
| 早前 | `--link2symlink` 被 launcher 解析后**丢弃** | 能力已实现，从未生效 |
| 早前 | `l2s_rt_patch_stat` 实现完整但**无人调用**（`bl` 数为 0） | 单测 119 条全绿，生产零效果 |
| 本次 | `fstatat` 漏接（缺陷 2） | 老工具正常、node 失效 |
| 本次 | `syscall(291)` 结果未补（缺陷 3） | node 完全失效 |
| 本次 | `envp == NULL` 的兜底**只写在注释里** | 第二层只剩 4 条环境变量 |

**共同模式**：能力实现完整、单元测试全绿，但**没有一条断言检查"它是否被接上"**。

### 可以采取的对策

1. **端到端契约测试必须覆盖多个调用入口**，而非只用一个工具。
   `test/RUN_L2S_E2E.sh` 最初只用 node —— 单一入口覆盖不全，正是缺陷 2
   藏了这么久的原因。现已加纯 C 探针逐个入口直测。

2. **在钩子架构里显式维护"路径清单"**。`syscall_guard.c` 的路径参数表
   （`path_arg_mask`）就是这个思路的一个成功案例 —— 它把"哪些调用要翻译"
   收敛到**一张表**，并配了单测 `test/test_syscall_argpos.c`（含防误加断言）。
   stat 族的"结果伪装"目前**没有**这样的表。

3. **对新功能问一句：它在哪几条路径上需要生效？** 把答案写进提交信息或注释，
   而不是默认"接一处就够了"。

---

## 复现与验证

```sh
cd /root/proroot-work/agents/rename-bxroot
sh BUILD_RUNTIME.sh
cp build/libbxroot-runtime.so "$ROOTFS/tmp/bxroot-e2e/"   # ★ 必须刷新 stage 副本
sh test/RUN_L2S_E2E.sh
# 期望 RESULT: PASS（nlink=2 islink=false content="hello"）
```

**时序陷阱**（踩过）：`RUN_L2S_E2E.sh` 从 **stage 目录**读 `.so`，不是 `build/`。
只重新构建而不 `cp`，会看到"改了没效果"。

## 我（父 agent）在定位过程中的两条误判

记录下来以免后人重蹈：

1. **"`patch_stat` 收到的 path 是目录"** —— 那是探针里 `fs.rmSync(d, {recursive:true})`
   对**目录**发起的 stat 造成的假象，与文件的 stat 无关。
   （证据：把 `rmSync` 从探针删掉后，`patch_stat` 一次都不再被调用。）
2. **"`readlink(a)` 返回自己 = 自环 = 数据损坏"** —— 不成立。
   官方对照：官方返回 `EINVAL`，bxroot 返回**还原后的客户视角路径**
   （`l2s_rt_rewrite_readlink` 的既定设计：把 `.l2s.a0001` 还原成客户本来的名字）。
   磁盘侧的两级结构是正确的。

两条都是由**子代理**复核纠正的。
