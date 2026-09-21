# 缺陷：`eaccess()` 未挂钩 —— `make` 的 PATH 搜索恒 ENOENT

> **结论**：`eaccess()`（`euidaccess()`）**没有被接进翻译层**，于是它
> 拿到的是**未翻译**的容器视角路径，内核按宿主视角去找 → 符号链接
> 必然 ENOENT。
>
> 后果：GNU make 的 PATH 搜索用 `eaccess` 判断候选是否可执行，
> **每次都被 ENOENT 打回，于是 make 认定"PATH 里没有这个命令"，
> 根本不会去 exec** —— 表现为 `make: gcc: No such file or directory`。
>
> **状态：已修复**（`src/runtime/preload.c`，新增 `eaccess`/`euidaccess` 钩子）。

---

## 一、现象

```sh
$ bxroot-run -- /bin/sh -c 'cd proj && make'
gcc -c -o a.o a.c
make: gcc: No such file or directory          # Error 127
make: *** [Makefile:5: a.o] Error 127
```

而同一个 `gcc` 直接调用完全正常：

```sh
$ bxroot-run -- /bin/sh -c 'gcc --version | head -1'
gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
$ bxroot-run -- /bin/sh -c 'command -v gcc'
/usr/bin/gcc
```

★ **"直接能用、make 里找不到"** 这个组合是最初的迷惑点 ★

## 二、根因

### 2.1 make 用 `eaccess()` 做 PATH 搜索

```sh
$ readelf -sW --dyn-syms /usr/bin/make | grep -E 'stat|access|exec'
    38: UND eaccess@GLIBC_2.17 (2)
    69: UND lstat@GLIBC_2.33 (5)
    84: UND stat@GLIBC_2.33 (5)
    98: UND execvp@GLIBC_2.17 (2)
```

make 遍历 `PATH` 的每个候选目录，用 **`eaccess(candidate, X_OK)`**
判断"这个文件可执行吗"。而 bxroot 的翻译层里**只有 `access`/`faccessat`，
没有 `eaccess`** —— 它们是不同的导出符号，前者的钩子拦不到后者。

### 2.2 未翻译路径 + 符号链接 = 恒 ENOENT

```c
eaccess("/usr/bin/gcc", X_OK)
  ↓ bxroot 没钩子，路径**原样**传给内核
内核按**宿主视角**找 "/usr/bin/gcc"
  ↓ 宿主文件系统里这个路径不存在（它在 rootfs 里）
ENOENT
```

实测对照（同一探针二进制）：

| 路径 | 宿主 | 官方 proroot | bxroot |
|---|---|---|---|
| `/usr/bin/gcc`（符号链接链） | `0` ✅ | `0` ✅ | **`-1 ENOENT`** ❌ |
| `/usr/bin/gcc-13`（符号链接） | `0` ✅ | `0` ✅ | **`-1 ENOENT`** ❌ |
| `/bin/sh`（**真文件**） | `0` ✅ | `0` ✅ | `0` ✅ |
| `/nope-xyz`（确实不存在） | `-1 ENOENT` | `-1 ENOENT` | `-1 ENOENT` ✅ |

★★ **第三行是这条缺陷最难发现的地方** ★★

`/bin/sh` 在 bxroot 下**返回 0** —— 因为"未翻译的宿主视角路径"
恰好也存在于**宿主**文件系统上（宿主与容器共用同一份 Ubuntu 用户态），
所以真文件"侥幸通过"；而 `/usr/bin/gcc` 是**符号链接**，宿主上不存在
那个链接，必然失败。

于是现象表现为「**部分命令能用、部分不能用**」，看起来像权限或环境
问题，而不像"整个类别的调用都坏了"。这一条如果只测 `/bin/sh`
就会得出"eaccess 没问题"的**错误结论**。

### 2.3 为什么长期没被发现

- `access()` 有钩子且测过 → 容易假设"权限检查这一族已覆盖"；
- 绝大多数程序用 `access()`/`faccessat()`，用 `eaccess()` 的是少数
  （glibc 把 `eaccess` 单独导出，`euidaccess` 是其别名）；
- 症状（"找不到 gcc"）离"权限检查"很远，第一直觉是
  PATH/翻译/exec 的问题，不会想到去查 `eaccess`。

## 三、修法

在 `src/runtime/preload.c` 增加 `eaccess` 与 `euidaccess` 两个钩子，
与既有 `access()` **完全同构**：

1. `translate_path()` 先翻译；
2. 调真实符号（`bxroot_next_symbol("eaccess")`，失败则回退
   `euidaccess`）；
3. 只在**真实调用失败**时按 fakeroot 模型考虑覆盖
   （`fakeroot_access_override`）—— 坚持"**只覆盖错误，绝不凭空
   造错误**"这条既有原则。

`euidaccess` 单独导出而不是靠 `alias`：客户可能引用任一名字，
与 dl 家族的处理方式一致。

## 四、验证

### 4.1 修复前后

| 调用 | 修复前 | 修复后 | 宿主基线 |
|---|---|---|---|
| `eaccess("/usr/bin/gcc", X_OK)` | `-1 ENOENT` ❌ | `0` ✅ | `0` |
| `eaccess("/usr/bin/gcc-13", X_OK)` | `-1 ENOENT` ❌ | `0` ✅ | `0` |
| `eaccess("/bin/sh", X_OK)` | `0` | `0` ✅ | `0` |
| `eaccess("/nope-xyz", X_OK)` | `-1 ENOENT` | `-1 ENOENT` ✅ | `-1 ENOENT` |

第四行**必须验**：修法的风险是把"确实不存在"也变成"存在"。
这一类"只覆盖错误、不造错误"的断言是同类修复的通用验收项。

### 4.2 `make` 端到端

```
$ bxroot-run -- /bin/sh -c 'cd /tmp/mkreal && make'
gcc -c -o a.o a.c
gcc -c -o b.o b.c
gcc -o prog a.o b.o
make-rc=0

$ bxroot-run -- /bin/sh -c 'cd /tmp/mkreal && ./prog'
REAL-MAKE-BUILD-OK
  from b.c
```

可靠性：**干净重建 5/5 通过**；`make clean` 正常。

### 4.3 回归

`sh test/RUN_ALL.sh`：**24 通过 / 1 失败**，与修复前**逐位一致**
（那 1 项是既有的 `RUN_UPSTREAM_CLI.sh` 用错加载路径，见
`docs/缺陷-exec名字解析丢失ENOENT.md`）。告警门禁零告警。

## 四点五、接完 `eaccess` 还不够：整族都要接

接上 `eaccess` 之后 make 仍然失败，因为**同一族里还有别的入口没接**。
实测的完整清单（每个都由独立证据推动，不是"顺手都加上"）：

| 入口 | 谁在消费 | 没接的后果 |
|---|---|---|
| `stat64` / `lstat64` | **dash/bash** 的 PATH 搜索 | `sh -c 'cc …'` 找不到 |
| `stat` / `lstat` / `newfstatat` | tar / find / 多数工具 | 同上 |
| `access` / `faccessat` | 大量程序 | "可执行判定"失败 |
| **`eaccess`** | **GNU make** | `make` 报 127 |
| `open` / `openat` | 一切读文件的 | 打不开 |
| `execve` | guest 自己 exec | 加载阶段 rc=2 |
| **`posix_spawn`** | **make 的配方子进程** | make 报 Error 2 |

★ **判据是"谁消费谁负责"，不是"看起来像就一起加"** ★
`eaccess` 之所以特殊，是因为 **GNU make 恰好用它** —— 而 dash 用
`stat64`。两者都是"检查文件能不能执行"，选哪个是**各程序自己的自由**，
所以翻译层必须把**整族**都覆盖，不能只覆盖自己想到的那几个。

这一族里最容易漏的是 `eaccess`（名字不像 access 的亲戚）、
`stat64`（64 位变体，和 `stat` 是两个符号）与 `posix_spawn`
（它内部用内联 svc，连符号都是绕过的）。

## 五、方法论

**"直接调用能用、被 make 调用就找不到"** 这个组合，把范围精确地
锁在"make 特有的调用路径"上 —— 而不是 PATH、不是 exec、不是权限。

定位手法：`readelf --dyn-syms /usr/bin/make` 列出它真正引用的符号，
再逐个对照 bxroot 的导出表。这比读源码快，也比猜测可靠 ——
`eaccess` 就在那份清单里，而 bxroot 的导出表里没有它。

**同类缺陷的通用排查式**（建议后续审计照做）：

```sh
# 对每个常用程序，列出它引用的 libc 符号，减去 bxroot 的导出表
comm -23 <(readelf -sW --dyn-syms /usr/bin/make | awk '/UND/{sub(/@.*/,"",$NF); print $NF}' | sort -u) \
         <(nm -D --defined-only build/libbxroot-runtime.so | awk '{print $3}' | sort -u) \
  | grep -E '^(a|l|f|e|stat|.*access)' | head
```

命中的就是"可能没被翻译"的符号。`eaccess` 正是这样一条。
