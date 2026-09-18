# D3 缺陷确认与修复设计：/proc/self/fd/N readlink 泄漏宿主路径

日期：2026-09-17 晚
状态：**缺陷成立（代码层确凿），运行时复现受本容器验证边界限制**

---

## 1. 缺陷陈述

`readlink("/proc/self/fd/N")`（以及 readlinkat 等价路径）在 fd 指向 rootfs
内文件时，返回的是**宿主视角路径**（带 `$ROOTFS` 前缀），而客户程序期望
guest 视角（无前缀）。

同一泄漏族还有两个形态：
- `readlink("/proc/self/cwd")` → 宿主 cwd（getcwd hook 已修，readlink 未同步）
- `readlink("/proc/self/root")` → 宿主 rootfs 路径（应返回 `/`）

## 2. 证据链

### 2.1 内核真值（本容器实测，raw syscall 绕开一切 hook）

```
RAW-syscall readlinkat(/proc/self/fd/6) (n=61):
    /data/data/com.dsh.client/files/linux/ubuntu/tmp/d3deep/f.txt
```

fd 是 `open("/tmp/d3deep/f.txt")`（guest 路径，bxroot 正确翻译后打开）所得。
**内核返回的是带 `$ROOTFS` 前缀的宿主路径** —— 这是泄漏的源头。

### 2.2 代码层证据（preload.c）

- readlink hook（1759 行起）：对 `/proc/self/exe` 有伪装，对 `/proc/self/fd/N`
  **无任何反向剥离逻辑**。
- readlinkat hook（3152 行起）：同上。
- 对照组：getcwd hook 已有完整反向翻译范本（`getcwd_fixup`，2560 行起：
  剥 rootfs 前缀 + `detranslate_binds` 反向 bind 映射），**但 readlink 系没有接**。
- realpath hook（2285 行注释）：自认"反向翻译暂未实现"。

### 2.3 本容器验证边界（诚实记录）

本容器内无法端到端复现"客户程序拿到泄漏路径"的现场：
- `LD_PRELOAD` 在本容器惰性（外层 proroot 自研 loader 劫持 execve）；
- bridge/linker 链路 SIGILL（第三方报告同样确认）；
- 直链（`-l:libbxroot-runtime.so`）只让**显式符号调用**生效，hook 依赖的
  符号 interpose 不会发生（探针 `open(guest)` ENOENT 证实）。
- 外层 proroot 自身也在做 readlink 反向剥离（A 侧 glibc readlink 返回
  guest 视角），会污染归因。

因此本缺陷的**运行时**确证需要在 LD_PRELOAD 语义成立的真机/纯 Linux 环境
完成（与报告作者环境一致）。**代码层证据已充分**：内核真值带前缀（2.1）+
hook 无反向逻辑（2.2）⇒ 泄漏必然发生。

## 3. 修复设计（最小改动）

新增共享函数（preload.c，getcwd_fixup 之后）：

```c
/*
 * readlink 系返回值的反向翻译。
 *
 * 内核对 /proc/self/fd/N、/proc/self/cwd、/proc/self/root 的 readlink
 * 返回的是**宿主视角**路径；客户期望 guest 视角。不做这一步，
 * 客户拿到的路径再喂回 open/stat 会双重翻译（或直接 ENOENT）。
 *
 * 返回：1 = 已重写（out 可用）；0 = 不需要改写（保持原返回值）。
 */
static int readlink_fixup(const char *raw, char *out, size_t outsz);
```

判别与处理顺序：
1. 返回值不含 `/` 开头 → 直接 0（相对链接目标，如 `/proc/self/fd` 对
   socket/pipe 返回 `socket:[123]`、`anon_inode:[eventfd]`，绝不能动）。
2. 匹配 `/proc/<pid>/root/...` → 剥 `/proc/<pid>/root` 前缀，剩余部分
   再走第 4 步。
3. 精确等于 `/proc/<pid>/cwd` → 已经被 getcwd 语义覆盖，无需处理；
   等于 `/proc/<pid>/root` → 重写为 `/`。
4. 其余绝对路径：调 `getcwd_fixup` 同款逻辑（剥 rootfs 前缀 → 组件边界 →
   空 则 `/`；再 `detranslate_binds`）。建议直接复用 `getcwd_fixup`，
   把它的"剥前缀"核心抽成 `detranslate_guest_path(char *buf)` 共享。

接入点（两处，改动各约 5 行）：
- `readlink` hook：`n = real_readlink(...)` 成功后、l2s 重写之前，对
  `buf`（拷入局部 raw 后）判别，命中则把 `fixed` 作为最终返回。
- `readlinkat` hook：`n = fn(dirfd, p, buf, bufsiz)` 成功后同样处理。

约束：
- 截断语义保持 readlink(2) 契约：不补 NUL，返回 min(len, buf_size)。
- 剥前缀只会让路径更短，原缓冲足够。
- `/proc/self/exe` 伪装分支在其之前，不受影响。

## 4. 验证方案（在 LD_PRELOAD 语义成立的环境）

判别输入：rootfs 内独有文件（如 `$ROOTFS/tmp/d3deep/f.txt`，宿主与容器
内容/路径可区分），探针：

```c
int fd = open("/tmp/d3deep/f.txt", O_RDONLY);   /* guest 路径 */
char lp[64]; snprintf(lp, sizeof lp, "/proc/self/fd/%d", fd);
readlink(lp, buf, sizeof buf);
/* 期望: /tmp/d3deep/f.txt   修复前: $ROOTFS/tmp/d3deep/f.txt */
```

对照矩阵：
| 用例 | 修复前（预期） | 修复后（预期） |
|---|---|---|
| `readlink(/proc/self/fd/N)` 文件 | 宿主路径 ❌ | guest 路径 ✅ |
| 目录 fd 同上 | 宿主路径 ❌ | guest 路径 ✅ |
| `readlink(/proc/self/cwd)` | 宿主 cwd ❌ | guest cwd ✅ |
| `readlink(/proc/self/root)` | 宿主 rootfs ❌ | `/` ✅ |
| pipe/socket fd | `pipe:[123]` 不变 | 不变 ✅ |
| bind source 下的 fd | 宿主 bind 源路径 ❌ | 反向 bind 后 guest 路径 ✅ |

## 5. 方法论教训（本次实验的自省）

1. **直链 ≠ interpose**：`-l:lib...so` 只解析显式引用；LD_PRELOAD 的
   hook 生效依赖符号 interpose。用直链探针测 hook 行为是方法错误 ——
   本次为此多绕了 6 轮实验。
2. **共享 inode ≠ 共享视角**：`/tmp`（容器）= `$ROOTFS/tmp`（宿主）
   是同一 inode，但两层容器各自的 readlink 剥前缀行为叠加，A/B 两侧
   都"看起来对"，归因必须构造**深于外层 rootfs 的判别 rootfs**。
3. 复杂实验前先列"哪一层在起作用"的归因矩阵，再设计能区分各层的
   判别输入。
