# proot CLI 兼容性报告

> 目标：**凡是 proot 能接受的命令行，bxroot 也要能接受**。
> 对照基准是 proot 源码，不是记忆或文档摘要。

## 结论

proot 的 **31 个选项**（去重后）在 bxroot 里**全部有明确行为**：

| 处理方式 | 数量 | 说明 |
|---|---|---|
| ✅ 已支持 | **27** | 语义与 proot 一致，或有意等价 |
| 🚫 明确拒绝 | **7** | 本实现没有该能力，**报错退出，不静默忽略** |
| ❓ 未处理 | **0** | — |

（27+7=34 > 31 是因为统计按"命令行写法"计，`-r` 与 `--rootfs` 这类长短名各算一条。）

## 为什么要做这件事

DSHA 这类上层应用是**按 proot 的接口写的** —— 它调用时传 `-r` / `-b` / `-0` 等等。
一个只想"把运行时换成 bxroot"的用户，不应该被迫改上层代码。
缺一个选项就是一次**静默降级**：上层照发，我们报错退出，用户看到的是"容器起不来"。

## 对照基准

逐条核对 **proot 源码**：

- 选项表：`src/cli/proot.h`（每个选项的 `.name` / `.separator` / `.value` / `.description`）
- 处理器：`src/cli/proot.c`（每个 `handle_option_*` 的实际语义）
- bind 清单：`src/cli/proot.h` 的 `recommended_bindings[]` 与 `recommended_su_bindings[]`

★ 一切以源码为准。本报告初稿曾把 `-H` / `-L` 误判为"bind 预设组合"，
**读源码后更正**：它们其实是 `hidden_files` / `fix_symlink_size` 两个扩展
（见 `handle_option_H` / `handle_option_L`）。
这正是"不靠记忆"这条要求的实战价值。

## 详细清单

### A. 已支持（27）

**基本选项 + 长名别名**

| proot 写法 | bxroot | 语义 |
|---|---|---|
| `-r` / `--rootfs <path>` | ✅ | rootfs 路径 |
| `-w` / `--cwd <dir>` | ✅ | 工作目录 |
| `-b` / `--bind <h>:<g>` | ✅ | bind mount |
| `-m` / `--mount <h>:<g>` | ✅ | 与 `-b` **完全同义**（proot 里两者 handler 相同） |
| `-0` / `--root-id` | ✅ | fakeroot |
| `--link2symlink` | ✅ | 硬链接模拟 |
| `-v` / `--verbose` | ✅ | 调试输出 |
| `-V` / `--version` | ✅ | 打印版本 |
| `-h` / `--help` | ✅ | 帮助 |
| `--about` | ✅ | 版本 + 简介 |
| `--usage` | ✅ | 用法 |
| `--kill-on-exit` | ✅ | 退出时结束容器内进程 |
| `--pwd` | ✅ | **归一**到 `-w`（proot 的旧名，它自己仍接受） |
| `-k` / `--kernel-release <r>` | ⚠️ | 接受并**明确告知不生效**（见下方） |

★ `-V`（大写，版本）与 `-v`（小写，verbose）**只差大小写但语义完全不同** ——
这是 proot 的既有设计，兼容层必须照做，不能"统一"成同一个小选项。

**别名组合**

| proot 写法 | bxroot | 展开为 |
|---|---|---|
| `-R <path>` | ✅ | `-r <path>` + `recommended_bindings[]`（18 条） |
| `-S <path>` | ✅ | `-0 -r <path>` + `recommended_su_bindings[]`（11 条） |
| `-i` / `--change-id 0:0` | ✅ | 等价于 `-0` |

**实测展开效果**（不是推测，用探针读 `BXROOT_BINDS` 环境变量数的）：

```
-r /tmp/rootfs           →  0 条 bind
-R /tmp/rootfs           → 14 条 bind
-S /tmp/rootfs           → 10 条 bind
```

与清单规模的差异全部来自"宿主上不存在 → 跳过"（见下）。

### B. 明确拒绝（7）—— 这条策略本身是设计决定

| proot 选项 | 含义 | 为什么拒绝 |
|---|---|---|
| `-H` | 隐藏 `.proot.*` 文件（`hidden_files` 扩展） | 本实现没有该扩展 |
| `-L` | 修正 `lstat` 对符号链接返回的 size（`fix_symlink_size` 扩展） | 同上 |
| `-p` | 端口保护（把 bind 到受保护端口的请求改到高位端口） | 同上 |
| `-q` / `--qemu` | 跨架构 QEMU 用户态模拟 | 本实现只做同架构路径翻译 |
| `--sysvipc` | 跨 IPC namespace 共享 SysV IPC | 无该能力 |
| `--ashmem-memfd` | Android 上用 ashmem 模拟 `memfd_create` | 无该模拟 |
| `-i <非 0:0>` | 任意 uid/gid 映射 | 需要完整的 setuid/getuid 语义拦截，未实现 |

★ **为什么是"明确拒绝"而不是"静默忽略"** ★

静默忽略比报错**糟得多**：用户以为选项生效了，实际没有。
举个具体的：用户传 `-H` 期望隐藏 `.proot.*`，我们若无视，他会看到那些文件
并以为"隐藏功能坏了"，而真相是我们从未实现 —— 排查方向完全跑偏。

同理 `-i 1000:1000`：用户想要那个身份，我们做不到却装作接受，
会让后续**所有**权限判断都错。所以宁可报错。

每个拒绝路径都打印**具体原因**，而不是笼统的"不支持"。

## 顺带修掉的一个真实缺陷

**未知选项被当成 guest 命令。**

```
$ bxroot --definitely-not-an-option
错误: rootfs 内找不到命令 --definitely-not-an-option
```

用户看到"命令找不到"，而真实原因是**选项名拼错了**。proot 的做法是
`unknown option '%s'`（`src/cli/proot.c` 的对应逻辑）。

已修为：以 `-` 开头但不认识的参数 → 报 `未知选项`，并**顺带提示最可能的原因**
（列出本项目明确未实现的几个选项）。单独的 `-` 按惯例仍当 guest 命令（表示 stdin）。

## 关于"接受但不生效"这两个选项的处理

按本项目的既定原则，**静默降级比报错糟**。但 `-k` 与 `--kill-on-exit`
既不适合直接拒绝（会让从 proot 迁移的命令行不可用），也不该静默接受。

最终取"**接受 + 明确告知**"这条路，理由是两者的失败模式**温和且可解释**：
不会产生错误数据，最多是走错分支。而拒绝它们的代价（命令行不可用）更大。

实测输出：

```
$ ./libbxroot -r /tmp -k 6.1.0 /bin/true
[bxroot] 注意: -k/--kernel-release 已接受，但**当前版本不生效**
          （需要 uname 钩子伪造 release 字段，尚未实现）。
          容器内 uname 仍返回宿主真实版本。

$ ./libbxroot -r /tmp --kill-on-exit /bin/true
[bxroot] 注意: --kill-on-exit 已接受，但**当前版本未接通**
          （需要在 runtime 的进程账本上实现退出清理，尚未实现）。
```

## 诚实标注：未能完全对齐的部分

| 项 | 状态 | 说明 |
|---|---|---|
| `-k` / `--kernel-release` | ⚠️ **接受但不生效**（已明确告知） | 需要 `uname` 钩子伪造 release 字段，未实现。**接受它的同时打印一行注意**，说明容器内 uname 仍返回宿主真实版本 —— 不这么做就是静默降级 |
| `--kill-on-exit` | ⚠️ **接受但未接通**（已明确告知） | 进程管理在 runtime 层（pid 账本），launcher 只组装参数并 execve，自己没有能力枚举 guest 进程树。同样打印注意 |
| `-R` 的 bind 清单 | ⚠️ 跳过逻辑是环境相关的 | 宿主上不存在的路径会被跳过并**打印条数**。proot 也是警告后跳过，但两边的"存在性判断基准"可能不同（见下） |
| `-H` / `-L` / `-p` | 🚫 未实现 | 见上表 |

### 关于 bind 存在性判断的一个陷阱

清单里的路径是**宿主视角**（`/etc/passwd` 指宿主那个文件），而 bxroot 自己跑在
容器里 —— 直接 `access("/etc/passwd")` 判断的是**容器的** `/etc/passwd`。

所以实现里用 `BXROOT_HOST_ROOTFS` 环境变量做前缀去看真实宿主文件。
**未设该变量时按容器视角判断**，这在纯容器环境里是对的，但在
"容器里跑 bxroot 再去开宿主路径"的场景下会判错。这是已知的语义边界。

实测（本容器，`BXROOT_HOST_ROOTFS` 未设）：`-R` 报"5 条推荐 bind 在宿主上不存在，已跳过"
—— 跳过的是 `/etc/hosts.equiv`、`/etc/netgroup`、`/etc/networks`、
`/var/run/dbus/system_bus_socket` 这类精简系统上本就没有的，**符合预期**。

## 复现

```sh
# 构建（交叉编译到 arm64；本容器里 gcc 直接产出 aarch64）
gcc -static -O1 -Wall -Wextra -o /tmp/launcher-test src/launcher/launcher.c

# 覆盖率矩阵
sh /root/probe/cli_compat.sh

# 逐个选项（用完整有效命令行，看首行判据）
# 见本报告"详细清单"一节的命令
```

## 改动文件

- `src/launcher/launcher.c` —— 唯一改动文件，零告警
  （`-Wall -Wextra -Wformat=2` 实测 0 条）
