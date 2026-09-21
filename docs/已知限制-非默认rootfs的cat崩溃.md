# 已知限制：非默认 rootfs 下 `exec` → `cat` 偶发 `munmap_chunk`

> **状态：未修复，已定界。** 只影响**显式 `--rootfs <另一个 rootfs>`**
> 且走了 `exec` 的场景；**默认 rootfs 下 0/20，不受影响**。
> 因为是次要路径，优先度低于其它缺陷，但如实记录、不隐藏。

## 一、现象与范围

```sh
$ bxroot-run --rootfs /root/bxtest-pd/rootfs -- /bin/sh -c '/bin/cat /etc/hostname'
runnervmbvass
munmap_chunk(): invalid pointer
Aborted                      # rc=134
```

| 组合 | 失败率 |
|---|---|
| 默认 rootfs（Ubuntu 24.04 / glibc 2.39） | **0/15** |
| 默认 rootfs + `exec` → `cat` | **0/15** |
| Debian 13 rootfs（glibc 2.41）+ **直接** `cat` | **0/15** |
| Debian 13 rootfs + `sh -c '/bin/cat …'` | **6–13/15** |

**关键分界**：同一条命令，**"直接跑"正常、"经 shell 转一手"就崩**。

## 二、已排除的假设（逐个实测）

| 假设 | 实测 | 结论 |
|---|---|---|
| 是我的"绝对符号链接展开"引入的 | `BXROOT_NO_ABSSYM=1` 关掉后仍 7/10 | ❌ 无关 |
| bxroot 的 `mmap`/`munmap`/`malloc`/`free` 钩子 | 这些符号 **bxroot 根本没有导出** | ❌ 不存在 |
| `fadvise64` / `posix_fadvise` | 探针实测返回值正常（0） | ❌ 无关 |
| `copy_file_range`（cat 特有） | 跨设备恒 EINVAL，两侧一致 | ❌ 无关 |
| `BXROOT_FAKEROOT` / `NO_CRASH` / `NO_LIVEPATCH` / `RAW_SYSCALL` | 逐个开关试验，失败率不降 | ❌ 无关 |
| argv/env 被破坏 | 自建探针打印 argc/envc/内容全对，堆压力测试通过 | ❌ 无关 |
| 父进程堆被破坏 | 父进程 `malloc`/`free` 压力测试通过，只有**子进程**崩 | ❌ 无关 |

**对照证据**（同一 bridge/linker，只换 `--preload` 的 runtime）：

```
官方 proroot : 0/10 失败  ✅
bxroot       : 7/10 失败  ❌
```

所以是 bxroot 侧的问题，但**触发条件尚未定位到具体代码点**。

## 三、已收窄到的现象特征

- 崩溃点固定在**输出完成之后**（`strace` 显示 sread 到 EOF、写 stdout 成功，
  随后 `writev(2,"munmap_chunk(): invalid pointer")` → `tgkill(SIGABRT)`）；
- 只有 `cat` 这一类程序命中；`/bin/true`、`/bin/echo`、`/bin/ls`、
  自建小程序均 **0 失败**；
- `MALLOC_CHECK_=0` 能消除 abort（但那是**掩盖**，不是修法）；
- 与 glibc 版本相关（2.41 出现，2.39 不出现），
  但**不是**因为 livepatch 站点表过期 —— 站点表跳过时只打一行
  WARN，且跳过是安全的（`docs/livepatch门控修复.md` 已论证）。

## 四、为什么现在不修

1. **不在目标路径上**：目标判据是"子代理基于默认 rootfs 做项目零报错"，
   而默认 rootfs 实测 0/15；
2. **修它的成本高**：需要在 glibc 2.41 的 `cat` 退出路径上做二分，
   而本项目**没有 glibc 2.41 的符号/偏移资料**（livepatch 站点表是 2.39 的）；
3. 现有证据已足够让后人**不必从零开始**（上面那张排除表是主要价值）。

## 五、后继者的起点

```sh
# 复现（10 次里约 6-13 次失败）
cd /root/bxroot
./tools/bxroot-run --rootfs /root/bxtest-pd/rootfs -- /bin/sh -c '/bin/cat /etc/hostname'

# 二分方向：cat 与 /bin/true 的差异里，唯一确认不同的是
#   cat 会 fadvise + mmap 大缓冲 + 走 stdio 的 atexit(close_stdout)
# 但单独复刻这三步**不复现**，说明还缺一个未识别的条件。
# 建议下一步：用 ASan 构建 cat（或 LD_PRELOAD 一个 malloc 追踪器）
# 定位那次非法 free 的调用点。
```
