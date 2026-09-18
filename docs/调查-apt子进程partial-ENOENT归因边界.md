# 调查：apt 子进程 `partial` ENOENT —— 本容器无法复现，归因锁定 bxroot 环境

> **状态**：**未能在本容器复现**。归因边界已查清，需报告作者环境（LD_PRELOAD
> 生效的纯 Linux）才能做最终判定。
>
> **来源**：第三方评估报告 3.7 条；本会话原调查子代理中途终止，本文件由
> 主会话据其留存的实验产物整理。

---

## 一、报告现象（原样记录）

报告作者在纯 Linux（Ubuntu 24.04 / aarch64 / 外层 proot）下，bxroot 内：

```
E: can not open /var/lib/apt/lists/partial/<file> - fopen (2: No such file or directory)
E: setgroups 65534 failed - setgroups (38: Function not implemented)
```

且：容器内对同一目录同名文件 `touch` 成功；手动跑 `/usr/lib/apt/methods/http`
协议正常；宿主 curl + `dpkg-deb -x` 可完成安装闭环。

## 二、本容器的实验与结论

实验产物：`/tmp/aptinv-232516/`（`apt-update-{1,2,3}.log`）。

| 次数 | 镜像 | 结果 |
|---|---|---|
| 1 | 127.0.0.1:18082 | `E: repository ... is not signed`（签名问题） |
| 2 | 同 1 | `E: Some index files failed to download`（签名问题） |
| 3 | 127.0.0.1:18081 | **完整成功**：`Fetched 1632 kB` → `Reading package lists...` |

- 三次日志 **grep `partial` = 0**，**grep `setgroups` = 0**。
- 失败的那两次是**本地镜像签名/索引问题**（`not signed` / `weak`），与
  bxroot 无关；换到签名正常的镜像（18081）后 apt 全流程走通。

## 三、为什么本容器无法做最终判定

**架构性原因**：本容器 `LD_PRELOAD` 惰性（外层 proroot 自研 loader 劫持
`execve`，见 `docs/调查-LD_PRELOAD在proroot容器内失效.md`）。因此：

- apt 主进程及其 `methods/*` 子进程**都不可能**挂上 bxroot 运行时；
- 上面第 3 次成功，是 **apt 在无 bxroot 介入**下的正常表现。

也就是说：本容器的"apt 正常"**不能**用来否定报告现象 —— 它只是证明了
"无 bxroot 时 apt 正常"。报告现象发生在 **bxroot 生效** 的环境，二者不可比。

## 四、归因假设（供报告作者环境验证，未定论）

按可能性排序，都需要在 LD_PRELOAD 生效环境用判别输入验证：

1. **apt 子进程环境清洗**（最可能）：apt 对 `methods/*` 子进程做环境清理
   （APT Sandbox 相关），`LD_PRELOAD` 在子进程丢失 → 子进程按**宿主视角**
   打开 `/var/lib/apt/lists/partial`（宿主该目录与 rootfs 内容不同）→ ENOENT。
2. **双重前缀**：子进程路径经两次翻译变成 `<rootfs><rootfs>/...`。
3. **realpath 反向翻译缺失**（本会话已修，见下）：apt 用 `realpath` 取绝对
   路径做相等性判断，旧版本返回宿主前缀导致判断错位。

## 五、本会话已顺带修复的相关项

**`realpath` / `__realpath_chk` / `canonicalize_file_name` 返回值反向翻译**
已实现（评估报告 8.2）：这三个 API 的返回值此前是宿主绝对路径，现已剥
rootfs 前缀 + 反向 bind，返回 guest 视角。单元测试 12/12 通过。这直接覆盖
了上面第 3 条假设的机制。

## 六、验证方法（给报告作者环境）

判别输入：在 rootfs 内建一个 `partial` 目录独有的标记文件（宿主同名目录
放不同内容），在 bxroot 内跑 `apt-get update`，观察：

```sh
# 宿主侧与 rootfs 侧的 /var/lib/apt/lists/partial 内容不同
echo HOST  > /var/lib/apt/lists/partial/marker.host
echo GUEST > $ROOTFS/var/lib/apt/lists/partial/marker.guest
# bxroot 内
apt-get update 2>&1 | grep -E "partial|setgroups"
# 若报 ENOENT 且能证明子进程按宿主视角 → 假设 1 成立
strace -f -e trace=openat -o /tmp/apt.tr apt-get update
# 检查 /tmp/apt.tr 里 partial 的 openat 用的是宿主还是 rootfs 路径
```

## 七、诚实标注

1. **本容器无法复现**，也没有在本容器制造出等价现象 —— 归因是推断，非实证。
2. 上述三个假设**一个都没在本环境验证**（架构上不可能）。
3. `setgroups` 那条报告作者已自认是外层 seccomp 限制（非 bxroot 缺陷），
   本容器三次实验中也未出现（apt 未走到降权沙箱那步）。
4. 报告作者验证时请注意区分："apt 在无 bxroot 下正常"与"apt 在 bxroot 下
   正常"是两件事。
