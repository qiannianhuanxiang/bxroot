# bxroot 原生调用第二版：自动 bionic world 分流

第二版在保留显式 `bx-host` 的基础上，加入可选的透明自动分流。启用方式：

```sh
BXROOT_AUTO_HOST=1 \
BXROOT_HOST_PATH=/system/bin:/system/xbin:/vendor/bin \
  bxroot ...
```

默认 `BXROOT_AUTO_HOST` 未设置或不等于 `1` 时，现有 guest 行为不变。

## 分流规则

进程管理层先按 guest PATH 查找。guest 中已有的同名程序优先；只有 guest PATH 没找到时，才按 `BXROOT_HOST_PATH` 查找宿主命令。宿主候选会读取 ELF `PT_INTERP`：

```text
/system/bin/linker64
/apex/com.android.runtime/bin/linker64
    -> Android bionic world

/lib/ld-linux-aarch64.so.1
    -> guest glibc world
```

候选的分类、执行权限检查和最终 raw `execve` 使用同一条宿主 backing path。自动模式不绕过 bxroot 的 rootfs/bind 翻译；显式 `/system/bin/...`、guest PATH fallback、`posix_spawnp` 都遵守同一个规则。

覆盖的入口包括：

```text
execve / execv / execvp / execvpe
posix_spawn / posix_spawnp
execveat / fexecve / syscall(SYS_execve)
system / popen
```

`posix_spawn` 的 file-actions、attr 和父进程 pid 账本仍按原语义传递。宿主分支清理 guest loader 环境，保留普通应用环境变量，重建 `PATH`、`HOME`、`TMPDIR` 和 Android runtime 变量；标准输入输出、PTY、窗口大小、信号、argv0 和退出状态保持继承。

## 环境与 shell

bash 会在启动时保存最初的 `envp`，仅调用后续 `setenv` 不能可靠改变它。第二版在自动模式的最早运行时入口中，若已有 `PATH`，原位替换原环境数组中的 PATH 槽位，不释放 loader 所有的旧字符串；因此 bash、dash、Node、C `execvp` 看到同一份 host PATH。

如果启动环境原本没有 `PATH`，runtime 不能把新变量安全地写入内核传入的 auxv 边界之前。该边界由 launcher/初始环境构造负责，不能通过在 NULL 后追加指针绕过。普通 bxroot 启动链会提供 PATH；bridge 直加载链应显式提供 PATH。

## 脚本

`#!/system/bin/sh` 等 bionic shebang 目标会在 exec 前解析，脚本和解释器都使用映射后的 backing path，解释器必须是可执行的 bionic ELF。可读但没有执行位的宿主脚本返回 `EACCES`，不会被强行交给解释器。

## 已验证

在 Termux 的 bxroot Ubuntu guest 中，第二版 runtime 通过匿名 memfd 加载，避免向设备目录写入测试库。真实 bridge/linker 链路的 **25 项回归全部通过**：

- `execve`、`execveat`、`fexecve`、`syscall(SYS_execve)` 保留 argv0、stdio、环境清洗和退出码；
- `execvp`、`execvpe`、`posix_spawnp`、`system`、`popen` 能执行 `getprop` 并返回 `V2352A`；
- `posix_spawn` 的 file-actions、attr、环境变量和退出码正常；
- Node `child_process.spawnSync` 同时启动宿主 `getprop` 与 guest `/usr/bin/true`；
- guest 同名程序优先，`BXROOT_AUTO_HOST=0` 时 `getprop` 仍为 command not found；
- host→host shell、PTY 窗口大小、输入、Ctrl-C 和退出状态正常；
- `#!/system/bin/sh` 原生脚本通过 exec 和 spawn；clean env 子 guest bash 继承 runtime、自动开关和 native PATH；
- host HOME/TMPDIR 可写，guest `/sbin/ldconfig` 返回 rc=0；
- runtime SHA256：`df2cd3080002eba59dc6736e4e84a60fcf5ea3f77fb192edb5294d49d7fe49a8`。

设备拒绝了匿名 memfd 权限修改，因此“非执行位脚本”的 Android 用例跳过；容器回归已通过 raw `X_OK` 验证 0644 脚本返回 `EACCES`。

容器侧真实分流集成回归为 **175 checks, 0 failures**，分类/环境回归为 **77 checks**，告警门禁检查 17 个编译单元零告警，原有 D4 回归为 118 cases / 908 checks PASS。

## 明确边界

这版不会把 DSHA 普通 UID 变成 Termux UID、root 或 Shizuku 身份；不会让 bionic 进程直接加载 glibc `.so`；host→guest re-entry、Termux companion RPC 和 Binder 后端仍属于后续能力。`dumpsys`、`pm` 等 Android 服务是否可用，仍由调用进程的 UID/SELinux/Binder 权限决定。

- 真机验证在 Termux App 的 Ubuntu guest 中，不是 DSHA 二改 APK；没有更新或重装你的 APK。
- `fexecve/execveat` 验证的是可还原为普通路径的 Android ELF；匿名/已删除 bionic ELF fd 的自动分流没有完成。
- 带 chdir file-actions 的相对 `posix_spawn` 不在父 cwd 下猜测为 host；自动 host spawn 只覆盖绝对 backing path。
- 本轮全量 `RUN_ALL --quick` 没有通过：l2s 类测试报错，随后测试环境出现工具/临时目录不可用。不能把聚焦回归的通过当作整套全绿。
- bridge 首次直接加载且初始 env 没有 PATH 时仍须由调用方补 PATH；launcher 与父 guest exec 环境构造已补齐，不能扩写原始 envp 的 NULL/auxv 边界。

本目录是第二版实验实现，源码、构建脚本与回归用例一同提交；它不是全量验证通过的稳定版。此前运行时包的 BUILD.json 记录的是打包时未提交的工作树状态，不代表之后的 Git 提交状态。源码推送不等同于更新 DSHA APK，也不自动发布 GitHub Release。
