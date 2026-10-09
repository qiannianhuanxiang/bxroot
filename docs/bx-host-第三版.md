# bxroot 原生调用第三版：双向执行与会话交接

第三版是可选的实验实现：Ubuntu/glibc 的 agent 可进入 Android 原生环境，再通过显式回入口启动原 guest 程序。bxroot 不绑定 DSHA 端口、凭据或 Termux UID；两种 libc 仍分属不同进程。

## 启用

```sh
BXROOT_AUTO_HOST=1 BXROOT_REENTRY=1 \
  /path/to/libbxroot.so -r /actual/rootfs -w /root /bin/bash
```

`BXROOT_AUTO_HOST` 控制第二版的原生命令自动分流，`BXROOT_REENTRY` 控制第三版会话。两个开关都须精确等于 `1`，默认行为不变。launcher 会预置会话变量槽、保存注入前的 guest PATH，并从同目录寻找 `libbxroot-enter.so`；可通过 `BXROOT_ENTER` 指定实际宿主路径。

入口应放在 App 实际可执行的 nativeLibraryDir。此包不能通过把文件复制到任意 App data 或 Download 目录就获得执行权限。普通 launcher 场景需要已可用的 ULX/guest ld.so 启动链；已有 bridge/linker 场景则复用该链。

bridge 直接加载调用者应提供 `BXROOT_ENTER`、`BXROOT_SESSION_FD=""` 和 `BXROOT_GUEST_PATH` 初始槽位；runtime 只替换已有原始 envp 槽，不在 NULL 后面扩写 auxv。后端内部仍保存权威会话供子进程传播，但没有预置槽的初始 bash 不能保证变量展开可见。

## 原生侧回入

```sh
# Android shell 中回到同一 guest
"$BXROOT_ENTER" --cwd /root -- /usr/local/bin/node app.js

# 使用 guest PATH 搜索
"$BXROOT_ENTER" --cwd /root -- printf 'back-to-guest\n'

# 参数中的文件路径不会自动改写
"$BXROOT_ENTER" --to-host /etc/os-release
"$BXROOT_ENTER" --to-guest /actual/rootfs/usr/lib/os-release

# env -i 后，调用者明确提供仍然有效的会话 fd
/path/to/libbxroot-enter.so --session-fd N --cwd /root -- /usr/bin/true
```

没有 `--cwd` 时读取 host 调用现场的真实 cwd，经反向映射与正向验证确定 guest 目录。多个有效 bind 别名返回 `ENOTUNIQ`；目录不可用或映射失败时报告具体错误，不静默切到 `/root`。`--cwd` 必须是 guest 绝对目录。

`--argv0 NAME` 支持自定义 argv0。目标支持 AArch64 glibc 动态 ELF、guest PATH 搜索和最多四层 shebang；静态 ELF及不支持的 interpreter 目前明确拒绝。URL、JSON、正则等普通 argv 原样传递，文件交接使用显式转换或共享 bind。

真机测试将回入口放在匿名 memfd，用 `/system/bin/linker64 "$BXROOT_ENTER" ...` 显式装载。该模式在 `AT_BASE` 存在且为 0、argv0 精确为 Android linker 时去掉一层 linker 参数。正常内核 PT_INTERP 启动保持原始 argv，不依赖 glibc 启动代码。

## 会话与环境

会话协议以 `BXSESS3`、版本和长度标记，采用小端记录，不含进程内指针。实际 rootfs、bind/只读标志、fakeroot/l2s 配置、加载链及两套环境通过封印 memfd 保存。内容写入后加 `F_SEAL_SEAL|SHRINK|GROW|WRITE`，再发布只读可继承 fd；读取用 `pread`，不共享可变 offset。

runtime 精确比对 rootfs 与有效 bind，记录会话 fd 的 dev/inode，拒绝关闭后被其他文件复用的 fd；在跨 exec 之前恢复会话 fd 的可继承状态。调用者若通过 spawn file-actions 等主动关闭会话 fd，回入口会失败，不能凭父 PID 重建配置。

host 环境清理 guest 的加载变量，仅显式加入 `BXROOT_ENTER`、`BXROOT_SESSION_FD`。回入口继承调用现场普通变量，再恢复 guest PATH/HOME/TMPDIR、loader、bind、cwd 与标记。独立 `bx-host` 已取消 128 项环境截断，并采用 host HOME/TMPDIR 配置或当前实际 cwd。

会话只恢复配置，不声称跨原生 exec 保存全部进程内 fakeroot inode 账本、临时身份变更或 pid 账本。

## 已验证

当前第三版在 vivo V2352A / Android 16 / Termux 普通 App 身份下通过真实 bridge/linker 链验证：

- 核心混合回归 **21/21 PASS**：Node→Android shell→guest Node→getprop、初始 bash 槽位、环境变化、cwd、路径交接、只读 bind、guest 脚本、持久 guest ldd 脚本、PTY、输入、Ctrl-C 与 clean env 显式 fd。
- 额外脚本诊断 **7/7 PASS**：bash/dash 回入前后读取匿名 bind 脚本，并严格验证 proc fd 不被解析为显示名。
- 真机会话 fd 是 `O_RDONLY`，封印值 15，写入为 `EBADF`；guest UID=0 与真实 App UID=10399 分开核验。
- 容器会话路径 **369 PASS、2 SKIP**；2 项跳过只在独立诊断确认外层 proc fd 重开被变成封印读写句柄、并显式开启测试开关时允许。默认严格模式仍报告这两项失败。真机相应断言已严格通过。
- native-session 后端 **18 cases / 1454 checks PASS**，静态及无 libc PIE 回入口各 **107 checks PASS**。
- proc fd 源码级解析器 **63/63 PASS**，覆盖 memfd、pipe、regular fd、非法形状、普通符号链接以及 guest symlink→proc fd；该项不代替 Android loader 覆盖。
- 发行回入口为 AArch64 PIE，PT_INTERP 为 `/system/bin/linker64`、16KB LOAD 对齐，无 NEEDED、TLS 和命名未定义符号。

曾将匿名脚本失败误判为 fd 生命周期并标 SKIP。后续只读对照证明 fd owner 仍在运行，实际原因是 runtime 将 proc fd 显示名重新拼到 rootfs 下。该缺陷已修复，测试恢复严格 PASS；旧 SKIP 日志不作为最终交付证据。

## 明确边界

- 真机结果来自 Termux App 沙箱，**不是 DSHA APK 集成验收**。没有替换、重装或更新 APK。
- 无透明的任意 host 后代 exec 拦截；原生程序调用 guest 必须经过回入口。
- 匿名/已删除 bionic ELF fd 自动分流，以及相对 `posix_spawn` 配合 chdir actions 仍保留第二版边界。
- 本轮未声称全量 `RUN_ALL --quick` 通过。两组 l2s 已同环境比对第二版前后，失败完全一致；独立探针确认外层 proot 的 `.l2s.*` 处理污染文件系统夹具。全量其他问题仍未全部归因。
- bxroot 不改变 Android 实际 UID/SELinux 权限，不提供跨 App 代执行、Termux companion 或通用 Binder 服务；这些属于独立适配工作。

产物为通用运行时 zip、源码与验证日志，不是 APK，也不自动创建 GitHub Release。
