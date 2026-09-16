# bxroot 架构设计

## 概述

对标上游闭源项目 proroot 的 5 个 .so 文件，实现一个开源的 LD_PRELOAD 路线 rootless Linux 运行时。

## 架构

```
libbxroot.so          入口 launcher
  └── libbxroot-runtime.so    运行时核心（路径翻译、环境伪装）
        └── libbxroot-linker.so    动态链接器拦截
        └── libbxroot-bridge.so    host/guest 桥接
        └── libbxroot-stub-loader.so 静态程序加载器
```

## 各组件职责

### 1. libbxroot.so（入口 launcher）
- CLI 参数解析：`-r <rootfs>`、`-w <dir>`、`-b <host>:<guest>`、`-0`（fakeroot）
- 自动发现其他 .so 文件（从 `/proc/self/exe` dirname）
- 设置环境变量（`BXROOT_ROOTFS`、`BXROOT_TMP_DIR` 等）
- 加载 runtime 库
- execve 目标程序

### 2. libbxroot-runtime.so（运行时核心）
- LD_PRELOAD hook：open、openat、stat、newfstatat、execve、readlink、realpath、access 等
- 路径翻译：绝对路径 + rootfs 前缀
- bind mount 映射：`-b <host>:<guest>` 路径重写
- fakeroot：伪装 uid=0/gid=0
- `/proc/self/exe`、`/proc/self/fd` 语义伪装
- 调试日志（`BXROOT_VERBOSE=1`）

### 3. libbxroot-linker.so（动态链接器拦截）
- 拦截 `ld.so` 的符号解析
- 确保 LD_PRELOAD 生效
- 处理 `dlopen`/`dlsym` 绕过点

### 4. libbxroot-bridge.so（host/guest 桥接）
- 与宿主系统通信
- 文件操作代理（当 rootfs 外路径需要访问时）
- 信号传递

### 5. libbxroot-stub-loader.so（静态程序加载器）
- 处理静态链接程序（LD_PRELOAD 无法注入）
- `execve` 拦截 + 解释器替换
- 预加载 trampoline

## 实现阶段

### 阶段 1：核心运行时（1-2 周）
- libbxroot-runtime.so（LD_PRELOAD hook）
- 路径翻译（open、openat、stat 等）
- rootfs、bind mount、fakeroot
- 测试：能运行 `/bin/sh`、`/bin/ls`

### 阶段 2：链接器拦截（1 周）
- libbxroot-linker.so
- 拦截 `ld.so` 符号解析
- 测试：能运行 Node.js、Python

### 阶段 3：静态程序支持（2-3 周，最难）
- libbxroot-stub-loader.so
- `execve` 拦截 + 解释器替换
- 测试：能运行静态编译的程序

### 阶段 4：入口 launcher（1 周）
- libbxroot.so
- CLI 参数解析
- 自动发现其他 .so 文件

### 阶段 5：生产化（2-4 周）
- 性能优化
- 调试日志
- Android 8-16 兼容
- 并行运行 + 灰度迁移

## 关键设计决策

1. **LD_PRELOAD 路线**：zero ptrace overhead，性能优于 proot
2. **静态程序处理**：通过 `execve` 拦截 + 解释器替换，而非 ptrace
3. **seccomp 兼容**：Android app 进程的 seccomp 白名单限制
4. **降级策略**：连续 3 次失败切回 proot（对标上游 proroot）

## 许可证

MIT 许可证（对标 DSHA 项目的 MIT 许可证）
