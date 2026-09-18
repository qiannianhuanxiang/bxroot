# Android / bionic 集成指南

> 面向想把 bxroot 打进 APK（一键 Linux 启动器等）的集成方。
> 本文沉淀 v0.1.1 在 bionic 工具链下的实测编译结论与部署契约。

---

## 一、组件与编译矩阵

| 组件 | bionic (NDK r26+ clang) | 说明 |
|---|---|---|
| `libbxroot-linker.so` | ✅ 零改动 | 无 glibc 专属 API |
| `libbxroot-bridge.so` | ✅ 零改动 | 同上 |
| `libbxroot-stub-loader.so` | ✅ 零改动 | 同上 |
| `libbxroot.so`（launcher） | ⚠️ 见 §二 | 静态链接需 `-latomic`；推荐动态形态 |
| `libbxroot-runtime.so` | ⚠️ 见 §三 | v0.1.1 起主要冲突已条件编译隔离 |

工具链实测：aarch64 原生 clang + NDK bionic sysroot（`--target=aarch64-linux-android21`）。
NDK 不再带 `libgcc.a`，需 `-nodefaultlibs` 规避自动 `-lgcc`。

## 二、launcher 链接形态

- **静态**（`-static`）：bionic 静态 libc 缺 LSE 原子内置
  （`__aarch64_ldadd/cas/swp`）与 `pthread_atfork`，需 `-latomic` 或
  `-Wl,--whole-archive -lc -Wl,--no-whole-archive`。
- **动态**（推荐）：`-shared -fPIE`，随 App `jniLibs` 被 linker 定位。
  launcher 本来就用 `dirname(self)` 找兄弟 `.so`，动态化零源码改动。

## 三、runtime 的 glibc/bionic 边界（v0.1.1 已处理）

| 冲突 | 状态 |
|---|---|
| `ioctl` 与 bionic `overloadable` 声明冲突 | ✅ `#ifndef __ANDROID__` 跳过该钩子（Android 上 ioctl 语义由 ldso 服务提供，路径翻译不依赖它） |
| `dlvsym`（glibc 扩展，bionic 无） | ✅ `#ifdef __ANDROID__` 走 `dlsym`；该降级分支在 Android 本不该走到 |
| `__libc_sigaction`（GLIBC_PRIVATE） | ✅ 弱引用 + 探测，bionic 下退化为不安装 SIGSYS 防护层 |
| `_GNU_SOURCE` 重定义告警 | ✅ `#ifndef` 包裹 |

## 四、部署契约（硬约束）

1. **5 个 `.so` 放同一目录**（APK `jniLibs/arm64-v8a/`，安装后即
   `nativeLibraryDir`）。launcher 用 `dirname(/proc/self/exe)` 找兄弟
   runtime —— 不可拆分目录。
2. **launcher 必须能被 exec**。`nativeLibraryDir` 满足 SELinux 的
   `system_app_data_file` execute 例外（app_data_file 不可 exec）。
3. **rootfs 放 app 私有目录**（`files/`），首次启动从 assets 解压。
4. **SELinux 禁止 `link(2)`** → 必须 `--link2symlink`（DSHA 生产即
   无条件启用）；`link()` 失败时 l2s 也会自动启用，但显式传更稳。
5. **环境变量**：`BXROOT_ROOTFS`（rootfs 绝对路径）、`BXROOT_TMP_DIR`、
   `BXROOT_FAKEROOT=1`、`BXROOT_GUEST_EXE`（guest 视角完整路径）。
6. **execve 用内核视图路径**：给 bridge 的组件路径**不带**
   `/proc/<pid>/root` 前缀（带前缀会让加载器算错 lib_dir → SIGSEGV）。

## 五、X11 / 图形

- GUI 依赖外部 X server（Termux:X11 / XSDL）。bind 形态：
  `bxroot -b /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=:0 ...`
- AF_UNIX 的 `bind`/`connect` 路径翻译已内建（上游 proot issue #8 的
  对应能力）；抽象命名空间不受影响。
- GPU 加速（DRM/GBM/vGPU）属于宿主 App 层能力，bxroot 不提供 ——
  纯软件渲染的桌面/终端可跑，硬件加速需 App 侧图形栈配合。

## 六、已知边界

- `pam` 登录族不可用（proot 上游 #156/#174 同样，非 bxroot 缺陷）。
- 静态链接的 guest 二进制拿不到 LD_PRELOAD 注入（upstream 同限制）。
- 内核最低版本未系统验证（Android GKI 4.14/4.19 为主流，欢迎反馈）。

## 七、复现/自查命令

见 `docs/` 的 Android 实测报告（bionic 编译命令逐条可粘贴）。
