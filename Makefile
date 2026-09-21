# Bxroot 顶层 Makefile
# 构建所有 5 个组件（DSHA bxroot 原生库接口）

CC = aarch64-linux-gnu-gcc-13
BUILD_DIR = build

# 通用标志
#
# ★ 本容器 aarch64 gcc 13.3.0 有**间歇性 ICE**（随机位置的 internal
#   compiler error）。所以重活请走 ./BUILD_RUNTIME.sh —— 它带重试循环
#   与 -O2→-O1→-O0 回退。这里的 make 规则是直接编译，ICE 时重跑即可。
COMMON_CFLAGS = -O2 -Wall -Wextra -D_GNU_SOURCE
SO_CFLAGS = -shared -fPIC $(COMMON_CFLAGS)
# ★ 16KB 页对齐（Android 15+ 16KB 内核设备硬要求；DSHA 集成的
#   调研报告 §六.2 点名缺失）。对静态 launcher 同样需要——
#   可执行文件的加载段对齐由链接器按 max-page-size 决定。
SO_LDFLAGS = -ldl -nostartfiles -Wl,-z,max-page-size=16384
LAUNCH_LDFLAGS = -static -Wl,-z,max-page-size=16384

# D4 进程管理层的源目录（proc.c / proc.h）。
#
# 优先仓库内的 src/proc —— 克隆下来即可构建，不依赖仓库外的兄弟目录。
# 回退到 ../proc 是开发期布局（D4 曾是独立子项目）。
# 可用 `make PROC_DIR=/path/to/proc` 显式覆盖。
PROC_DIR ?= $(if $(wildcard src/proc/proc.c),src/proc,$(abspath $(CURDIR)/../proc))

# DSHA 原生库目录（通过 /proc 访问）
DSHA_PID = 862
DSHA_LIB_DIR = /proc/$(DSHA_PID)/root/data/app/~~INREEqnMsX1sE4wB1AwTNA==/com.dsh.client-vawFPvwroDwIUExBFG9INw==/lib/arm64

# 目标文件
TARGETS = \
	$(BUILD_DIR)/libbxroot.so \
	$(BUILD_DIR)/libbxroot-runtime.so \
	$(BUILD_DIR)/libbxroot-linker.so \
	$(BUILD_DIR)/libbxroot-bridge.so \
	$(BUILD_DIR)/libbxroot-stub-loader.so

.PHONY: all clean install install-dsha debug runtime test test-quick

all: $(TARGETS)

# 推荐入口：带 ICE 重试与优化级回退的运行时构建（产物同一路径）
runtime:
	@sh ./BUILD_RUNTIME.sh

# === Launcher (静态二进制，伪装为 libbxroot.so) ===
$(BUILD_DIR)/libbxroot.so: src/launcher/launcher.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(COMMON_CFLAGS) $(LAUNCH_LDFLAGS) -o $@ $<

# === Runtime (LD_PRELOAD hook + l2s 硬链接模拟 + D4 进程管理) ===
#
# l2s 层（src/l2s/）编进同一个 .so：它挂在 link/linkat/unlink 上，
# 与被 hook 的路径翻译共享同一份状态，拆成两个 .so 反而要跨库调用。
#
# D4 进程管理层（agents/proc/proc.c）同样是**独立编译单元**编进本 .so：
#   - 它提供 execve/execv/execvp/execvpe（**已从 preload.c 删除**，
#     否则同名符号 multiple definition）、fork/vfork/posix_spawn*/
#     kill 家族/system/popen；
#   - preload.c 通过 weak 桥 bxroot_translate_path/bxroot_log 与它对接，
#     保证两层只有一套路径翻译语义。
#   - 链接期还需要一个 __dso_handle（定义在 preload.c 内）：
#     -nostartfiles 排除了 crtbeginS.o，而 proc.c 的 pthread_atfork
#     经 libc_nonshared.a 需要它。
L2S_SRC = src/l2s/l2s.c src/l2s/l2s-runtime.c
FR_SRC  = src/runtime/fakeroot.c
CR_SRC  = src/runtime/crash.c
SG_SRC  = src/runtime/sigsys.c src/runtime/syscall_guard.c src/runtime/livepatch.c

PROC_SRC  = $(PROC_DIR)/proc.c

# 注意这里的两个宏**语义不同、必须共存**：
#   -DFAKEROOT_PURE_LOGIC  存在性宏（#ifndef）→ fakeroot 只编纯逻辑
#   -DPX_PURE_LOGIC=0       取值宏（#if !PX_PURE_LOGIC）→ proc.c 编钩子层
# ★ 必须是 =0，不能只写 -DPX_PURE_LOGIC ★（后者会让钩子层声明被跳过
#   而实现仍编译 → 整片 unknown type name 'px_rtconfig'）
$(BUILD_DIR)/libbxroot-runtime.so: src/runtime/preload.c src/runtime/config.h \
        src/l2s/l2s.c src/l2s/l2s.h src/l2s/l2s-runtime.c src/l2s/l2s-runtime.h \
        src/runtime/fakeroot.c src/runtime/fakeroot.h \
        src/runtime/crash.c src/runtime/crash.h \
        src/runtime/sigsys.c src/runtime/sigsys.h \
        src/runtime/syscall_guard.c src/runtime/syscall_guard.h \
        src/runtime/livepatch.c src/runtime/livepatch.h \
        $(PROC_SRC) $(PROC_DIR)/proc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SO_CFLAGS) -Isrc/l2s -I$(PROC_DIR) -DFAKEROOT_PURE_LOGIC \
	    -DPX_PURE_LOGIC=0 \
	    -o $@ src/runtime/preload.c $(L2S_SRC) $(FR_SRC) $(CR_SRC) $(SG_SRC) \
	    $(PROC_SRC) $(SO_LDFLAGS)

# === Linker (dlopen/dlsym 拦截) ===
$(BUILD_DIR)/libbxroot-linker.so: src/linker/linker.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SO_CFLAGS) -o $@ src/linker/linker.c $(SO_LDFLAGS)

# === Bridge (host/guest 桥接) ===
$(BUILD_DIR)/libbxroot-bridge.so: src/bridge/bridge.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SO_CFLAGS) -o $@ src/bridge/bridge.c $(SO_LDFLAGS)

# === Stub Loader (静态程序加载器) ===
$(BUILD_DIR)/libbxroot-stub-loader.so: src/stub-loader/stub-loader.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SO_CFLAGS) -o $@ src/stub-loader/stub-loader.c $(SO_LDFLAGS)

# === 安装到本地测试目录 ===
INSTALL_DIR = /data/local/tmp/bxroot

install: all
	@mkdir -p $(INSTALL_DIR)
	cp $(BUILD_DIR)/libbxroot.so $(INSTALL_DIR)/
	cp $(BUILD_DIR)/libbxroot-runtime.so $(INSTALL_DIR)/
	cp $(BUILD_DIR)/libbxroot-linker.so $(INSTALL_DIR)/ 2>/dev/null || true
	cp $(BUILD_DIR)/libbxroot-bridge.so $(INSTALL_DIR)/ 2>/dev/null || true
	cp $(BUILD_DIR)/libbxroot-stub-loader.so $(INSTALL_DIR)/ 2>/dev/null || true
	@echo "安装到: $(INSTALL_DIR)"
	@ls -la $(INSTALL_DIR)/

# === 部署到 DSHA 原生库目录（替换原 proroot 库） ===
install-dsha: all
	@echo "部署到 DSHA nativeLibraryDir..."
	@echo "目标: $(DSHA_LIB_DIR)"
	cp $(BUILD_DIR)/libbxroot.so $(DSHA_LIB_DIR)/
	cp $(BUILD_DIR)/libbxroot-runtime.so $(DSHA_LIB_DIR)/
	cp $(BUILD_DIR)/libbxroot-linker.so $(DSHA_LIB_DIR)/ 2>/dev/null || true
	cp $(BUILD_DIR)/libbxroot-bridge.so $(DSHA_LIB_DIR)/ 2>/dev/null || true
	cp $(BUILD_DIR)/libbxroot-stub-loader.so $(DSHA_LIB_DIR)/ 2>/dev/null || true
	@echo "部署完成！重启 DSHA 应用以生效。"
	@ls -la $(DSHA_LIB_DIR)/libbxroot*

# === 清理 ===
clean:
	rm -f $(BUILD_DIR)/libbxroot.so
	rm -f $(BUILD_DIR)/libbxroot-*.so
	@echo "清理完成"

# === 调试版本 ===
debug: CFLAGS += -DBXROOT_VERBOSE=1 -g
debug: clean
debug: all

# === 测试 ===
#
# ★ 修正 ★ 原规则写的是 `bash test/full_test.sh`，而**该文件从不存在** ——
# 也就是说过去谁执行 `make test` 都只会拿到 "No such file or directory"，
# 全量回归实际上从没从 make 入口跑起来过（历史"全绿"记录均来自手敲的
# gcc 命令）。现指向真实的回归入口 test/RUN_ALL.sh，它串起 9 组测试：
# 告警门禁 / l2s / 协同 / fakeroot / 参数位置 / crash / D4 / wait / 构建。
#
# `make test-quick` 跳过耗时的运行时构建。

test:
	sh test/RUN_ALL.sh

test-quick:
	sh test/RUN_ALL.sh --quick
