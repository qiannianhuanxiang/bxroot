# 外部原生 CI 隔离审计入口

`test/RUN_ISOLATED_AUDITS.sh` 是独立 Bash 入口，不修改 runtime、RUN_ALL 或 workflow，不在宿主直接执行任何审计探针。

## 实际副作用审查

| runner / probe | 真实行为 | 此入口的运行范围 |
|---|---|---|
| RUN_SYSCALL_TABLE_AUDIT.sh / test_syscall_table_audit.c | 原生 AArch64 svc；mount40、umount39、pivot_root41、chroot51、现代 mount 族；unlink/chmod/rename 等夹具操作；另扫描400–500 | 每次独立、非特权 Docker 内可编译并尝试 runner；errno/availability 受 seccomp 与权限影响 |
| RUN_TRAP_PARITY.sh / probe_trap_enum.c | 三轮0–462全号枚举，不能按“fd=-1”推断无副作用 | 容器先编译探针，再运行原 runner；外部原生CI无官方proroot映射时原 runner明确rc2，不伪造映射、不强行绕过前提执行枚举 |
| RUN_AUDIT_FIXES.sh / probe_audit_fixes.c | 删除固定/tmp/aud_*、/tmp/victim，mount/pivot_root名称未证明不存在 | 容器先编译，再运行原 runner；无官方注入链时rc2；固定/tmp仅存在于本次tmpfs |

原 runner 自己打印的 PASS 只属于受限容器内观察结果。包装器整体从不输出 native e2e PASS，正常收集结果后仍返回2（INCOMPLETE_NATIVE_E2E），任何构建、实际测试、Docker失败或timeout返回1。

## 外部 CI 前提

- 原生 Linux AArch64；不是 Android、DSHA、PRoot，也不是 QEMU/binfmt 交叉模拟。
- `CI=true`，无 DSH/DSHA/PROROOT 环境变量、无设备凭据路径/Android文件系统；进程及全部可读祖先的cmdline/maps也不得含相关运行器。无法读祖先即拒绝。CI变量不能绕过这些检测。
- 本机 Unix Docker context，无 DOCKER_HOST/TLS远程配置。
- Docker builtin seccomp启用，且daemon使用userns-remap或rootless。普通rootful未配置userns的daemon拒绝。不能改成privileged或seccomp=unconfined。
- Docker需支持 `--mount bind-recursive=disabled`（现代Docker Engine）；不支持会明确失败，不回退到更宽的挂载。全部bind禁用递归子挂载。
- 预先准备本地可信arm64镜像，含 `/bin/sh`、gcc、python3、GNU timeout、cp及runner所需基本工具；Docker image不能声明VOLUME。脚本解析本地image ID后以ID运行，`--pull=never`，执行期间不拉镜像或安装软件。
- CI用户可读src/tools与选定test文件，拒绝src/tools内任何符号链接；Docker userns-remap权限必须让非root UID65532可读取只读挂载（工作副本用正常只读权限即可，不要挂用户凭据）。

```sh
# 任何环境都可以执行：只打印计划，不连接Docker、不编译/运行探针
bash test/RUN_ISOLATED_AUDITS.sh --dry-run

# 只能在满足上述条件的外部原生CI运行
CI=true bash test/RUN_ISOLATED_AUDITS.sh --run \
  --image YOUR_PRELOADED_ARM64_AUDIT_IMAGE \
  --output /absolute/existing/artifact-directory
```

这里故意没有可在设备开启的override、host namespace开关或提权参数，也没有自动sudo。当前DSHA环境只能syntax/dry-run；不能因为脚本拒绝设备而改用另一通道执行。

## Docker约束与结果

每项一个新容器，默认独立PID/IPC/cgroup/network namespaces；network none；nonroot UID/GID65532；cap-drop ALL；no-new-privileges；只读image rootfs。要求daemon userns/rootless，不使用host userns。没有宿主socket/device挂载，没有容器特权或宿主network/PID/IPC模式。

只读bind挂src/、tools/及当前runner/probe两文件；容器仅复制src内 `.c/.h/.S/.s/.inc/.ld/.sh` 和单个 `tools/bxroot-run` 到私有可写/work，不复制src历史测试二进制。/work(512MiB)、/tmp(256MiB)、/run(16MiB)均tmpfs，nosuid/nodev；/run额外noexec，/work和/tmp允许执行本次编译产物。宿主源码不可写。没有绑定宿主可写rootfs、.git、build产物、/etc、/usr或Docker socket。

资源上限：128 pids、1GiB RAM且swap总额1GiB、1 CPU、256 fd、core=0；每runner180s加5s强杀宽限，每Docker任务900s加10s宽限。所有退出路径只删除本次精确随机容器名，Docker --rm回收私有tmpfs；宿主结果保留到指定目录下mktemp生成的独立子目录。当前设计总计最多三项，不执行任意用户给定脚本。

结果含固定image ID、source路径、每项完整stdout/stderr、Docker/runner rc。无法启动、编译失败、timeout等不会算SKIP或PASS。seccomp EPERM/ENOSYS/SIGSYS或capability拒绝仅代表受限策略结果，不能证明原生内核的syscall参数/错误优先级，也不能证明Android guest过滤器或SHM模拟行为。

## 本轮验证

当前没有在本机运行Docker或高风险probe。只检查 `bash -n`、dry-run输出和设备环境拒绝。没有获得容器audit结果，更没有native内核语义e2e通过结论。
