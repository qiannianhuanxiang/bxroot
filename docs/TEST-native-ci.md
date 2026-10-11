# 原生 ARM64 验证入口

## 已准备

`.github/workflows/native-arm64.yml` 在 `ubuntu-24.04-arm` 执行：原生 l2s 与 fakeroot 协同、SHM 文件后端、copyout 两模式、OFD claim、ID ABA、fork 门窗口、static exec fd/映射、实际 SHM TRAP、原生 Linux LD_PRELOAD 自动 fork/wait。权限仅 `contents: read`，checkout 不持久化认证，不发布或部署。每步严格检查退出码和精确完成标记。timeout或缺marker为FAIL，不当SKIP。

运行器 `test/RUN_NATIVE_CI.sh` 的 run 模式拒绝 DSHA/Android/PRoot 环境标记、设备路径、被追踪进程以及进程祖先中的 PRoot。compile-only模式只编译不执行，因此当前AArch64工作区可以进行编译验证，但它不证明原生FS或TRAP行为。

日志根目录由 `BXROOT_NATIVE_CI_OUTPUT` 指定，未指定则为临时根下独立结果目录。结果/日志不会在退出时删除。CI无论成功失败都上传仅限 `.log`、`results.txt`、`metadata.txt` 的7天证据；不上传DSHA APK、源码、设备日志或构建二进制。

## 当前实证

- 工作流经现有 YAML parser 解析，runner/triggers/只读权限检查通过。
- `sh -n test/RUN_NATIVE_CI.sh` 通过。
- `CI=true ... --compile-only` 输出 `NATIVE_CI_COMPILE_PASS`。
- 当前设备尝试run模式，在测试前因 `DSH_HOME` 明确拒绝，rc1。
- 静态SHM探针增加真实SIGSYS交付计数：只有计数0才记TRAP_UNREACHED；收到信号后默认gate的ENOSYS作为正确关闭，verified错误作为失败。
- 远程权限核验命令 `GIT_TERMINAL_PROMPT=0 git push --dry-run origin HEAD:refs/heads/fix/shm-hardening-guest-reentry` 返回128：当前HTTPS GitHub身份不可用。没有实际push。

## 运行条件

恢复既有仓库GitHub认证后可推送该分支，通过PR触发原生作业。`workflow_dispatch` 手动入口需先让GitHub在默认分支注册该workflow，不能假定仅在新分支新增文件就已有手动入口。此前公开bxroot仓库的授权不等于当前会话仍有可用凭据；不得把凭据写进仓库、日志或URL。没有认证或真实runner结果时，本文件只能说明入口准备完成，不能声称剩余原生测试通过。

后续只读核查还确认：GH_TOKEN/GITHUB_TOKEN不存在，git credential helper未配置，Docker/Podman均不可用；公共Actions API读取被网络工具拒绝（api.github.com解析为非公网地址）。没有读取/输出凭据值，没有重复push认证失败，也没有换通道绕过网络工具拒绝。

`test/RUN_ISOLATED_AUDITS.sh` 是另一条外部受限Docker审计入口，需要预加载arm64工具镜像、rootless/userns-remap、builtin seccomp等条件。当前没有Docker/Podman，仅语法/dry-run/拒绝设备执行已验证。其结果即使收集成功也标记受限观测/不完整原生语义，不用来替代APK应用UID的最终seccomp/ABI验证。
