# SHM 测试收尾与验证范围

本轮仅修改 test/docs，runtime 由并行代理维护。

## 显式 key 接口

所有 keyed 探针现在必须传入 runner 生成的 key，不再回退到固定值。

```sh
spec KEY MISSING_KEY NEGATIVE_KEY
race KEY
rebuild KEY
xproc put KEY VALUE
xproc get KEY
xproc expect-absent KEY
xproc rm-id OWNED_ID
```

runner 使用 `secrets` 生成五个不同的正 key 和一个负 key，官方/bxroot 的 spec 使用同组 key 串行运行。初始创建以 `IPC_CREAT|IPC_EXCL` 确认归属；冲突失败，绝不先删除未知 key。随机值只降低碰撞，不提供内核 IPC namespace 隔离。

xproc 创建完成后打印精确 ID，runner 仅按该 ID 清理，退出 trap 也只清理已记录对象。进程强杀与创建到记录的窗口仍可能留下对象，不能承诺 SIGKILL 无泄漏。

## 判据

`RUN_SYSVSHM.sh --compile-only` 始终编译 spec/xproc/race/rebuild，使用 `-std=c11 -O1 -Wall -Wextra -Werror -pthread`。

运行模式在编译成功后检测官方环境。只有缺少官方 proroot、runtime 或 Python 等前置条件返回 2；一旦开始执行阶段，timeout、非零退出、清理失败、载荷不匹配、缺少或重复完成标记都返回 1。

- A：双方 rc=0，恰一个 `SPEC_DONE`。在定向归一之前要求官方 `nattch=0`、bxroot `nattch=2`，均 `segsz=5000 mode=600`。只归一明确的成功 shmget ID、id 字段和已验证的 nattch，不隐藏负返回值/errno。
- B：官方 EXCL 创建，bxroot 读到同 ID 和完整 payload；清理后确认 ABSENT；bxroot 再 EXCL 创建，官方读取；bxroot RMID 后官方确认 ABSENT。两个方向实际覆盖不同创建/发布路径。
- C：父进程读取16个结构化子进程 ID，必须相同；8线程200次 attach/detach 后计数1600、nattch1，rc=0且恰一个 `RACE_DONE`。
- D：100轮一个 remover 和两个 creator 并发。在操作静止后，仍可 attach 的返回 ID 必须仍由 key 索引；RMID 前已 attach 的数据必须保留；已知测试 ID 回收后可以重新 EXCL 创建。要求 `RMID_REBUILD_DONE rounds=100`。

runtime 非等待 claim 的 `EAGAIN` 只由测试 caller 对 shmget 最多100次、每次1ms重试。持续忙仍失败，SIGSYS handler 不因此增加等待。

D 是概率压力测试：一次通过不证明消除全部 TOCTOU。它不验证完整 Linux 延迟 RMID 账本/global nattch；保留映射是当前与官方兼容的必要行为。

## Copyout 和 CRLF

`RUN_ALL.sh` 增加 copyout compile-only 检查与 fork 隔离的 syscall capability 检查。能力测试只代表当前进程过滤链；没有自动在普通会话跑 `--ipc-stat` 并冒充 guest runtime 验证。

`RUN_EXEC_DIAG.sh` 的 CRLF 判据现在对比静态原生 exec syscall 基线，成功时比较完整 stdout，包括尾 CR；失败时要求126与CRLF诊断。不再接受任意 `^x` 输出，不把当前环境行为归因于某一内核版本。

## 本轮验证结果

- SHM 四探针 `--compile-only`：PASS。
- 改动 shell 脚本的 `sh -n`：PASS。
- `git diff --check`：PASS。
- 当前21个核心编译单元告警门禁：零告警（并行runtime修改后主线程应再复核最终状态）。
- Copyout 能力及单元测试：PASS；正常112字节，非法地址 EFAULT，跨页56字节短写。
- Exec 诊断：PASS；fd exec 子项因没有外层官方注入跳过。
- Proc fd：63/63 PASS。
- Session：兼容平台模式372/372，2项预期的外层proc-dup差异跳过。
- SHM runtime runner：rc2，缺少官方比较会话；未声称RMID并发测试在生产runtime已通过。

## 客观限制

1. 当前工作环境原生 SysV IPC 在创建阶段返回 ENOSYS，不能执行 Linux SysV IPC 的真实语义对照。
2. APK/guest 最终继承的过滤链需要在该会话运行 copyout 能力和 IPC_STAT fault 测试，root/adb shell 或普通容器能力不能替代。
3. quarantine 的 rename 后校验不是条件 CAS；不能靠测试调整宣称 runtime TOCTOU 已修复。claim 协议只协调遵守协议的参与者，官方 runtime 不参与时混合并发仍需明确限制。
4. 源码编译告警通过不证明新 anchor fd 的 close/dup/close_range/static-exec 生命周期完整；该问题由runtime代理和主线程验证。
5. 本轮没有提交、打tag、发布或上传任何 DSHA 文件。
