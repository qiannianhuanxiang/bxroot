# RUN_ALL quick 运行器事故审查与修复

## 原始证据

审查输入为 `/root/work/bxroot-quick-final.log`（193 行）。路径参数表实测审计之前，运行器能执行编译和测试；该步之后首次出现 `tail/cut/sed/rm: not found`，同时结果文件所在 `/tmp` 变成不可访问。随后 `[ -f ... ]` 判断和日志重定向失败被当作“没有测试”或 rc=2 环境跳过。原始汇总只显示4通过/3失败，没有正常读取结果账本，不能当作完整回归结果。

日志与源码只能确认故障从路径参数表实测步骤起发生；原运行器删除每步日志，未留审计器原始输出与 syscall 返回值，不能进一步证明具体哪个 syscall 删除了真实 `/tmp`，或改变了外层 PRoot 的路径视图。`not found` 不等于这些可执行文件真的被删除。禁止在共享 rootfs 中通过盲目重跑寻找那个 syscall。

`test_syscall_table_audit.c` 不只是只读表核对：它执行 raw svc 400..500 全零参数扫描、mount/umount/chroot/pivot-root 相关调用、chmod、rename、unlink 和夹具清理。fork 只隔离进程状态，不隔离共享文件系统；ptrace 容器的 raw svc 也并非真实原生 syscall 空间。该测试必须先在可丢弃 rootfs/真实 mount 隔离后端中审查，不能以 fork 当沙箱。本环境未发现 bwrap，仅存在 unshare 命令；未执行未知权限的 namespace/mount 操作。

## 前两项 l2s 失败

安全复现了 `test_l2s_rt.c`：动态与静态编译均44失败。A1 的 l2s_rt_link 成功，读取内容成功，但 libc lstat 对客户/中间层的元数据契约失败，导致后续 link_more、unlink、stat 和目录项测试继续失败。integration 的14失败集中在这些元数据与l2s/fakeroot联合记账。

当前外层进程明确是 `libproot.so --link2symlink ... -0`，是 ptrace 执行链。去掉 LD_PRELOAD 或静态链接不能避开这个执行链。独立 `probe_runner_l2s_baseline.c` 使用同一个 REAL_OPS 和合法A1布局，实际结果为：

```
link=0 client_lstat=-1 errno=1 mode=120777 symlink=1
L2S_INJECTED_FS_PREREQUISITE_NOT_NATIVE
```

即接口在已填 symlink mode 后仍返回 EPERM；这证明当前注入文件系统前提不满足。它不证明所有44失败都只由容器引起，也不证明移到原生Linux后l2s实现一定正确。原始两项失败仍记录 FAIL，未通过硬编码期望或 SKIP 隐藏。

## 修改范围

只修改 `test/RUN_ALL.sh`，新增独立运行器自测/基线探针和本文档；没有修改 runtime。

- 默认结果路径位于 `/root/work/bxroot-regression-results/quick-*`，禁止将总账本放 `/tmp`。
- 账本保持打开的 append fd；全部每步日志、退出码和汇总留存，不再自动删除。
- 每个测试在 subshell 中执行，固定启动时PATH、设置专属TMPDIR；脚本步骤增加180秒timeout及5秒强杀宽限。
- 前后健康检查 `/tmp`、仓库、captured工具和持久结果可写性；失败记 ERROR 并停止，不级联制造SKIP。
- rc=2只有明确前提诊断且没有 `not found/cannot create/Directory nonexistent/编译失败/FAIL:` 才能SKIP。非零实际失败仍FAIL。
- 未完成副作用审查的探针记 BLOCKED，不执行，不计成功；存在BLOCKED时总返回1，明确表示不完整。
- 审查后运行的是完整“步骤登记矩阵”，不是完整测试全PASS，也不是已提供内核文件系统隔离。运行器从进程与日志层做隔离；共享文件系统风险通过禁止未审查探针处理，后续需要真实可丢弃隔离环境补测。

## 可核验运行结果

审查后执行 `sh test/RUN_ALL.sh --quick`，进程正常结束，exit1：

- PASS 20
- FAIL 5
- 明确前提 SKIP 1
- 未执行 BLOCKED 48
- 运行器基础设施 ERROR 0

完整stdout：`/root/work/bxroot-runner-review/quick-isolated.log`

持久结果与逐步原始日志：`/root/work/bxroot-regression-results/quick-CwGFj9/results.txt`、同目录 `step-N.log`。

五项失败：

1. l2s运行时44个assertion；完整日志step-2。
2. l2s×fakeroot14个assertion；step-3。
3. 身份syscall探针：statx输出NULL期望EFAULT，实际EINVAL；step-9。
4. session：374checks中两个proc-fd只读/EBADF与外层复制保留O_RDWR、EPERM差异；step-29。此次没有自动打开兼容skip开关。
5. bx-enter：107checks中一个失败；step-31。保留所有环境/cwd/stdin/session输出，不修改runtime。

`RUN_RUNNER_SELFTEST.sh` 已通过，验证 PASS、明确前提SKIP、假rc2→FAIL、实际FAIL、私有哨兵损坏→ERROR 的五条顺序和所有日志留存。它只删除自己的哨兵，不操作 `/tmp` 或系统目录。自测证据 `/root/work/bxroot-runner-selftest-QcOoog`。

## 下一步

在真实可丢弃 rootfs/mount 隔离环境中逐个审查并补测48项BLOCKED，尤其raw syscall全号/路径表审计、权限与路径爆破。5项失败需要按已保留日志判断是环境契约不满足、测试错误还是实现错误，不能把大量环境失败改成成功。当前结果是可核验但不完整且失败的quick矩阵。
