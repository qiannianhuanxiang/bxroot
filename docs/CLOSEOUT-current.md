# 当前收口状态

本文件记录 2026-09-28 收尾轮的实际代码和验证范围，替代早期“全部完成”表述。

## 已落实

- 默认 claim gate=0 同时拒绝 keyed 和 IPC_PRIVATE 新建，目录不新增 segment/token/key；避免能创建不能 RMID。
- 错误 key record/非普通文件返回 EINVAL，读取错误传播，仅 ENOENT进入创建。
- INT_MIN key 可发布并由 RMID清理。
- RMID在全局锁内先删segment，失败保留key；成功/ENOENT后清key，错误传播。
- size负值/页对齐溢出拒绝，初始化缓存实际pagesize；segment文件保留请求精确长度，只有mmap按页舍入。16KB模拟检查4097字节段和16384字节映射。
- OFD正常release显式UNLCK再close；无fork继承的SIGKILL owner自动释放已测。
- 持久.id-ID reservation防bxroot分配器生命周期内ID ABA，64候选耗尽ENOSPC，token不可GC且占用inode。
- 真实SHM入口与导出fork wrapper使用非等待事务门；活动SHM时fork EAGAIN，fork占门时SHM EAGAIN；父子返回各释放门，不复制半发布槽或持锁临界区。raw clone/_Fork/绕过wrapper的内部创建路径不在保证内。
- static早期handler与veneer接入194..197；模拟exec解除旧ACTIVE映射并清attach记录；默认gate保持明确关闭。
- default与verified隔离构建、BUILD-METADATA、严格profile参数，默认不会被环境gate变量盲开。

## 已获得证据

22编译单元零告警。claim默认无泄漏/INT_MIN/坏record/size/16KB/RMID错误/强杀恢复PASS；ID ABA PASS；真实shm_do_ctl两个copyout gate地址矩阵PASS；真实static reset旧映射解除和fd复用PASS；原生bridge/linker加载链fork忙门/自动登记/wait回收PASS；native reentry两入口各118checks PASS；l2s mock内存FS28checks PASS，独立于原生FS测试。

快速回归快照：/root/work/bxroot-regression-results/quick-AQaHBb/results.txt，44 PASS、2 FAIL、15 SKIP、23 BLOCKED、0基础设施ERROR。真实 mmap 完成到 attach 发布前、DETACHING 到 munmap 前两个暂停窗口均 fork_begin=-EAGAIN，恢复后 fork child 可 detach ACTIVE 映射，SHM_FORK_GATE_PASS；handler handled标志与detach实际返回码分开断言。两个FAIL是原生l2s与fakeroot协同，在外层PRoot --link2symlink下有独立FS前提失败证据；保留FAIL而非修改断言。mock PASS不替代原生FS验证。

原生 Termux（UID 10399，TracerPid=0，无 PRoot）用户执行 `RUN_TERMUX_NATIVE.sh`：copyout/claim/id_aba/fork_gate/static_reset/static_trap/l2s_mock/l2s_native 共 8 项 PASS。`static_trap` 实测 `FRAME ready=1 code=1 nr=194 offset=184` 且四组 gate `STATIC_SHM_SYSCALL_PASS`，这是 bxroot SHM SIGSYS 在原生环境的第一次通过。`l2s_native` 18 cases / 153 checks PASS。integration 首次因测试写死 real_uid=2000 失败；改为 `getuid()` 后单独重跑 7 cases / 47 checks PASS。

共存 APK `com.dsh.bxroot` 用户安装后 guest 终端：`BXROOT_REENTRY=1`，`TracerPid: 0`，`ldconfig.real -v` 无 EROFS，`node v24.19.0` 通过；`exit 7` 透传码 7；4 worker + pbkdf2Sync 正常返回。用户反馈可与官方 `com.dsh.client` 同时运行。

## 明确未通过

1. 外层 PRoot 容器内真实静态 SHM TRAP 仍是 `TRAP_UNREACHED`（raw 194 → ENOSYS）。该项已由原生 Termux `STATIC_SHM_SYSCALL_PASS` 覆盖，容器结果不再当作该项的失败证据。
2. 共存包冷启动/reentry/ldconfig/node/worker/`exit 7` 已过。未覆盖：dpkg 新装、两边实际 3080/3090 绑定、完整 guest syscall 过滤矩阵。`run-as com.dsh.bxroot` 仍可能 POLICY_BLOCKED。两个 App 都能开 ≠ 官方 proroot 与 bxroot 的 SysV SHM 混合并发已协调。
3. 高风险mount/chroot/pivot_root/全号扫描/逃逸测试未在共享文件系统执行。namespace创建能力探测成功不等于已建立完整可丢弃rootfs。Docker 当前不可用。
4. 官方proroot不采用锁/token，任意混合并发不保证；共用decimal格式只保证文件格式互通。
5. 保持官方文件式RMID、本进程nattch的兼容模式；完整Linux延迟删除/全局计数是不同协议，尚未实现，不能声称相同语义。
6. 并发guest主动close/reuse内部fd、直接munmap/MAP_FIXED、raw clone等绕过运行时接口不构成沙箱保证。

## 构建

```sh
sh BUILD_RUNTIME.sh -O1
BXROOT_BUILD_PROFILE=verified BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 sh BUILD_RUNTIME.sh -O1
```

默认输出build/libbxroot-runtime.so；verified输出build/verified/libbxroot-runtime.so。verified仅为已确认环境准备，不默认部署到共存APK。bxroot 源码发行见 tag `v0.2.3` 与 [`RELEASE-v0.2.3.md`](RELEASE-v0.2.3.md)。本仓库不包含、不上传任何 DSHA APK 或 DSHA 源码。
