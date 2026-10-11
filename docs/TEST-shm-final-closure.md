# SHM 收尾验证与边界（最终补充）

## 最新实现状态

以下内容取代早期单纯 close 释放和 PRIVATE 可创建的描述：release 会显式 `F_UNLCK` 后 close；claim gate=0 下 PRIVATE 与 keyed 新建均返回 ENOSYS且不创建 backing，测试检查空目录。RMID 在全局锁内先删除 segment，成功或 ENOENT 后再清 key；segment 删除失败保持索引。坏 key record/非 regular 返回 EINVAL，只有 ENOENT 允许创建。INT_MIN 发布与回收已实际测试。初始化缓存页面大小，映射按实际页面舍入并检查溢出。

分配器先建立永久 `.id-ID` reservation，再建立十进制 segment。RMID和失败路径不删除 reservation；ID碰撞重试64次后ENOSPC。测试强制重复ID，验证旧shmid无法删除新段。reservation消耗inode/目录项，清理它会破坏目录生命周期内不复用保证；官方不遵守该协议的分配不在保证内。

真实SHM分发入口和导出的fork钩子共同使用非等待事务门。SHM正在进行时fork返回EAGAIN且不产生子进程；fork成功占门后新SHM操作返回EAGAIN，真实fork返回后父子各释放自己的快照。由此避免受钩子管理的fork复制活动claim或RESERVED/DETACHING attach槽。原生加载链实测忙门拒绝、父子门释放与自动账本登记。raw clone、_Fork及不经过该fork钩子的第三方内部创建路径不由pthread_atfork通知独立保护。

static syscall veneer与早期SIGSYS handler已接入194..197后端；四种gate的ucontext寄存器帧测试通过，真实限定TRAP当前被外层PRoot转为ENOSYS，记录rc2。静态exec提交阶段会解除旧ACTIVE SHM映射并释放attach槽；真实reset测试验证旧地址mincore返回ENOMEM、计数归零、anchor仍保留。

构建profile默认gate0/0写入build/libbxroot-runtime.so，verified必须显式profile和两gate1，写入build/verified/libbxroot-runtime.so；两者各有BUILD-METADATA，互不覆盖。默认版是明确的能力退化而非完整SHM恢复。

## 历史验证与仍适用的边界

当前实现使用持久 `.claim-lock` inode 和独立 open-file-description 的非等待 `F_OFD_SETLK`，所有 bxroot keyed shmget、stale 清理与完整 RMID 共同持有这一个锁。锁文件在运行期间不 unlink。锁失败立即返回；竞争返回 EAGAIN，信号处理器不等待。锁 fd 关闭或最后持有它的进程退出会释放锁。fork 继承同一 OFD 时，父 close 不会释放仍被子持有的锁，这属于明确的生命周期边界。

`test/RUN_SHM_CLAIM.sh` 直接包含当前 runtime 源码，实测：默认 gate 关闭、创建/复用、第二 creator 和 RMID 非等待竞争、busy 时段保留、SIGKILL owner 自动释放、重试创建、publish 错误释放、非 regular 段保留 key、RMID 删除错误传播与锁释放。测试只清理自己创建的 fixture。原 `.claim-key-*` 文件不再参与协议，不需要删除外部未知文件。

`test/RUN_RUNTIME_STAT.sh` 调用真实 shm_do_ctl，两个 copyout gate 各覆盖8种地址情况。`test/RUN_STATIC_SHM_FD.sh` 同时包含真实 static_exec 与 sysvshm，实际执行 sx_reset_process_state：有效 anchor 保留，普通 CLOEXEC 关闭，真 exec 关闭，关闭后同号复用被实际 getter 拒绝并关闭。两者已实跑通过。

构建开关：

```sh
BXROOT_BUILD_PROFILE=verified BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 sh BUILD_RUNTIME.sh -O1
```

仅在目标完整过滤链已验证的部署中使用。默认两个 gate 均为0，因此默认构建不是功能恢复版：IPC_STAT 与 keyed mutator/RMID 会明确 ENOSYS，不能将禁用称为兼容性修复。

原生 bridge/linker 副本的真实加载链已实测 raw 271 的地址矩阵、raw fcntl25 OFD冲突与close释放、自动fork登记与wait回收。启用版真实库的 emulation 后端创建、IPC_STAT(size4096)、RMID成功。但外层当前 PRoot仍把原生SysV IPC syscall返回ENOSYS，不能称SIGSYS入口端到端通过。共存APK run-as被设备策略POLICY_BLOCKED，读屏SCREEN_TARGET_UNAVAILABLE；没有绕过策略。

官方proroot不使用 `.claim-lock`，官方与bxroot混合并发没有协调保证。固定目录fd不是安全沙箱，同进程并发close/reuse仍有边界。当前布局维持官方文件式RMID与进程本地nattch，不声称实现Linux全局nattch/延迟删除账本，也不声称glibc与bionic跨ABI结构转换。

完整快速矩阵证据：`/root/work/bxroot-regression-results/quick-VNJbP0/results.txt`，40 PASS、3 FAIL、14 SKIP、23 BLOCKED、0基础设施ERROR。其中最后错误路径修复之后额外重跑claim与22单元告警门禁成功。三个失败为当前外层PRoot环境中的l2s两项与statx NULL errno差异，未隐藏为通过；BLOCKED涉及未建立真实隔离的测试。运行器保留每一步日志并在基础设施失效时停止。


最终复测追加：22 个编译单元零告警；`RUN_RUNTIME_STAT.sh` 两 gate 通过；`RUN_STATIC_SHM_FD.sh` 通过；`RUN_SHM_CLAIM.sh` 默认关闭/启用及强杀恢复通过；`RUN_NATIVE_FORK_WAIT.sh --compile-only` 通过。未提供加载器参数时 native chain 明确 rc2；指定独立 bridge/linker 副本后 `NATIVE_CHAIN_FORK_WAIT_PASS`。
