# 非默认 rootfs 下 `exec` → `cat` 偶发 `munmap_chunk`（已重测：不复现）+ 顺带修掉的真缺陷

> **状态（2026-09-26 复查）：**
> 1. 文档原记录的 `munmap_chunk(): invalid pointer`（rc=134）在**当前代码
>    上用真 glibc 2.41 rootfs 重测 0/60，无法复现**；老 runtime（079e607，
>    即原记录时的代码）同样 0/40。原环境（`/root/bxtest-pd/rootfs`）已不存在，
>    无法回溯到底是什么条件触发的 —— 如实记录为"不复现"，不宣称"已修复"。
> 2. 复查过程中在**同一 rootfs** 上发现并修复了一个 **100% 复现**的真缺陷：
>    glibc 2.41 下任何经 bxroot exec 钩子重入的进程，其 `fork()`/`_Fork()`
>    子进程、`pthread_create`、`posix_spawn(RESETIDS)` 全部死于 SIGSYS(159)
>    —— 表现为 `sh -c '/bin/sh -c "/bin/true"'` rc=159。修复见 92d7355，
>    回归 `test/RUN_ALT_ROOTFS.sh`（已接入 RUN_ALL）。

## 一、原现象与范围（2026-09-21 记录，保留原文）

```sh
$ bxroot-run --rootfs /root/bxtest-pd/rootfs -- /bin/sh -c '/bin/cat /etc/hostname'
runnervmbvass
munmap_chunk(): invalid pointer
Aborted                      # rc=134
```

| 组合 | 失败率 |
|---|---|
| 默认 rootfs（Ubuntu 24.04 / glibc 2.39） | **0/15** |
| 默认 rootfs + `exec` → `cat` | **0/15** |
| Debian 13 rootfs（glibc 2.41）+ **直接** `cat` | **0/15** |
| Debian 13 rootfs + `sh -c '/bin/cat …'` | **6–13/15** |

当时已排除：绝对符号链接展开、mmap/munmap/malloc/free 钩子（不存在）、
fadvise/copy_file_range、FAKEROOT/NO_CRASH/NO_LIVEPATCH/RAW_SYSCALL 开关、
argv/env 被破坏、父进程堆被破坏。对照：官方 runtime 0/10，bxroot 7/10。

## 二、2026-09-26 复查：准备 rootfs 与复现尝试

原 rootfs 不存在，`debootstrap` 在本容器因 `noexec/nodev` 挂载拒绝安装，
Docker Hub/GitHub 直连超时；最终从 `deb.debian.org` 直接拉 trixie 的 arm64
`.deb` 用 `dpkg-deb -x` 拼出最小 rootfs：

```
/root/rootfs-trixie      libc6 2.41-12+deb13u4、coreutils 9.7、dash、bash、
                         libc-bin、locales-all、libselinux1/pcre2/acl/attr/gmp/crypt/gcc-s1
                         ln -s dash /usr/bin/sh；echo trixiehost > /etc/hostname
/root/rootfs-copy        cp -a 当前容器 /usr /etc（同 glibc 2.39 的"另一棵树"）
```

复现统计（`bxroot-run --rootfs /root/rootfs-trixie -- /bin/sh -c '/bin/cat /etc/hostname'`）：

| 条件 | 结果 |
|---|---|
| 当前 runtime，默认条件 | **0/60** |
| 老 runtime（079e607，原记录时的代码） | **0/40** |
| 同 glibc 的另一 rootfs（/root/rootfs-copy） | 0/15 |
| 与原路径相同（cp 到 /root/bxtest-pd/rootfs） | 0/15 |
| `exec cat` / 两个 cat / `echo \| cat` / 大文件 cat / PATH 查找 cat | 各 0/10 |
| 60 KB 单变量 / 300 个环境变量 | 各 0/10 |
| rootfs 路径 232 字节深目录 | 0/12 |
| `LANG=C.UTF-8` / `en_US.UTF-8` / `zh_CN.UTF-8`（装了 locales-all） | 各 0/10 |
| `MALLOC_CHECK_=3` / `GLIBC_TUNABLES=…check=3:perturb=…:tcache_count=0` / `mmap_threshold=4096` | 各 0/10 |
| stdout 接管道 / `>/dev/null` / 输出到 stderr / stdin 重定向 / 伪终端（script） | 各 0/15 |
| 16 路并发 | 0/16 |
| 生成 `/etc/ld.so.cache`、去掉 `LD_LIBRARY_PATH`、`env -i` 干净环境 | 各 0/15 |
| bash 代替 dash 做中间层 | 0/15 |

**结论：无法复现。** 差异候选只剩"原 rootfs 的具体内容"（原记录的 cat/
libc 小版本、是否装了别的 preload/NSS 模块等），已无法获取。不编造根因。

## 三、复查中发现的真缺陷：glibc 2.41 下 fork 子进程死于 SIGSYS

### 现象

```sh
$ bxroot-run --rootfs /root/rootfs-trixie -- /bin/sh -c '/bin/sh -c "/bin/true"'
Bad system call              # rc=159，100%
$ bxroot-run --rootfs /root/rootfs-trixie -- /bin/sh -c '/bin/sh -c "( exit 0 )"'   # 159
$ bxroot-run --rootfs /root/rootfs-trixie -- /bin/sh -c '/bin/sh -c "exit 0"'       # 0（不 fork 就没事）
```

官方 runtime 同链路 3/3 rc=0。外层日志：`SIGSYS trapped syscall=439`
是**子进程死后**父 shell 报的，不是死因。

### 为什么一层 sh 没事、两层才死

`bxroot-run` 直接启动的首进程由外层 proroot linker 加载的是**容器自己的**
glibc 2.39（`/proc/self/maps` 里 libc 路径在 `ubuntu/usr/lib`），只有经
bxroot exec 钩子重入 trampoline 的进程才真正加载 `--rootfs` 里的 2.41。
所以"直接跑正常、经 shell 转一手就不同"这个分界，本质是 **glibc 版本分界**。
（这也解释了原文档第一节里那条"关键分界"。）

### 二分证据（探针放进 rootfs 的 /tmp，`sh -c 'exec /tmp/probe'` 保证跑在 2.41 上）

| 探针 | 结果 |
|---|---|
| 裸 `clone(SIGCHLD)` 子进程 | 正常 |
| glibc `_Fork()` 子进程 | **sig=31** |
| glibc `fork()` 子进程 | **sig=31** |
| `pthread_create` | 创建返回 0，随后进程 Bad system call |
| `posix_spawn(POSIX_SPAWN_RESETIDS)` | 子进程 sig=31 |
| 子进程：裸 `rt_sigprocmask(BLOCK, all)` 后内联 `svc 99` | **sig=31**（官方 runtime 下同样死 —— 这是内核语义） |
| 子进程：只裸屏蔽、不发 99 | 正常 |
| 主线程（未屏蔽）内联 `svc 99` | -38 ENOSYS，由 SIGSYS 处理器兜住 |

`objdump -d` 对比 `_Fork`：

```
2.39 _Fork:  svc clone3 → 子进程直接 svc set_robust_list(99)
2.41 _Fork:  bl __abort_lock_rdlock（内部 rt_sigprocmask 屏蔽全部信号）
             → svc clone3 → 子进程 svc set_robust_list(99) → bl 解锁
```

宿主 seccomp 对 99 是 TRAP；**SIGSYS 被屏蔽时内核不投递信号而直接杀进程**。
2.41 的 `_Fork` 恰好把 99 放在全屏蔽窗口里，所以子进程必死。2.39 没有那段
屏蔽，同一个站点漏补只表现为"多进一次 SIGSYS 处理器"，看不出来。

而 bxroot 的 livepatch（把 glibc 内联 `svc` 改成 `mov x0,#0`）此前只有
**2.39 的站点表**，版本不符就整体跳过（只打一行 WARN），于是 2.41 上
**一条都没补**。官方 runtime 在 2.41 活体 libc 上补了 `0x85f6c`（pthread
路径 99）、`0x86224`（rseq 293）、`0xbfc08`（`_Fork` 里的 99）—— 活体内存
dump 与磁盘文件逐字比对确认。

第二个连带缺陷：`px_heal_thread_list` 用 2.39 的 `pd = TCB-0x740` 去修
2.41（`pd = TCB-0x720`，`__libc_fork` 反汇编 `sub x22, x26, #0x720` /
`ldp x4,x3,[x1,#-96]`），自环写到别的字段，真正的 list 仍 NULL。

### 修复（92d7355）

- `src/runtime/livepatch.c`：站点表按 `gnu_get_libc_version()` 精确选表
  （2.39 / 2.41），两版都补上 `_Fork` 里的 99 站点；无表版本仍跳过 + 告警。
  打补丁前仍逐字节校验 `svc #0`。
- `src/proc/proc.c`：`px_heal_thread_list` 的 TCB→pd 偏移按版本选
  （0x740 / 0x720），未登记版本不动。

修后（2.41 rootfs）：两层 sh rc=0；`_Fork`/`fork`/`pthread_create`/
`posix_spawn(RESETIDS)` 全部成功；`BXROOT_VERBOSE=1` 可见
`livepatch: 已中和 5 个站点`。

### 回归：`test/RUN_ALT_ROOTFS.sh`（已接入 RUN_ALL）

- A) 同 glibc 的另一 rootfs（`cp -al` 现做硬链接镜像，本环境总能跑）：
  `sh -c cat` ×N 全 rc=0、输出必须等于**那棵树**的 `/etc/hostname`、两层 sh 链。
- B) 异 glibc rootfs（默认探测 `/root/rootfs-trixie`，或 `BXROOT_ALT_ROOTFS=`）：
  同上 + 派生族探针 `test/altrootfs/probe_fork_family.c`（exec 重入后跑）。
  没有时明确打印跳过原因（不静默）。
- 判别力：换回修前 runtime（57e312d）跑 → `两层 sh -c 链 rc=159` 与
  `派生族探针 rc=159（_Fork/fork child killed by signal 31）` 两项变红；
  当前 runtime 全绿。

## 四、后继者须知

- 站点表是**版本精确绑定**的：再接一个 glibc（2.40 / 2.42 …）要用
  `objdump -d libc.so.6` 找 `mov x8,#0x63/#0x125/#0x93/#0x95` 后 1–3 条内的
  `svc #0`，共 5 个站点（pthread 99、rseq 293、`_Fork` 99、`__spawni`
  147/149），并核对 `pthread_self` 里的 `sub x0, x0, #0x…` 得 TCB→pd 偏移。
- 原 `munmap_chunk` 现象若再出现，先确认 libc 版本是否在站点表里
  （`BXROOT_VERBOSE=1` 看是"已中和 N 个站点"还是"偏移不可信 → 已跳过"），
  再按第二节的表逐项复测；本轮所有变量都试过，别重复。
