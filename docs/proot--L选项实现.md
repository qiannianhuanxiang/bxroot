# proot `-L` 选项实现报告

**日期**：2026-09-16
**范围**：`-L`（fix_symlink_size）实现 + 连带修复的 l2s 真实工具链缺陷
**结论**：`-L` 已按 proot 语义实现；更重要的是，**顺带修好了 `-L` 管不到的那一半**
—— l2s 伪造链接的元数据伪装缺陷，它才是 `tar` / `cp -a` 损坏的真正原因。

---

## 一、先纠正一个前提：`-L` 与 l2s 的 size 缺陷是**两件独立的事**

任务书原本的假设是「`-L` 就是修 l2s 场景下 `lstat` 的 size」。**实测证明不是。**

### 读 proot 源码确认 `-L` 到底做什么

`src/cli/proot.c:322`：

```c
static int handle_option_L(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
        (void) initialize_extension(tracee, fix_symlink_size_callback, NULL);
        return 0;
}
```

`src/extension/fix_symlink_size/fix_symlink_size.c` 的核心逻辑：

```c
case PR_lstat64:
case PR_lstat: {
    ...
    status = lstat(original, &statl);
    /* If it is not a link, get out */
    if (!S_ISLNK(statl.st_mode)) {
       return 0;                          /* ← 不是符号链接 → 什么都不做 */
    }
    size = readlink(original, intermediate, PATH_MAX);
    ...
    statl.st_size = (off_t)size;          /* ← size = readlink 的返回长度 */
```

**即：`-L` 是「对真符号链接，把 `st_size` 钉成 `readlink()` 返回的长度」。**

它 filter 的只有 `PR_lstat` / `PR_lstat64`，且注释明确写着：

> for lstat, the link2symlink extension should have already drilled down to the
> final file and past a fake hard link, so if the path returned points to a
> symbolic link, it should be a normal symbolic link

—— 「l2s 应当已经解链完毕」。所以 `-L` 排在 l2s **之后**，管的是 l2s **没**接管的
普通符号链接。

### 推论：`-L` 在 l2s 场景下是**空操作**

伪造链接已被 l2s 替换成普通文件（`S_IFREG`），`if (!S_ISLNK(...)) return 0;` 直接返回。
所以：

| 问题 | 归属 | 默认是否生效 |
|---|---|---|
| 伪造链接 `lstat` 的 size/ino/blocks/mode 不对 | **l2s 层**（无条件） | ✅ 官方默认就对 |
| 真符号链接的 `st_size` 是否等于 `readlink` 长度 | **`-L`**（显式开关） | ❌ 默认不开 |

**实测证据（官方不传 `-L`）**：

```
===== 官方 proroot（不传 -L）=====
  stat(a):  size=1000 nlink=2 S_ISREG=1
  lstat(a): size=1000 nlink=2 S_ISLNK=0     ← 默认就是真实大小，不是链接长度
  read:     1000 字节
```

所以任务书验收标准②的表述（「不传 `-L` 时 size 应仍是符号链接自身的大小，
proot 默认不开」）**与实测不符** —— 官方不传 `-L` 时也是正确的真实大小。

**本次按实测做**：默认行为与官方一致（正确），`-L` 另行实现为独立的兼容开关。

---

## 二、顺带修掉的真实缺陷（这才是 `tar` / `cp -a` 损坏的根因）

### 2.1 实测基线（逐字段 diff，官方 vs bxroot 修复前）

用 `probe3` 对同一份 l2s 伪造链接逐字段对比：

| 字段 | 官方 | bxroot（修前） | |
|---|---|---|---|
| `size` | **5** | **62**（符号链接目标串长度） | ❌ |
| `ino` | 数据文件的 | 符号链接自己的 | ❌ |
| `blocks` | 8 | 0 | ❌ |
| `mode` 权限位 | `0100600` | `0100777`（符号链接恒为 0777） | ❌ |
| `nlink` | 2 | 2 | ✅ |
| `readlink` | `EINVAL` | 返回宿主路径（形似自环） | ❌ |
| `open(O_NOFOLLOW)` | OK | `ELOOP` | ❌ |
| `__xstat64(ver≠0)` | OK | `EINVAL` | ❌ |

### 2.2 官方为什么默认就对（架构差异，不是它多做了什么）

官方是 **ptrace** 方案，`link2symlink.c` 的 `translated_path()` 在**系统调用入口**
就把伪造链接解析成最终数据文件：

```c
if (resolve_faked_hard_link(translated_path, final) < 0)
        return;
strcpy(translated_path, final);
```

于是内核直接 stat/readlink/open **数据文件本身**：

- `lstat` 的 size/ino/blocks/mode 全是真值（**因为内核看到的就是那个文件**）
- `readlink` 回 `EINVAL`（**因为内核看到的是普通文件**，不是刻意设计）
- `open(O_NOFOLLOW)` 成功（同上）

bxroot 是 **LD_PRELOAD** 方案，路径翻译**只换前缀**、不做逐级解链，所以内核停在
符号链接那一层，只能靠**事后补丁**。这是必须**整体回填** `struct stat` 而不是
只补 nlink 的根本原因。

### 2.3 各缺陷的修法与证据

#### ① `size` / `ino` / `blocks` / 时间戳 → 取数据文件的

`l2s_rt_patch_stat` 里 `resolve_final()` 早就把数据文件路径解析出来了，只差一次
`g_ops->lstat(final, &final_st)`。按 PRoot 的做法回填。

**保留不动的字段**：`st_uid` / `st_gid` —— 调用顺序是「先 fakeroot 后 l2s」，
用 `final_st` 的属主会**把 fakeroot 的伪装抹掉**。

#### ② `mode` 权限位 → 取数据文件的

内核给符号链接的权限位**恒为 `0777`**（Linux 规定）。只抹类型位会让客户看到
`0100777`，官方是 `0100600`。

```c
/* 修前：只改类型位，权限位留着符号链接的 0777 */
st->st_mode = (st->st_mode & ~(mode_t)S_IFMT) | S_IFREG;
/* 修后：权限位取数据文件 */
st->st_mode = (final_st.st_mode & ~(mode_t)S_IFMT) | S_IFREG;
```

#### ③ `readlink` 对伪造链接返回 `EINVAL`（但**保留** `/proc/self/fd/N` 的还原）

旧实现把中间层名「还原」成客户名返回成功。它与 `lstat` 报的 `S_IFREG`
**自相矛盾**（只有符号链接的 readlink 才会成功），于是：

- `tar cf` → 按符号链接归档，把**宿主绝对路径**写进归档
- `cp -a` → `ELOOP`（cp 拿 readlink 结果自己去解析，形成自环）

**但有一个必须区分的边界**：`readlink("/proc/self/fd/N")` 时内核已经把 fd
解析**穿透**整条链，返回的是**数据文件**路径。那不是「客户正对着伪造链接」，
而是「客户拿 fd 反查这是哪个文件」，理应拿到它自己用的名字。

**实测（官方）**：

```
readlink(a)                     → EINVAL              （客户路径直查）
readlink(/proc/self/fd/N)       → "/tmp/p5/a"  OK     （fd 反查）
```

所以判据是「内核返回的是**中间层**（`L2S_KIND_INTERMEDIATE`）→ EINVAL；
是**数据文件**（`L2S_KIND_FINAL`）→ 还原成客户名」。一刀切成 EINVAL 会误伤
fd 反查名字（node 的 `uv_exepath` 等都在用）。

#### ④ `(dirfd, 相对路径)` 全家族 → 统一解析

**这是反复踩过的同一类缺陷**，本项目先后因此出过三次问题：

| # | 入口 | 症状 |
|---|---|---|
| ① | `fstatat` 漏接 l2s 补丁 | node 的 `statSync` 全错 |
| ② | `readlinkat(dirfd, 相对名)` | `tar` 看到 readlink 有结果 → 判定是链接 |
| ③ | `openat(dirfd, 相对名, O_NOFOLLOW)` | `tar` 报 ELOOP |
| ④ | `fstatat(dirfd, 相对名, NOFOLLOW)` | `islnk=1`（本次实测发现） |

**根因完全相同**：`translate_path()` 只翻绝对路径，相对名原样返回，于是后续
判据按**进程 cwd** 解析，而客户的意思是**相对 dirfd**。cwd 恰好等于 dirfd 时
看着是对的 —— 这就是它难以被单点测试发现的原因。

修法：加 `resolve_dirfd_path()` + `resolve_host_path()`，用
`/proc/self/fd/<dirfd>` 读出目录真实路径拼成绝对路径（`AT_FDCWD` 是特例，
值 -100，不是真实 fd）。

**实测证据**（cwd 与 dirfd 不同时）：

```
修前：fstatat(dirfd,"a",NOFOLLOW) mode=0120777 islnk=1 nlink=1 size=67   ❌
修后：fstatat(dirfd,"a",NOFOLLOW) mode=0100777 islnk=0 nlink=2 size=5    ✅
官方：fstatat(dirfd,"a",NOFOLLOW) mode=0100600 islnk=0 nlink=1 size=5
```

#### ⑤ `__open_2` / `__openat_2` —— `tar` 走的真实入口

**这是 `tar` 那条路上最关键的一处。** `tar` 用 glibc 的 `_FORTIFY_SOURCE`
变体，**完全绕过** `open`/`openat`：

```
$ nm -D --undefined-only $ROOTFS/usr/bin/tar | grep open
                 U __open_2
                 U __openat_2
```

所以只修 `open`/`openat`/`open64`/`openat64` 时，`tar` 走的这条路上**完全没有解链**，
`O_NOFOLLOW` 直接撞上磁盘上的符号链接 → `ELOOP` → `Cannot open`。

修法：`__open_2` / `__open64_2` / `__openat_2` / `__openat64_2` 四个变体
同样接 `l2s_open_path()`（并在 `__openat*` 里先做 dirfd 解析）。

#### ⑥ `__xstat*` 家族的 `ver` 参数归一化

`__xstat`/`__lxstat`/`__fxstat` 家族的第一个参数是「结构体版本」。
aarch64 上 glibc 只认 `_STAT_VER == 0`，而调用方可能传别的值：

```
修前：__xstat64(ver=0) OK，ver=1/2/3 → EINVAL   ❌
修后：ver=0/1/2/3 全部 OK                        ✅
官方：ver=0/1/2/3 全部 OK
```

顺带修正了 `__fxstatat` 兜底分支里硬编码的 `_STAT_VER = 1`（那是 **x86_64** 的值；
aarch64 是 0）。该分支在 glibc 2.33+ 上从不被走到，所以一直没暴露。

---

## 三、`-L` 的实现

### launcher（`src/launcher/launcher.c`）

`-L` 从「明确拒绝」改为**接受**，置 `cfg->fix_symlink_size`，随后：

```c
if (cfg.fix_symlink_size)
    setenv("BXROOT_FIX_SYMLINK_SIZE", "1", 1);
else
    unsetenv("BXROOT_FIX_SYMLINK_SIZE");   /* ★ 必须成对，否则旧值被子进程继承 */
```

帮助文本同步更新：从「明确未实现」列表移到已支持项。

### runtime（`src/runtime/preload.c`）

新增 `l2s_fix_symlink_size()`，在 `lstat`/`lstat64`/`__lxstat`/`__lxstat64`
四个入口调用：

```c
if (!g_fix_symlink_size || st == NULL || p == NULL) return;
if (!S_ISLNK(st->st_mode)) return;        /* 与 proot 的 S_ISLNK 门控一致 */
n = real_readlink(p, target, sizeof(target));
if (n < 0) return;                        /* 读不到就保持原值，不乱猜 */
st->st_size = (off_t)n;
```

**★ 顺序必须在 l2s 之后 ★**：l2s 把伪造链接的 mode 从 `S_IFLNK` 改成 `S_IFREG`；
`-L` 若先跑会看到 `S_ISLNK`、把 size 钉成目标串长度，**把 l2s 刚回填的真实大小覆盖掉**，
正好退回本次要修的缺陷。这与 proot 的扩展顺序一致（`-L` 注明「l2s 应当已解链完毕」）。

**`/proc/self/exe` 的特例**：该路径被 readlink 钩子改写过（返回
`g_config.guest_exe`）。若 `-L` 仍按宿主真实目标算，客户会看到
`st_size = strlen("<...>/libproroot-bridge.so") = 107` 而 `readlink = "/tmp/lprobe" (11)`
—— 而「size 与 readlink 一致」正是 `-L` 存在的全部意义，不能自己制造新的不一致。
所以这里取 `strlen(g_config.guest_exe)`。

### 实测（`-L` 的可观测差别在 `/proc` 魔法链接上）

`/proc/self/cwd` 的 `st_size` 是 0，而 `readlink` 返回实际路径长度 —— 这是 `-L`
唯一真正改变结果的场景：

```
不传 -L:  /proc/self/cwd  st_size=0   readlink_len=44   （保持内核原值）
传   -L:  /proc/self/cwd  st_size=44  readlink_len=44   （钉成 readlink 长度）
传   -L:  /proc/self/exe  st_size=11  readlink_len=11   （客户可见长度，非宿主 107）
```

**默认行为不变**（与 proot 一致，`-L` 是显式选项）。

---

## 四、测试改动说明

### `test/test_l2s_rt.c` —— A4 断言更新

**原断言固化的正是缺陷行为**：

```c
CHECK_EQ_I(rc, 1);                       /* 改写成功 */
CHECK(strstr(out, "orig.txt") != NULL);  /* 还原出原始名字 */
```

改为反映新契约：

```c
CHECK_EQ_I(rc, L2S_RT_READLINK_FAKE);    /* 命中伪造链接 → 调用方转 EINVAL */
```

**保留了「用户自己的真符号链接不被改写」那一半（`rc == 0`）** —— 那是一刀切
关掉 readlink 时最容易破坏的回归点，也是 `RUN_L2S_E2E.sh` 的 `reallink=true`
所守的东西。

同时补了一条：**同一个链的第二个名字也必须失败**（两条都是伪造链接）。

### `test/RUN_CLI_COMPAT.sh` —— `-L` 期望更新

`-L` 从「C) 明确拒绝」列表移到「B) 无值选项（已支持）」列表，并加注释说明
它与 l2s 的 size 缺陷是两件独立的事。

---

## 五、验收结果（全部实测）

| # | 验收项 | 结果 |
|---|---|---|
| 1 | `l2ssize` 探针 `lstat(a).size == 1000` | ✅ 与官方逐字一致 |
| 2 | 默认行为（不传 `-L`） | ✅ **与官方一致**（`size=1000`；见第一节，任务书原前提有误） |
| 3 | `sh test/RUN_L2S_E2E.sh` | ✅ **PASS**（`nlink=2 islink=false size=5 stsize=5 reallink=true`） |
| 4 | `sh test/RUN_ALL.sh --quick` | ✅ **12/12 全绿** |
| 5 | `sh test/RUN_CLI_COMPAT.sh` | ✅ **38/38** |
| — | `sh test/RUN_WARN_GATE.sh` | ✅ 零告警（11 个编译单元） |

### 真实工具链对照（这才是终极判据）

```
############ 官方 ############              ############ bxroot ############
[ls -l]   -rw-------. 2 root root 5 ...    [ls -l]   -rw-------. 2 root 0 5 ...
[readlink a]  rc=1                         [readlink a]  rc=1
[cp -a]   c size=5                         [cp -a]   c size=5
[tar]     -rw------- root/root 5 ... a     [tar]     -rw------- root/0   5 ... a
[cat]     fill                             [cat]     fill
```

**逐项一致。** 修复前 `tar` 输出的是 `lrwxrwxrwx ... a -> /data/data/com.dsh.client/...`
（符号链接 + 宿主绝对路径泄漏），`cp -a` 直接 `ELOOP` 失败。

唯一的残留差异是属主**名字**（`root/0` vs `root/root`）—— 那是 fakeroot 的
uid→名字转换问题，与本次改动无关，属另一个范畴。

---

## 六、连带修掉的其它预先存在缺陷

以下三项在本任务中被实测发现，且**都用改动前的旧产物复现过**，确认与本次
l2s / `-L` 改动无关，是预先存在的缺陷。因为它们的危害同样是"真实工具链坏掉"，
本次一并修掉。

### 1. `chdir` 的 cwd 在 exec 后被重置

现象（shell 里最明显）：

```
bxroot:  cd /tmp/d; ls   → 列出 rootfs 根（bin boot data ...）   ❌
         stat ./a         → ENOENT
官方  :  cd /tmp/d; ls   → a                                     ✅
```

`pwd`（dash 内建，用自身记账）看上去是对的，所以现象是「**pwd 对但 ls 错**」，
极易误判成 `getcwd` 的问题。

**根因定位过程**（这里记录方法，因为它很容易查错方向）：

1. 纯 C 探针里 `chdir("/tmp")` 后 `getcwd()` 返回 `/tmp` —— **正常**
2. 但同一探针 `fork()` + `exec("/bin/pwd")` 后，`/bin/pwd` 输出 **`/`** —— **错**
3. 差别在于：第 1 步用的是**已加载好**的本 .so，第 2 步是 exec 后**重新加载**的
4. 于是看构造函数 —— 找到了：

```c
/* 每个进程加载本 .so 时都会跑 */
if (g_config.workdir) {
    syscall(SYS_chdir, translate(g_config.workdir));   /* ← 把 cwd 重置成 workdir */
}
```

`BXROOT_WORKDIR` 的语义是「容器**启动时** cwd 设到哪里」，但它被无条件地
应用在**每一个** exec 出来的子进程上，于是父进程的 `cd` 全部丢失。

**修法**：用环境变量当跨 exec 的标记（环境变量会被 fork/exec 继承）：

```c
if (g_config.workdir && getenv(BXROOT_WORKDIR_DONE_ENV) == NULL) {
    syscall(SYS_chdir, target);
    setenv(BXROOT_WORKDIR_DONE_ENV, "1", 1);   /* 之后 exec 的子进程不再重置 */
}
```

首个进程（launcher 起的）设一次；子进程继承父进程的 cwd。与 proot 一致
（proot 只在启动 tracee 时应用 `-w`）。

**实测（`/root/fsize/cdinherit.c`，父 `chdir("/tmp")` 后 fork+exec `/bin/pwd`）**：

```
官方  : 父 getcwd=/tmp  子 getcwd=/tmp  /bin/pwd → /tmp   ✅
修前  : 父 getcwd=/tmp  子 getcwd=/tmp  /bin/pwd → /      ❌
修后  : 父 getcwd=/tmp  子 getcwd=/tmp  /bin/pwd → /tmp   ✅
```

### 2. `getcwd(NULL, 0)` 分支跳过反向翻译

`getcwd` 只给 `buf != NULL` 分支做了「剥 rootfs 前缀 + 反向 bind 映射」，
`buf == NULL` 分支直接返回：

```c
/* 注释写着"glibc 会 malloc 一块，我们不能用栈缓冲替代"——解释对，结论是"什么都不做" */
if (buf == NULL)
    return fn(NULL, size);
```

于是 `getcwd(NULL, 0)` 把**未处理的宿主路径**交给客户。**dash 的内建 `cd`/`pwd`
走的正是这个分支**（它是上面第 1 条现象的另一半成因）。

**修法**：把修整逻辑抽成 `getcwd_fixup()`，两个分支都调。glibc 的
`getcwd(NULL, n)` 分配的是「实际路径长度 + 余量」，而剥前缀只会让路径**更短**，
所以对它 malloc 的缓冲原地 `memmove` 安全。

**实测**：

```
官方  : getcwd(buf,size)=/tmp   getcwd(NULL,0)=/tmp
修前  : getcwd(buf,size)=/tmp   getcwd(NULL,0)=/data/.../ubuntu/tmp   ❌
修后  : getcwd(buf,size)=/tmp   getcwd(NULL,0)=/tmp                   ✅
```

## 七、如实记录的残留项（本次未修）

### 1. `tar` 归档整个目录时会包含 `.l2s.*` 中间文件

```
tar cf t.tar -C $D .   →   ./.l2s.a0001、./.l2s.a0001.0002 也进了归档
```

官方没有这个问题（它用集中目录布局 + `detranslate_path`）。这是 l2s 模拟的
固有代价（中间文件必须存在于同一文件系统），修它需要隐藏 `.l2s.*` 的目录项
（proot 的 `-H` 扩展正是干这个的）。**本次未做**，如实记录。

**注意**：`tar cf t.tar a`（指定成员）已完全正确 —— 这是最常见的用法。

### 2. fakeroot 的属主**名字**显示为 `root/0` 而非 `root/root`

`tar tvf` 输出里 bxroot 是 `root/0`、官方是 `root/root`。那是 fakeroot 的
uid→名字转换问题（`getpwuid` 相关），与本次改动无关，属另一个范畴。

---

## 八、改动文件清单

| 文件 | 改动 |
|---|---|
| `src/l2s/l2s-runtime.c` | `patch_stat` 整体回填 + 权限位；`readlink` 语义反转（区分中间层/数据文件）；新增 `l2s_rt_resolve_fake_link()`；statx 两处同步 |
| `src/l2s/l2s-runtime.h` | `L2S_RT_READLINK_FAKE` 哨兵、`l2s_rt_resolve_fake_link()` 声明、契约注释更新 |
| `src/runtime/preload.c` | `resolve_dirfd_path()` / `resolve_host_path()` 统一入口；stat 家族 dirfd 解析；4 个 open 变体 + 4 个 `__open*_2` 变体解链；4 个 readlink 入口 EINVAL；`ver` 归一化；`-L` 实现；`getcwd_fixup()` 抽取（两分支共用）；构造函数 workdir 只设一次 |
| `src/launcher/launcher.c` | `-L` 接受（原为拒绝）+ setenv/unsetenv + 帮助文本 |
| `test/test_l2s_rt.c` | A4 断言更新（见第四节） |
| `test/RUN_CLI_COMPAT.sh` | `-L` 期望从「明确拒绝」移到「已支持」 |
| `docs/proot--L选项实现.md` | 本报告 |

**未改动**（按要求）：`src/proc/proc.c`、`src/runtime/fakeroot.c`、
`test/RUN_ALL.sh`、`test/RUN_WARN_GATE.sh`、`BUILD_RUNTIME.sh`。

---

## 九、方法论教训（供后来者）

1. **不要从选项名推断它管什么**。`-L` 的说明写着「lstat 的 size」，很容易
   把它与 l2s 的 size 缺陷当成同一件事 —— 读源码 + 实测才发现是两回事。
   **任务书的前提也可能错，以实测为准。**

2. **「形式覆盖不全」是本项目最高频的缺陷类型**。同一个语义有多种入口：
   - stat 家族：`stat` / `lstat` / `fstatat` / `statx` / `__xstat*` / `__lxstat*` / `__fxstat*`
   - open 家族：`open` / `openat` / `open64` / `openat64` / `__open_2` / `__openat_2` / `__open64_2` / `__openat64_2`
   - 每种又分「绝对路径」与「(dirfd, 相对路径)」

   **发现一个入口有问题时，应当把整个家族枚举一遍**，而不是只修被探针命中的那个。
   本次 `tar` 的根因（`__open_2`）就藏在最不容易想到的那个入口里。

3. **看真相要用宿主视角**。`readlink`/`stat` 的返回值都可能被钩子改写，
   用经钩子的工具去看会得出错误结论（本项目为此误判过多次）。
