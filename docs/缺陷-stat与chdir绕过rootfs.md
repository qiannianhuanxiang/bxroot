# 缺陷：`stat` / `chdir` 家族绕过 rootfs —— 静默的错误元数据与错误工作目录

> **状态：已修复。** 两条都是"**成功返回但答案是外层的**"，比报错危险得多。
> 由**最终验收子代理**用 inode 证据发现，并指出**我上一轮的修法有根本缺陷**。

---

## 一、为什么上一轮"修过了"却还错 —— 一条重要的方法论

上一轮我对 stat 家族做的是**"失败后重试"**：

```c
rc = real_stat(p, buf);
if (rc != 0) { /* 展开绝对链接再试一次 */ }
```

这在**链接失效**（ENOENT）时有救，但在**链接能打开**时**完全无能为力** ——
而后者恰恰是最危险的情形：

```
内核按真实根解析绝对目标 → 命中外层命名空间的同名文件
→ stat **成功**返回，但 st_dev/st_ino/st_size 全是外层的
```

★ **教训**：对"可能返回错误答案"的 API，"失败后重试"是**不够的**
——必须**先探后改**。我把"重试"当成了"修复"，于是得到
"看起来修好了（`cat` 能读对了）、实则核心路径仍错"的假象。

**而发现它的是一个用 `st_ino` 做对照的独立测试者**，不是我自己 ——
我当时的验证只看了"能不能读到内容"（`cat`），没看"元数据对不对"。

## 二、缺陷 1：`stat` 家族返回外层文件的元数据

### 现象（inode 证据）

```c
stat("/tmp/x", &st);      // x -> /etc/passwd
```

| 路径 | dev | ino | size |
|---|---|---|---|
| `stat("/tmp/x")`（经链接） | **65037** | **167512699** | **0** |
| `stat("/etc/passwd")`（直读） | 65086 | 5853922 | 839 |

`dev=65037` 正是**外层 Android** 设备的编号 —— 也就是说这次 `stat`
落到 `/system/etc/passwd` 上去了。

### 危害

| 用途 | 后果 |
|---|---|
| 按 `st_size` 分配缓冲 | 分配 0 字节 → 后续读空 / 越界 |
| 按 `st_ino` 做去重或缓存 | 把两个不同文件当成同一个（或反之） |
| 按 `st_dev` 判断跨设备 | 误判，`cp`/`tar` 走错分支 |
| **全程无错误码** | 调用方**不可能察觉** |

**内容泄漏同时存在**：容器 `/etc/hosts` 是 0 字节，经链接读到 **56 字节**
（外层 `/system/etc/hosts`）。

### 修法：先探后改

`stat` 没有 `flags` 参数，但等价能力是有的 ——
`fstatat(path, buf, AT_SYMLINK_NOFOLLOW)` 就是"看链接本身"：

```c
1. 先用 AT_SYMLINK_NOFOLLOW 取一次（同族调用，代价相当）
2. 若结果是符号链接 → 自己解析到底（绝对目标按 rootfs 翻译）再 stat
3. 否则直接返回第一次结果   ← **普通文件零额外开销**
```

覆盖 `stat` / `stat64` / `newfstatat`。`AT_SYMLINK_NOFOLLOW` 时
辅助函数直接返回 0，**语义不变**（`tar`/`rsync` 判断"是不是链接"仍正确）。

## 三、缺陷 2：`chdir` 绕过 rootfs

```sh
cd /tmp/etc.lnk       # ln -s /etc /tmp/etc.lnk
pwd                   # ← 落到**外层** /system/etc
```

| 对象 | dev | ino |
|---|---|---|
| `chdir("/tmp/etc.lnk")` 后的 cwd | **65037** | **1464**（外层） |
| `chdir("/etc")` 后的 cwd | 65086 | 5853670（容器） |

### 危害

不是"读错一个文件"，而是**整个工作目录被换到容器外** ——
其后所有**相对路径**操作都落在外层。常见触发：
`make -C <符号链接目录>`、构建脚本里 `cd $(dirname …)` 恰好经过链接。

### 修法

与 open/stat 同一套：先 `resolve_symlink_full()` 解析到底，再交给
真实 `chdir`。

## 四、验证

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `stat(link)` vs `stat(/etc/passwd)` | ❌ dev/ino/size 全不同 | ✅ **完全相同**（65086/5853922/839） |
| `chdir(link)` 后 cwd | ❌ dev=65037 ino=1464（外层） | ✅ dev=65086 ino=5853670（容器） |
| `cat link` | 839（上一轮已修） | ✅ 839 |
| `wc -c < link` | 839（上一轮已修） | ✅ 839 |
| `wc -c < link→hosts` | ❌ 56（外层） | ✅ 0（容器） |
| `make -C symlinked-dir` | ❌ 失败/落外层 | ✅ 正常 |
| `test -L link`（NOFOLLOW 语义） | ✅ | ✅ 未破坏 |
| 普通文件 stat | ✅ | ✅ 零额外开销 |

回归：`sh test/RUN_ALL.sh` **24 通过 / 1 失败**，与修复前**逐位一致**
（那 1 项是既有的 `RUN_UPSTREAM_CLI.sh` 加载路径问题）；
告警门禁**零告警**（过程中曾两次被 `-Wdangling-pointer` 拦下 ——
`p` 会指向在块内声明的解析缓冲，见第五节）。

## 五、顺带记录：`-Wdangling-pointer` 抓到的真实缺陷

写这段修复时我把解析缓冲声明在块内：

```c
{ char rs_[MAX_PATH_LEN]; if (…) p = rs_; }   /* ← 块结束 rs_ 就失效 */
rc = real_stat(p, buf);                        /* ← p 已是野指针 */
```

`p` 会一直用到函数末尾（后续 l2s/fakeroot 补丁都按它判断）。
**gcc 的 `-Wdangling-pointer` 直接报了出来**，而本项目的告警门禁是
零容忍 —— 所以它在编译期就被拦下，没有变成"偶发读到垃圾路径"那种
最难查的线上问题。

这与 `px_do_spawn`/`px_do_execve` 里 `sb_argv` 的教训**完全同类**：
**凡是会被指针长期引用的缓冲，都必须放在函数作用域。**


---

## 六、续：**中间组件**的链接（第三轮验收发现，已修）

第五节那个"先探后改"的修法仍然不够 —— 它用 `O_NOFOLLOW` 探
**最后一段**是不是链接，而 `O_NOFOLLOW` **只看最后一个组件**。

### 现象

```sh
mkdir /tmp/repro && ln -s /etc /tmp/repro/e
cat /tmp/repro/e/hosts        # → 56 字节 = ★外层 Android★
cat /etc/hosts                # →  0 字节（容器自己的）
```

链接在**中间**（`e`），最后一段（`hosts`）是真文件 ——
于是 `O_NOFOLLOW` 探测**成功**通过，我们不去解析，
内核随后把 `e -> /etc` 按真实根展开 → 泄漏。

实测证明探测确实漏了：

```
open("/tmp/repro/e/hosts", O_RDONLY|O_NOFOLLOW) = 11   ← 成功，没报 ELOOP
```

### 修法：逐个前缀检查

新增 `resolve_intermediate_symlinks()`：从 rootfs 前缀**之后**开始，
逐段扩展前缀并 `readlink`，碰到链接就地展开（绝对目标按 rootfs 翻译），
最多 8 轮（拦链接环）。

★ **跳过 rootfs 前缀是性能关键** ★ rootfs 路径（如
`/data/data/<pkg>/files/linux/ubuntu`）的每一段都是真实目录，
不可能是链接。若不跳过，一次 `open` 要为它做 ~10 次 `readlink` ——
那会把 bxroot "无额外内核往返"的主张直接推翻。

### 又一个"修了但没生效"

把它接到 `open` 之后，`cat` 已经正确（0 字节），但
`wc -c < link` **仍然读到 56** —— 因为 **dash 的重定向走 `open64`**，
而我只接了 `open`/`openat`/`openat64`。

```
readelf --dyn-syms /bin/dash | grep open
   UND open@GLIBC_2.17
   UND open64@GLIBC_2.17      ← 重定向用这个
```

**同一个缺陷在四个入口上表现不同**，必须逐个覆盖。
这与本轮 `eaccess` 那条是同一个教训：
**判据是"谁消费谁负责"，不能因为一个入口修好了就以为整族都好了。**

### 一处实现陷阱：递归返回值的语义

初版把展开后的路径**递归**回本函数。但递归那层的 `translated` 参数
已是**改写后**的路径，于是它走到末尾的
`strcmp(cur, translated) == 0 → return 0`，把"已改写"误报成
"没变化"，外层因此**丢弃了改写**。

症状极具误导性：`e -> /etc` 明明被识别出来了（调试输出可见），
最终 `open` 用的却仍是原路径。

修法：改成**外层循环**（单遍展开 + 最多 8 轮），
"有没有变化"只跟**最初入参**比较，语义唯一。

### 验证

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `cat /tmp/repro/e/hosts` | ❌ 56（外层） | ✅ 0（容器） |
| `wc -c < /tmp/repro/e/hosts` | ❌ 56（外层） | ✅ 0（容器） |
| 叶子链接 `glk_pw -> /etc/passwd` | ✅ 839 | ✅ 839 |
| `stat` 元数据一致（dev/ino/size） | ✅ | ✅ |
| `chdir` 经目录链接 | ✅ | ✅ |
| 相对目标链接 | ✅ | ✅ |
| `test -L`（NOFOLLOW 语义） | ✅ | ✅ 未破坏 |
| 普通文件 | ✅ | ✅ 零额外开销 |

回归：**24 通过 / 1 失败**，与基线逐位一致；告警门禁零告警。

### 严重性收敛的说明

第三轮验收子代理指出这条"**有界**"：经该链接**写**会撞 erofs 的
`Read-only file system`，所以是**只读的信息泄漏 / 静默错误数据**，
不是写逃逸。但对构建系统而言，"静默读到外层文件"比硬报错更危险 ——
没有任何信号提示读错了。

标准系统链接（`/bin -> usr/bin`、`/lib -> usr/lib`、`/var/run -> ../run`）
都是**相对目标**，所以不受影响 —— 这也是为什么构建本身一直能成功，
只有刻意构造的绝对目标链接才会踩到。

---

## 七、修中间组件时**自己制造**的一个回归（已修，记录在案）

修第六节那个问题时引入了新缺陷，**被 `/root/bxr-v3` 的测试套件逮到** ——
值得单独记，因为它的成因很反直觉。

### 症状

```
guest 内 fork + execv("/bin/echo") → rc=127  EPERM
guest 内 fork + execv("/usr/bin/true") → rc=0  ✅
```

差别只在 `/bin` **是不是符号链接**（`/bin -> usr/bin`，相对目标）。

更要命的是 `/bin/sh` 也在同一路径上 —— 于是
**"fork + execv('/bin/sh', '-c', …)" 全线失败**，
而这正是 `popen`/`system`/测试工具的常用写法。

### 根因：内部判断用了**被自己钩住的** stat

`px_do_execve` 里有一段内部判断，用来决定"要不要走 trampoline"：

```c
if (stat(host, &tst) != 0) { ... definitive_no = 1 ... }
```

`host` 是**已经翻译好的宿主路径**（`<rootfs>/bin/echo`）。
而这次调用走的是 **libc 的 `stat` —— 也就是本进程自己安装的钩子**：

```
钩子里的"中间组件链接解析"把 <rootfs>/bin/echo 里的
`bin -> usr/bin` **又展开了一遍**（那是**宿主视角**的链接）
→ 路径被拼错 → stat 失败 → 误判"不是可执行文件"
→ 跳过 trampoline → 退化成直接 execve
→ SELinux app_data_file 拒绝 → EPERM
```

**关键在于 `bin -> usr/bin` 是相对链接**：它在"容器视角"下是正常的
系统链接，但在"宿主视角"下 `<rootfs>/bin` 也是一个真实的相对链接 ——
两种视角都能解析它，于是**重复解析**就把路径搞坏了。

### 修法：内部判断一律用裸 syscall

```c
long rr = syscall(SYS_newfstatat, AT_FDCWD, host, &raw_st, 0);
```

理由：这里要的是"**磁盘上到底是什么**"，不需要任何客户视角的语义，
更不该让本进程的钩子介入。绕开符号层直接问内核。

### 教训（与第五节同类，但更深一层）

- 第五节：`p` 被块内缓冲悬垂 → `-Wdangling-pointer` 拦下；
- 第七节：**钩子会作用于自己内部的判断** → 用裸 syscall 隔离。

★ 共同点：**翻译层在"处理自己的内部逻辑"时必须显式退出翻译语义。**
`host` 已经是宿主视角了，再翻译一次必然出错。这类"重复翻译"
在本项目里已经出现过多次（`translate_path` 的幂等性保护就是为它加的），
但**幂等保护只覆盖"路径已带前缀"，覆盖不了"路径内的相对链接被再解析"**。

### 验证

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `execv("/bin/echo")` | ❌ rc=127 EPERM | ✅ 正常输出 |
| `execv("/bin/true")` | ❌ rc=127 EPERM | ✅ rc=0 |
| `execv("/bin/sh","-c",…)`（测试工具的写法） | ❌ 失败 | ✅ `SETUP-OK` |
| `execv("/usr/bin/true")` | ✅（非链接） | ✅ 未回归 |
| `/root/bxr-v3` 符号链接测试套件 | ❌ 14/1 | ✅ **15/0** |

回归：`test/RUN_ALL.sh` **24 通过 / 1 失败**，与基线逐位一致。


---

## 八、第二次自我回归：相对目标拼装漏了 `tgt`（最严重的一次，已修）

第七节那个回归修好之后，修"中间组件"时又引入了**更严重**的一个，
由第四轮验收子代理报为 BLOCKED。

### 症状

```
stat("/bin/sh")        → ENOENT     ❌
stat("/usr/bin/sh")    → OK          ✅
[ -e /bin/ls ]         → false       ❌
cat /bin/sh            → 失败        ❌
```

**`/bin`、`/sbin`、`/lib` 下的所有路径全部失效** —— 因为 Ubuntu 的
merged-`/usr` 把它们做成了**相对目标**的目录链接
（`/bin -> usr/bin`、`/sbin -> usr/sbin`、`/lib -> usr/lib`）。

同一进程里 `statx`/`fstatat`/`access` 却正常，只有走
`stat_pre_resolve` 的入口踩到 —— 这种"符号级不一致"极难从现象反推。

### 根因：拼装时只写了父目录，忘了接 `tgt`

```c
/* 相对目标：接在 prefix 的父目录之后 */
char *slash = strrchr(prefix, '/');
size_t dlen = (slash != NULL) ? (size_t)(slash - prefix) : 0;
memcpy(joined, prefix, dlen);      /* ← 只有父目录 */
/* ★ 忘了把 tgt 接上去 ★ */
```

于是 `<rootfs>/bin`（`-> usr/bin`）被算成 `<rootfs>` 而不是
`<rootfs>/usr/bin`，再拼上剩余部分就得到 `<rootfs>/sh`。

**定位方式**（一行调试输出就够）：

```
STATDBG p=<rootfs>/bin/sh rr=1 mid=<rootfs>/sh
                                        ^^^^^ 少了两级
```

`mid` 明显不对 —— 一眼看出 `tgt` 没被拼进去。

### 修法

```c
if (dlen == 0) nj = snprintf(joined, sizeof(joined), "/%s", tgt);
else           nj = snprintf(joined, sizeof(joined), "%.*s/%s",
                             (int)dlen, prefix, tgt);
```

### 验证

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `stat("/bin/sh")` | ❌ ENOENT | ✅ `ino=5853838` |
| `stat("/usr/bin/sh")` | ✅ `ino=5853838` | ✅ 同一 inode |
| `[ -e /bin/ls ]` | ❌ false | ✅ true |
| `cat /bin/sh` | ❌ 失败 | ✅ 成功 |
| `/sbin`、`/lib` 下路径 | ❌ 全部失效 | ✅ 全部正常 |
| 子代理的 `symtest` | ❌ 47 通过 / **10 失败** | ✅ **57 通过 / 0 失败** |
| 子代理全套 | 4 个套件共 10 失败 | ✅ **14+57+14+22 = 107 / 0** |

回归：`test/RUN_ALL.sh` **24 通过 / 1 失败**，与基线逐位一致。

### ★ 这一节最该记住的东西 ★

**本轮我两次修 A 引入 B，两次都是"子代理用真实项目跑出来"才发现的。**

| 次数 | 我引入的缺陷 | 谁发现 |
|---|---|---|
| 第一次 | 内部判断用了被自己钩住的 `stat` → `execv("/bin/sh")` EPERM | 第三轮子代理的 `make test` |
| 第二次 | 相对目标拼装漏 `tgt` → `/bin` 全线失效 | 第四轮子代理报 BLOCKED |

而我自己的验证**两次都没覆盖到** —— 我的测试恰好都用了
`/usr/bin/...` 这类非链接路径，或只跑回归套件（它对 `/bin` 的
覆盖是间接的）。

**结论：改"路径翻译"这种核心逻辑时，自测必须包含
"系统自带的符号链接路径"（`/bin`、`/sbin`、`/lib`），
并且必须拿一个真实项目的构建+测试当验收 —— 不能只看回归套件绿。**

---

## 九、续：`statx` / `realpath` 与"过度重试"（第五轮验收，已修）

第五轮验收子代理报了 4 条缺陷，**同一个根因族**：翻译层漏了几个入口，
外加**我前几轮的"失败后重试"过于激进**。

### 9.1 `statx` 没接（`stat` 修了它没修）

```
stat("/tmp/leafabs")                → ino=5853922 size=839    ✅
statx(AT_FDCWD,"/tmp/leafabs",0,…)  → ino=167512699 size=0    ❌ 外层
statx(AT_FDCWD,"/usr/bin/cc",0,…)   → ENOENT                   ❌
```

`statx` 是 **coreutils ≥9 / rsync / pnpm 的现代主路径**，优先级高于 `stat`
—— 只补 `stat` 等于没补，现代工具会绕过它。修法与 stat 家族同构
（中间组件 + 最后一段，`AT_SYMLINK_NOFOLLOW` 时不动）。

### 9.2 `realpath` 泄漏外层 → 连带 `ln -sfn` 失效

```
realpath("/tmp/rp/E")     # E -> /etc
  宿主 : "/etc"
  bxroot: "/system/etc"        ← ★外层★
```

**危害不止返回值**：`ln -sfn` 用 `realpath` 判断"是否同一个文件"，
拿到 `/system/etc` 后误判，于是**无法替换指向目录的符号链接**：

```
ln -sfn /etc/passwd g/passwd
→ rc=1  "'/etc/passwd' and 'g/passwd/passwd' are the same file"
（宿主 rc=0，正常替换）
```

`canonicalize_file_name` 同样修了。

### 9.3 ★ 最深刻的一条：**"失败后重试"必须区分失败的种类** ★

修完 9.1/9.2 后 `ln` **仍然失败**。真正的原因是**我自己前几轮引入的**：

```c
/* 初版：任何失败都去展开链接再试 */
if (fd >= 0) return fd;
if (resolve_abs_symlink(q, resolved2, ...)) { /* 再开一次 */ }
```

于是：

```
宿主 : open(link-to-dir, O_NOFOLLOW|O_PATH|O_DIRECTORY) = ENOTDIR
bxroot: 同一调用 **成功**（fd=11）        ← 错
```

`ENOTDIR` 是 `ln` 判断"目标是不是目录"的**依据**；
我们把它"修好"成成功，`ln` 就以为目标是目录、把路径拼成
`<dest>/<basename>`，再判定与源同文件 → **拒绝替换**。

修法：**只在 `ENOENT` 时重试**，其余 errno **如实透传**：

```c
if (errno != ENOENT) return -1;   /* 不动调用方对内核答复的理解 */
```

★ **这条教训比缺陷本身重要** ★
展开链接的语义是"**这个路径因为链接指向别处而找不到**"（ENOENT），
不是"这个路径的**用法**不合法"（ENOTDIR / ELOOP / EACCES）。
把后者也一并"修好"，等于**替调用方曲解了内核的答复** ——
而调用方（`ln`、`tar`、`rsync`）恰恰依赖这些 errno 做**语义判断**。

`ELOOP` 尤其要注意：在带 `O_NOFOLLOW` 的调用里它**正是期望的答案**
（"这是个链接"），绝不能被"修好"。

### 9.4 验证

| 检查 | 修复前 | 修复后 | 宿主基线 |
|---|---|---|---|
| `statx(link)` vs `stat(link)` | ❌ 167512699 / 0 | ✅ 5853922 / 839 | 一致 |
| `statx("/usr/bin/cc")` | ❌ ENOENT | ✅ OK | OK |
| `realpath(link→/etc)` | ❌ `/system/etc` | ✅ `/etc` | `/etc` |
| `ln -sfn`（替换指向目录的链接） | ❌ rc=1 | ✅ rc=0，`-> /etc/passwd` | rc=0 |
| `open(link-to-dir, O_NOFOLLOW\|O_PATH\|O_DIRECTORY)` | ❌ **成功** | ✅ `ENOTDIR` | `ENOTDIR` |
| `/bin`、`/sbin`、`/lib` inode 一致 | ✅ | ✅ 未回归 | 一致 |
| 子代理 v4 套件（107 检查） | ✅ | ✅ | — |

回归：`test/RUN_ALL.sh` **24 通过 / 1 失败**，与基线逐位一致；
告警门禁零告警（过程中又被 `-Wdangling-pointer` 拦下一次，见第五节）。

### 9.5 五轮验收的累计产出

| 轮次 | 子代理发现的 bxroot 缺陷 | 其中我前一轮引入的 |
|---|---|---|
| 1 | `exec` 名解析、`faccessat2`、`eaccess`、shebang、绝对链接 | 0 |
| 2（复验） | 绝对链接读取仍错（stat 家族） | 1（"失败后重试"不够） |
| 3 | `chdir`、中间组件链接 | 0 |
| 4 | **`/bin` 全线失效** | **1（相对目标拼装漏 `tgt`）** |
| 5 | `statx`、`realpath`、`ln -sfn`、过度重试 | **1（过度重试改写了 ENOTDIR）** |

**五轮里三轮的缺陷是我自己引入的，全部由子代理用真实项目跑出来。**
我自己的验收从未覆盖到 —— 我的测试恰好都用 `/usr/bin/...` 而非
`/bin/...`，或只跑回归套件（对 `/bin` 的覆盖是间接的）。

**结论：改"路径翻译"这类核心逻辑时，自测必须显式包含
"系统自带的符号链接路径"（`/bin`、`/sbin`、`/lib`）与
"errno 语义不变性"（ENOTDIR/ELOOP 不能被改写成成功），
并且必须拿一个真实项目的构建+测试当验收 —— 回归套件绿是不够的。**
