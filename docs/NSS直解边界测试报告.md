# NSS 直解回退 · 边界测试报告

> 被测特性：`getpwnam` / `getpwnam_r` / `getgrnam` / `getgrnam_r` 四个钩子的
> **"/etc/passwd、/etc/group 直解回退"**（缺口 D 的修法，见 `docs/缺口D-NSS用户库查询失败.md`）。
>
> 实现：`src/runtime/preload.c`（`grep 直解`）。
> 探针：`test/probe_nss_edge.c`（T01..T10，本报告只读不改）。
> 新增 runner：`test/RUN_NSS_EDGE.sh`。
>
> 被归因的源码状态：`src/runtime/preload.c` md5 `93854c68b83994479090536f99976887`
> （mtime 2026-09-17 21:11:00），对应运行时 md5 `dc41a08afd8d400009556a0e0c65f808`。

---

## 〇、一句话结论

**契约用例 T01..T10 在 bxroot 侧全绿（10/10），但缺陷钉桩 D1..D5 全部命中**：
四个钩子的主路径（正常记录、缺字段、空行、超长行、文件缺失、ERANGE、100 次一致性）
都正确，**边界之外还藏着 5 个真实缺陷**（另有 1 项 D6 由本报告单独实测补充，
未进 runner 桩），其中 2 个属于"会把调用方缓冲区写坏"或"静默丢数据"的级别。
这 6 项**未改代码**（任务约束），只做登记与复现。

---

## 一、方法与两个基线

### 1.1 为什么 runner 要有"文件组"这个概念

探针的 10 个用例需要 **5 种互不相同的 `/etc/passwd` + `/etc/group` 内容**
（正常行 / 缺字段 / 空行 / 超长行 / 文件缺失）。一个进程只能看到一套文件，
所以必须分批换文件、每批只跑属于该批的用例（`EDGE_CASES` 就是为此存在的）。

分组表（用例归属从 `probe_nss_edge.c` 的**实际实现**读出，不是照抄任务描述）：

| 组 | passwd 内容 | group 内容 | 用例 |
|---|---|---|---|
| A | `root:x:0:0:root:/root:/bin/sh` | `root:x:0:` + `g:x:1:m1..m5` + `empty:x:1:` | T01, T06, T07, T09, T10 |
| B | A + `bad:x:1:2`（3 字段）+ `badnum:x:abc:def:junk:...` | `root:x:0:` | T02, T05 |
| C | 990 字节长名行 + A | `longg:x:7:` + 1200 字节 + `root:x:0:` | T04 |
| D | 三个空行 | 三个空行 | T03 |
| E | **不存在** | `root:x:0:` | T08 |
| F | 末行**不带换行** | 9 成员组 `nine` | D1–D5（缺陷钉桩，非 T 用例） |

> ★ **不分组会得到全是假阳性** ★
> 我最初的临时验证把 10 个用例对着"真实 rootfs 的 passwd"一次跑完，得到
> T01「pw_shell 不符」（真实 root 的 shell 是 `/bin/bash`，探针期望 `/bin/sh`）、
> T08「直解路径错误地命中了非法行」（其实 passwd 存在、root 本来就能查到）
> —— **四个 FAIL 全是分组错，不是代码缺陷**。分组表就是为了消除这类假阳性。

### 1.2 隔离手段：迷你 rootfs（不动真 rootfs）

runner 在 `$ROOTFS/tmp/<mktemp>/mini/` 建一个只含必需品的小 rootfs：
`lib/aarch64-linux-gnu/{ld-linux-aarch64.so.1,libc.so.6}`、`lib/ld-linux-aarch64.so.1`
软链、`etc/{passwd,group,nsswitch.conf}`（合成内容）、探针、bxroot 运行时。
bxroot 侧把 `BXROOT_ROOTFS` 指向它 —— **真 rootfs 完全不被触碰**。

### 1.3 bxroot 侧怎么跑（重要：不是 launcher）

本容器**已经在官方 proroot 容器内**。实测：用 launcher（静态二进制）直接跑，
即使 `env -i` 清空环境、即使 `LD_PRELOAD` 明确指向 bxroot，guest 里映射进来的
仍是官方 `libproroot-runtime.so`：

```
$ env -i PATH=/usr/bin:/bin /tmp/.../bxroot-launcher-bin -r / -0 -w / /tmp/.../who
[bxroot-launcher] stat(//tmp/.../who) OK, mode=700, size=70592
maps: bxroot=2 official_runtime=2          ← 官方运行时也在，且 -b / -r 全部无效
```

所以 runner 走本仓库其余测试（`RUN_PRIVDROP` / `RUN_PTHREAD_CREATE` / `RUN_SHEBANG`
/ `RUN_E2E` …）同样的路：

```sh
BXROOT_ROOTFS=<mini> BXROOT_TMP_DIR=<mini>/tmp BXROOT_WORKDIR=/ BXROOT_FAKEROOT=1 \
EDGE_EXPECT_DIRECT=1 \
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
  --argv0 probe --preload <mini>/libbxroot-runtime.so <mini>/probe
```

launcher 那条路仍会编译并跑一次**诊断**（§1，不做判据），把上述事实留证。

### 1.4 对照侧（真实 glibc NSS）

题目说"不用任何 runtime，直接在容器里跑探针"就是可用的对照 —— 采用。
容器内 NSS 只认 `/etc/passwd`（= `$ROOTFS/etc/passwd`，**同一 inode**），
所以对照侧必须在 trap 保护窗口内把真实 `/etc/passwd`、`/etc/group` 换成与
bxroot 侧**逐字节相同**的合成内容。

**恢复有两处关键细节（都是踩坑后改的）**：

1. **必须保留 inode**。第一版用 `cat 备份 > /etc/passwd` 换内容、跑完再 `cat` 回去
   —— 内容 md5 恢复了，**inode 却变了**（`6012456 → 6080154`）。inode 一变，
   另一个视角里那份"同一个文件"就对不上了（本项目的经典双视角陷阱）。
   改法：备份时**留一个硬链接**（同 inode），换文件用 `rm + 新建`，
   恢复时 `rm + ln 硬链接`；`verify_restore` 同时校验 **md5 与 `dev:ino`**。
2. **SIGKILL 是不可捕获的**（见 §五"已知缺口"），另有 `--restore` 兜底模式。

---

## 二、每个用例的设计意图与判据

| 用例 | 输入 | 判据 | 意图 |
|---|---|---|---|
| T01 | `root:x:0:0:root:/root:/bin/sh` | `pw_uid==0`、`pw_name=="root"`、`pw_dir=="/root"`、`pw_shell=="/bin/sh"`，且 `getpwnam_r` 同步正确 | **环境对照锚点**：两侧都该查到，谁查不到谁坏 |
| T02 | `bad:x:1:2`（只有 3 字段） | 直解侧必须 NULL；对照侧意外命中只记 skip | 缺字段行应整行跳过、不崩溃 |
| T03 | passwd/group 都只有空行 | 查任意名返回 NULL | 空行文件不越界、不返回垃圾 |
| T04 | passwd 990 字节长行、group 1200 字节长行（`fgets(512)`/`fgets(1024)` 会切块） | 不越界不崩溃，**且长行之后的 `root` 仍查得到** | 切块解析不能污染后续行 |
| T05 | `badnum:x:abc:def:...` | 要么整行拒绝(NULL)，要么 `atoi=0` 语义；**不许返回非零垃圾** | 非数字 uid/gid 的处理 |
| T06 | `g:x:1:m1,m2,m3,m4,m5` | `gr_gid==1`、`gr_mem` 恰 5 个且内容逐一相符 | 多成员组解析 |
| T07 | `empty:x:1:` | `gr_mem != NULL` 且 `gr_mem[0] == NULL` | 空成员列表 = NULL 结尾数组（不是 NULL 指针） |
| T08 | `/etc/passwd` **不存在** | 两族都 NULL，不崩溃 | `fopen` 失败路径 |
| T09 | 组 A 的文件 | 四族 × 100 次结果全部一致 | 反复调用不漂移（静态缓冲/缓存正确性） |
| T10 | 同一文件，`buf` 只有 8 字节 | 两族都必须 `ERANGE` 且 `*result==NULL` | `_r` 版缓冲区不足契约 |

---

## 三、两侧实际结果

命令：

```sh
cd /root/proroot-work/agents/rename-bxroot
# 用自建运行时以排除"共享产物对应别人代码状态"的风险
gcc -shared -fPIC -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter \
    -D_GNU_SOURCE= -Isrc/l2s -Isrc/runtime -Isrc/proc \
    -DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0 -O2 \
    src/runtime/preload.c src/l2s/l2s.c src/l2s/l2s-runtime.c src/runtime/fakeroot.c \
    src/runtime/crash.c src/runtime/sigsys.c src/runtime/syscall_guard.c \
    src/runtime/livepatch.c src/proc/proc.c -ldl -nostartfiles -o /tmp/priv/libbxroot.so
BXROOT_SO=/tmp/priv/libbxroot.so sh test/RUN_NSS_EDGE.sh
```

### 3.1 契约用例 T01..T10

| 用例 | bxroot 侧 | 对照侧（真实 glibc NSS） |
|---|---|---|
| T01 | `[ok]` uid=0 dir=/root shell=/bin/sh，`_r` 同步正确 | `[ok]` 同上 |
| T02 | `[ok]` 返回 NULL，未崩溃 | `[skip]` 真实 NSS 意外命中 |
| T03 | `[ok]` 返回 NULL，未崩溃 | `[ok]` |
| T04 | `[ok]` 未越界未崩溃，后续查询不受影响 | `[ok]` |
| T05 | `[ok]` atoi=0 语义，未崩溃 | `[ok]` 该行被拒绝（NULL） |
| T06 | `[ok]` gr_mem 5 个成员，gid=1，内容逐一相符 | `[ok]` |
| T07 | `[ok]` `gr_mem[0]==NULL` | `[ok]` |
| T08 | `[ok]` 返回 NULL，未崩溃 | `[ok]` |
| T09 | `[ok]` 四族结果全部一致 | `[ok]` |
| T10 | `[ok]` passwd/group 两族均 ERANGE 且 result=NULL | `[ok]` |

**bxroot 侧小结：通过 10 / 失败 0 / 跳过 0**（五组小结行依次 `ok=5,2,1,1,1`）。

原始输出（runner §2）：

```
   [组 A] cases=1,6,7,9,10
     probe EDGE: start mode=bxroot-direct cases=1,6,7,9,10
     [ok] T01 getpwnam(root) uid=0 dir=/root shell=/bin/sh，_r 同步正确
     [ok] T06 多成员组(g) gr_mem 5 个成员，gid=1，内容逐一相符
     [ok] T07 空成员组(empty) gr_mem[0]==NULL
     [ok] T09 连续 100 次 四族结果全部一致
     [ok] T10 ERANGE(buf=8) passwd/group 两族均 ERANGE 且 result=NULL
     probe EDGE: ok=5 fail=0 skip=0 mode=bxroot-direct
   ...（B/C/D/E 组同样 0 fail）
```

### 3.2 T02 对照侧为什么是 skip（不是失败）

对照侧真实 NSS 对 `bad:x:1:2` **意外命中了**（探针按设计记 skip）。
这不是缺陷：`bad:x:1:2` 解析成"3 个字段"，glibc 把它当
`name=bad, passwd=x, uid=1`，gid/gecos/dir/shell 取默认/空 —— 这是 glibc 的行为，
本测试钉的是 **bxroot 直解解析器**，不是 glibc。探针头注释已明确此约定，实现一致。

### 3.3 回归锚点：真实 rootfs 上的 NSS 全家（§6，不动任何文件）

缺口 D 的原始症状是 `getent passwd root` 空、`dpkg -i` 报 `unknown system user 'root'`。
边界用例再多，这条断了特性就是没修好：

```
   bxroot:
     getent passwd root: [root:x:0:0:root:/root:/bin/bash]
     getent group root: [root:x:0:]
     getent group messagebus: [messagebus:x:101:]
     id: [uid=0(root) gid=0(root) groups=0(root)]
   ✅ getent passwd root 与 rootfs/etc/passwd 逐字一致
   ✅ getent group root 与 rootfs/etc/group 逐字一致
   ✅ getent group messagebus（非 root 的普通组）一致
   ✅ id 的组名解析正常（缺口 D 的原始症状之一）
```

> 对比 `docs/已知限制与架构能力边界.md` §2.2 里记的"`getent passwd root`：bxroot 空、rc=2"、
> "`id`：bxroot `gid=0`（组名缺失）" —— **那三个症状现已消失**，该文档 §2.2 的
> "剩余边缘"示例块已过期，需要更新。

---

## 四、发现的真实缺陷（本轮最有价值的部分）

runner §5 的"缺陷钉桩"把直解解析器与 glibc 的 NSS files 解析器**放在同一份合成
文件上**对比。期望值来自 glibc 语义与 passwd/group 格式规范，不来自当前实现。

```
   bxroot：
     D1 getgrnam_r(nine) nmem=1 rc=0 (期望 nmem=9)
     D2 getgrnam_r(s,buflen=20) rc=34 哨兵被破坏=32 字节 (期望 0)
     D3 getgrnam(nine)   nmem=7 (期望 9)
     D4 getpwnam(lastuser) = (NULL) (期望 lastuser；末行无换行)
     D5 getpwnam_r(不存在) rc=2 res=NULL (glibc 契约 rc=0 res=NULL)
     D5 getgrnam_r(不存在) rc=2 res=NULL (glibc 契约 rc=0 res=NULL)
     probe DEFECT: fail=6
   对照（真实 glibc，同一份合成文件）：
     D1 getgrnam_r(nine) nmem=9 rc=0      D2 哨兵被破坏=0 字节
     D3 getgrnam(nine)   nmem=9           D4 getpwnam(lastuser) = lastuser
     D5 getpwnam_r(不存在) rc=0 res=NULL  D5 getgrnam_r(不存在) rc=0 res=NULL
     probe DEFECT: fail=0
   ✅ 对照侧无差异 → 说明 D1..D5 是 bxroot 直解侧的问题，不是文件格式或环境问题
```

### D1 ★ `getgrnam_r` 只返回第一个成员（静默丢数据）

**现象**：`getgrnam_r("nine")` 对 `nine:x:9:m1,...,m9`（9 个成员）返回
`rc=0` 但 `gr_mem` 只有 **1** 个成员；`nmem=1`。

**根因**（`src/runtime/preload.c` `getgrnam_r`，5422–5439）：成员列表被**切了两次**。
第一次循环（5422–5427）只为**计数** `mi`，但它用 `strchr(tok, ',')` 把**逗号原地改成
`'\0'`**；第二次循环（5433–5438）再从同一块内存重新扫，此时**逗号已经被吃掉了**，
于是整串 `"m1"` 被当成**一个**成员：

```c
/* 第一次：计数 —— 但顺手把 ',' 改成了 '\0' */
tok = buf + (used - len);
while (tok != NULL && mi < 7) {
    char *c = strchr(tok, ',');
    if (c != NULL) *c = '\0';          /* ← 破坏性写入 */
    if (*tok != '\0') mi++;
    tok = (c != NULL) ? c + 1 : NULL;
}
{   /* 第二次：填充 —— 逗号已经没了，只能填进 1 个 */
    tok = buf + (used - len);
    while (tok != NULL && k < 7) { ... ml[k++] = tok; ... }
```

`getgrnam`（非 `_r`）**没有**这个问题 —— 它只用一次循环（5329），所以同一份文件
下 `getgrnam` 返回 3 个成员而 `getgrnam_r` 只返回 1 个。**同一功能两条路径行为不一致**，
正是本仓库反复出现的缺陷模式。

**真实工具影响**（实测，非推测）：

```
getent group big: [big:x:5000:m1,m2,m3,m4,m5,m6,m7]     ← 非 _r 路径，7 个（见 D3）
python grp mem: ['m1']                                   ← _r 路径，只剩 1 个
```

`getent`/`python grp` 的**成员列表被静默截断**。对依赖组成员判断的程序
（如 `sg`、权限检查）会得出**错误的授权判断**。

### D2 ★ `getgrnam_r` 缓冲区不足时**越界写调用方缓冲**（同时报 ERANGE）

**现象**：`buflen=20` 时返回 `rc=34`(ERANGE) —— 看起来"正确拒绝了"，
但**已经写坏了调用方的缓冲区**。用哨兵精确测量：

```
M1 buflen=20 rc=34 被写字节数=78 最远偏移=79 → 越过 buf 末尾 60 字节
```

**根因**（5441–5442）：`gr_mem` 指针数组的写入**完全没有 `buflen` 检查**，
检查放在**写完之后**：

```c
char **ml = (char **)(buf + ((used + sizeof(char*) - 1) & ~(sizeof(char*) - 1)));
...
for (; k < 8; k++) ml[k] = NULL;      /* ← 已经写进去了，可能在 buf 之外 */
grp->gr_mem = ml;
used += 8 * sizeof(char*);
if (used > buflen) { fclose(f); return ERANGE; }   /* ← 检查太晚 */
```

**危害**：调用方按契约只提供 `buflen` 字节，超出部分是**别人的栈/堆**。
返回 ERANGE 会让调用方以为"安全失败"并可能重试或释放缓冲，而越界写已经发生。
这是**内存安全**问题，不只是语义问题。

> 注：T10（`buf=8`）之所以全绿，是因为 T10 只查 `gr_gid`/`rc`/`*result`，
> **没有检查哨兵**，且 `getgrnam_r("g")` 在组 A 里只有 5 个成员、
> `buf` 在栈上恰好没踩到关键数据。**探针 T10 覆盖不到这个缺陷** —— 这正是
> 缺陷钉桩存在的意义。

### D3 `getgrnam` 成员数被硬上限截断到 7（静默丢数据）

**现象**：9 成员组返回 `nmem=7`。**根因**（`getgrnam`，5329 + 5319–5320）：
`g_memlist[8]` 且 `while (tok != NULL && mi < 7)` —— 循环条件**硬编码 7**，
第 8、9 个成员被静默丢弃，不报错、不截断标志。
同文件里 `getgrnam_r` 是 `k < 7`（5433），另一处 `ml` 也是 8 项 ——
容量上限 7 是**多个地方各自硬编码**的魔数。

**真实工具影响**：`getent group big` 输出 `...,m7]`，`m8`/`m9` 消失（实测）。

### D4 文件末行不带换行符时整条记录被丢弃（静默丢数据）

**现象**：`lastuser:x:777:777:L:/home/last:/bin/sh` 作为**文件最后一行且无换行**时，
`getpwnam("lastuser")` 返回 **NULL**。glibc 对同一份文件正常命中
（`glibc fgetpwent_r: 命中`）。

**根因**（5099 / 5180 等处）：字段切分器最后一个字段用 `'\n'` 作分隔符：

```c
e = strchr(w, i < 6 ? ':' : '\n');
if (e == NULL) { break; }     /* ← 无换行 → 第 7 个字段切不出来 */
...
if (nf < 7) continue;         /* ← 整行被跳过 */
```

`fgets` 读到 EOF 时**不补换行**，所以最后一行天然可能没有 `\n`。POSIX 明确
"最后一行可以没有换行符"，`/etc/passwd` 在手工编辑/被脚本截断后出现这种形态
完全可能。4 处解析器（`getpwnam`/`getpwnam_r`/`getgrnam`/`getgrnam_r`）**同一写法**，
所以四个钩子都受影响。

### D5 `_r` 版"查不到"返回 `ENOENT`，违反 glibc 契约（把"没找到"报成"出错"）

**现象**：

```
bxroot  : getpwnam_r(不存在) rc=2 (ENOENT) res=NULL
glibc   : getpwnam_r(不存在) rc=0          res=NULL
```

**根因**（5170/5230/5378/5451）：直解循环走完没命中就 `return ENOENT;`。

**为什么这是缺陷**：`getpwnam_r`/`getgrnam_r` 的契约是
**"没找到" = 返回 0 且 `*result = NULL`**；非 0 返回值只用于**真正的错误**
（ERANGE、EIO…）。调用方的标准写法是：

```c
rc = getpwnam_r(name, &pw, buf, len, &res);
if (rc != 0) { /* 当成严重错误：报错、退出、或 errno 路径 */ }
else if (res == NULL) { /* 正常的"用户不存在" */ }
```

所以 bxxroot 会把**正常的"用户不存在"**变成调用方眼中的**系统错误**。
实测佐证：`python3 -c "import pwd; pwd.getpwnam('nosuch')"` 在真机上
抛的是 `KeyError`（= 走了 res==NULL 的正常分支），而 bxroot 下会变成
`OSError`/`PermissionError` 一类 —— 错误类型改变会**改变程序的错误处理分支**。

### D6（附带发现）字段被 `snprintf` 静默截断

`getpwnam` 用固定大小的静态缓冲承载字段（5112–5113、5319）：

```c
static char f_name[64], f_passwd[64], f_gecos[64];
static char f_dir[256], f_shell[64];
snprintf(f_gecos, sizeof f_gecos, "%s", fields[4]);   /* 超长静默截断 */
```

实测（GECOS > 63 字节）：

```
bxroot: bob: gecos_len=63 gecos=[Bob Verylongname,Department of Extremely Long Names, Building 7]
glibc : bob: gecos_len=104 gecos=[Bob Verylongname,..., Room 1234, +1-555-0199, bob@example.com]
```

`pw_dir` 上限 256、`pw_shell` 64 同理。截断**无任何提示**。
（`pw_name` 上限 64 也会截断，但 Linux 的 `LOGIN_NAME_MAX` 就是 64，
这一项影响可忽略；GECOS 与 dir 才是实际问题。）

> 附带测过一项**不算缺陷**的：CRLF 行（`...:/bin/sh\r\n`）末字段保留 `'\r'`。
> 我核对了 glibc 的 `fgets` 读数 —— glibc 同样按 `'\n'` 切、同样保留 `\r`。
> **两侧一致，不作为缺陷**（记录在此以免后续重复调查）。

### 缺陷汇总与优先级

| # | 位置 | 类型 | 真实影响 | 建议优先级 |
|---|---|---|---|---|
| D2 | `getgrnam_r` 5441–5443 | **内存安全**：越界写调用方缓冲（报 ERANGE 但仍越界） | 缓冲区不足时写坏别人的栈/堆 | **P0** |
| D1 | `getgrnam_r` 5422–5441 | 静默丢数据（只返回第 1 个成员） | 成员判断错误的授权结果 | **P1** |
| D4 | 4 处解析器 5099/5180… | 静默丢数据（末行无换行整条丢弃） | 一条用户/组记录凭空消失 | **P1** |
| D3 | `getgrnam` 5329 | 静默丢数据（成员上限硬编码 7） | 大组成员列表被截断 | P2 |
| D5 | 4 处解析器 5170/5230/5378/5451 | 契约违反（ENOENT 代替 0+NULL） | 调用方把"不存在"当系统错误 | P2 |
| D6 | `getpwnam`/`getgrnam` 5112–5113/5319 | 静默截断（gecos 63 / dir 255 / shell 63） | 长字段被砍掉 | P3 |

**这 6 项都未改动 `src/`**（任务约束：发现缺陷写报告，不改代码）。

---

## 五、已知差异的归因

### 5.1 官方 runtime 在本容器里**不做路径翻译**（重要，影响对照设计）

对比 `docs/` 中若干报告用 `libproroot-runtime.so` 作对照的做法，本轮实测发现
**官方 runtime 在本容器的 harness 下不生效**。证据（用唯一标记做判别）：

```
$ echo MINI-UNIQUE-HOST > <mini>/etc/hostname
$ PROROOT_ROOTFS=<mini> ... --preload <mini>/libproroot-runtime.so <mini>/hn
HOSTNAME_SEEN=[localhost.localdomain]          ← 读到的是容器根，不是 <mini>

$ BXROOT_ROOTFS=<mini>  ... --preload <mini>/libbxroot-runtime.so <mini>/hn
HOSTNAME_SEEN=[MINI-UNIQUE-HOST]               ← bxroot 正常翻译
```

而且与"完全不加载任何 runtime 直接在容器里跑"的输出**逐字相同**：

```
$ <mini>/t1          （无 runtime）
   mini-only.txt -> (NOT FOUND)
   etc/hostname -> localhost.localdomain
$ PROROOT_ROOTFS=<mini> ... --preload libproroot-runtime.so <mini>/t1
   mini-only.txt -> (NOT FOUND)                ← 完全相同
   etc/hostname -> localhost.localdomain
```

已排除：`PROROOT_ROOTFS`（含指向不存在路径）、`PROROOT_BINDS`、
`PROROOT_ESCAPE_FD`、`PROROOT_CFG_FD`、换用 app 自带的 linker、
直接 exec linker（`linker.so <prog>`）。运行时的 `strings` 里确有
`PROROOT_ROOTFS`/`PROROOT_CFG_FD`/`PROROOT_ESCAPE_FD`，且有一条
`missing PROROOT_CFG_FD or PROROOT_ESCAPE_FD` —— 说明它期待父进程（官方
launcher）**传递这两个 fd**，而本容器没有可复现的构造方式。

**结论与影响**：
- 官方 runtime **不能**作为"rootfs 隔离下的严格对照"。本轮因此**没有**把官方
  数字当判据，改用两个可靠基线：**容器直跑（真实 glibc NSS）** + **glibc 自带
  `fgetpwent_r`/`fgetgrent_r` 解析同一份合成文件**。
- 本仓库其它文档若用官方 runtime 做同 rootfs 对照，**需要复核那一节是否真的
  测到了官方**（本报告 §5.2 就是一个反例）。

### 5.2 `docs/已知限制与架构能力边界.md` §2.2 已过期

该节表格"`getent passwd root`：官方 `root:x:0:0...` / bxroot（空，rc=2）"、
"`id`：bxroot `gid=0`（组名缺失）"、`python pwd` KeyError —— 本轮**实测均已修复**
（§3.3）。标题写"核心已修"但正文表格仍是修前的数字，**自相矛盾**，建议更新。

另注：该节说"NSS 全家与官方一致 ✅"、同文档 §2.11 说"NSS 全家逐项一致 ✅" ——
本报告 §5.1 表明官方那侧在本容器里是**未翻译的容器直跑**，所以这类"与官方一致"
的结论**可能只是"两侧都在看容器的 /etc/passwd"**。真实 rootfs 上 bxroot 的
`getent`/`id`/`python pwd` 确实正确（§3.3 有独立判据），但归因方式需要修正。

### 5.3 三个 T 用例在两侧的差异属**预期**

- **T02**（对照侧 skip）：glibc 与 bxroot 对 `bad:x:1:2` 的处理不同，
  探针按设计只在直解侧判失败。**不是缺陷**。
- **T05**：bxroot 走 `atoi=0`，glibc 整行拒绝。两者探针都接受
  （"可接受"分支）。**语义差异，已由探针契约覆盖**。

---

## 六、复现方式

```sh
cd /root/proroot-work/agents/rename-bxroot

# 完整跑（bxroot 侧 + 对照侧 + 缺陷钉桩）
sh test/RUN_NSS_EDGE.sh

# 不碰真实 /etc（推荐在 CI/并行环境用）
sh test/RUN_NSS_EDGE.sh --bxroot-only

# 指定被测运行时（并行多 agent 时必用，否则 build/ 可能是别人的代码状态）
BXROOT_SO=/path/to/libbxroot-runtime.so sh test/RUN_NSS_EDGE.sh

# 若上一次被 SIGKILL 打断（见下），从备份还原真实 /etc
sh test/RUN_NSS_EDGE.sh --restore
```

**退出码**：`0` = 无 FAIL（允许 skip）；`1` = 有 FAIL；`2` = 环境不满足（SKIP）。
当前 `src/` 下会返回 **1**（因 §4 缺陷钉桩 D1–D5 命中）。

### runner 自身的两个安全设计（都来自实测教训）

1. **SIGKILL 兜底**：对照侧要改真实 `/etc`。脚本对 EXIT/INT/TERM/HUP/PIPE 都装了
   trap，实测 `kill -TERM` 在窗口内能**完整恢复 md5 + inode**。但
   **SIGKILL 不可捕获**：实测 `kill -9` 后 `/etc/passwd` **停在合成内容上**
   （md5 `930991…` ≠ 原始 `693a2b…`）。这无法用 shell 消除（要根治只能用
   mount namespace，而本容器 `CapEff=0000000000000000`，
   `unshare -m` 直接 `Operation not permitted`，已实测）。
   缓解：① 进入窗口前写状态文件 `~/.bxroot-nss-edge-state`（SIGKILL 后仍在，
   下次运行**警告并提示** `--restore`）；② `--restore` 用备份里的硬链接还原。
   实测 `--restore` 已成功修复一次真实的 SIGKILL 残留。
2. **清理幂等 + 先恢复后删除**：第一版 `sh RUN_NSS_EDGE.sh | head -30` 会因
   SIGPIPE 在 trap 中途打断（trap 里的 `echo` 自己又触发 PIPE），残留三个暂存目录。
   现在 cleanup **不写 stdout**、恢复放在删除之前、可重复调用。

---

## 七、遗留问题（跑不了 / 没结论的部分）

| 项 | 状态 | 原因 |
|---|---|---|
| 官方 runtime 的严格对照 | **跑不了** | 官方 runtime 在本容器不接受 `PROROOT_ROOTFS`/`PROROOT_BINDS`，需要父进程传 `PROROOT_CFG_FD`/`PROROOT_ESCAPE_FD`（实测 5 种构造均无效）。见 §5.1 |
| 上游 ptrace 版 proot 对照 | **主动放弃** | 本容器已在 proroot 容器内，ptrace 版是双重翻译死胡同（题目亦指出） |
| `/etc/group` 成员数 > 7 的真实发行版 | **未覆盖** | 实测本 rootfs 的 `group` **60 个组里没有一个带成员**，所以 D1/D3 在**真实 rootfs 上不会触发**，只在合成文件下暴露 —— 但用户可能自建含成员的 group 文件 |
| D2 越界写的实际崩溃复现 | **未做** | 需要构造"越界正好踩到关键数据"的场景，本轮只做到哨兵精确测量（60 字节）；危害判断基于测量与代码，未观察到崩溃 |
| `getpwuid`/`getpwuid_r`/`getgrgid` 的同类边界 | **未覆盖** | 探针只覆盖 `*nam` 两族；`*uid`/`*gid` 是**另一条代码路径**（`getgrgid` 甚至不读 group 文件，是 fakeroot 合成），同类缺陷可能存在 |
| `getgrent`/`setgrent` 遍历族 | **未覆盖** | 缺口 D 文档记 `getpwent()` 遍历返回 0 条；本轮未测遍历族 |

**未做**：`src/` 任何改动（任务约束）；`test/RUN_ALL.sh` 未触碰（由外部集成）。

---

## 八、给后续的三条建议

1. **先修 D2（内存安全）**：把 `gr_mem` 指针数组的 `buflen` 检查**提到写入之前**
   （`if (used + 8*sizeof(char*) > buflen) { return ERANGE; }`），并删掉第一次
   计数循环里的 `*c = '\0'`（改成 `memchr` 计数或只数不写）—— 一处改动同时解掉 D1。
2. **D4 用统一的"行解析"辅助函数**：现在 4 个钩子各自抄了一遍字段切分逻辑
   （`strchr(w, ... '\n')`），于是同一个 bug 复制了 4 份。抽出
   `bxroot_parse_line(buf, nfields, seps)` 并让"最后一个字段以 `\n` **或 EOF** 结束"，
   既修 D4 又避免下次再漂移。
3. **把本 runner 接进 `RUN_ALL.sh`**：注意 §1 的 launcher 诊断与 §3 的 `/etc` 窗口 ——
   并行环境建议默认 `--bxroot-only`，把带对照侧的完整跑留给串行场景。
