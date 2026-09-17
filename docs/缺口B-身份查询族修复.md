# 缺口 B 修复：身份**查询**族在裸 syscall 层缺失

> 前置：`syscall(174..177)`（getuid 族）已由前一个任务修完。
> 本任务修**查询**族的其余三个：`148 getresuid` / `150 getresgid` / `158 getgroups`。
>
> **缺口 C（降权族）与缺口 D（NSS）不在本任务范围**，见文末状态。

---

## 一、缺陷（三侧对照实测）

| 项 | 官方 | bxroot（修前） | 原生（容器外） |
|---|---|---|---|
| `syscall(148,&r,&e,&s)` | `0/0/0` rc=0 | **`10655`×3** ❌ | `0/0/0` |
| `syscall(148,&r,NULL,NULL)` | `rc=0 r=0` | **`rc=-1 EFAULT`** ❌ | `rc=0 r=0` |
| `syscall(150,...)` | `0/0/0` | 10655 ❌ | `0/0/0` |
| `syscall(158,0,NULL)` | **1** | **6** ❌ | 6 |
| `getgroups(0,NULL)`（符号层） | **1** | **0** ❌ | 6 |

**注意最后一行**：原任务只提到 syscall 层，实测**符号层也不一致**
（bxroot 的 `getgroups` 返回 **0 个组**，官方返回 1 个 `[0]`）。
两层都要对齐 —— 否则会出现"同一个程序用两种方式问出两个答案"。

## 二、★ 一个重要的实测更正：容器内核与原生内核不同 ★

先前文档写"`getresuid(NULL,NULL,NULL)` 原生返回 EFAULT"。**实测表明那描述的是容器内的行为，不是内核语义：**

```
                    容器外（本 Ubuntu）   容器内（外层 proroot）
all-NULL            rc=0                  rc=-14 (EFAULT)
only-&r             rc=0 r=0              rc=-14 (EFAULT)
all-3               rc=0 r=0/0/0          rc=0 r=10655/...
```

用**真·裸 svc**（内联汇编，绕过一切符号钩子）测量得到同一结论。
**所以"部分 NULL → EFAULT"是外层容器引入的，不是内核规范。** 官方对此
一律回 0（它自己填好输出位置），bxroot 修前则把容器的 EFAULT 透传给客户。

这直接影响修法：**148/150 分支不能沿用 `ret >= 0` 门控** ——
那会让"部分 NULL"这条**合法**调用永远进不来。

## 三、修法

### 3.1 两个新入口（`preload.c`）

```c
int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                            unsigned int *suid, unsigned int *rgid,
                            unsigned int *egid, unsigned int *sgid);
int bxroot_fakeroot_groups(unsigned int *groups, int cap, int *count);
```

**为什么不复用 `bxroot_fakeroot_ids`**：那一个入口只给**一个** uid 和一个
gid，而 `getresuid` 要写**三个各不相同**的值、`getgroups` 要写一整个数组。
用它填三个字段会让 `getgid` 也拿到 uid 的值 —— 本项目刚在 statx 的
`stx_mode` 宽度、fakeroot 初始化顺序上踩过"同一套规则写两处、两边漂移"。

**取值与符号层钩子完全同源**（都读同一份 `g_fakeroot_state` 字段）——
这是硬要求：符号层与 syscall 层各读一处就会出现"两层两个答案"。

### 3.2 `syscall_guard.c` 的结果改写

- **148/150**：不看 `ret`（因为容器给 EFAULT 而官方给 0），自己填好输出位置、
  `ret = 0`、**清 errno**。
  唯一保留的失败语义：**三个指针全 NULL**（无输出位置，原生也是 EFAULT）。
- **158**：双重语义 —— `cap==0` 回数量；`cap>0` 写数组；cap 不足回 EINVAL
  且**不写数组**（复刻内核实测行为）。成功路径**清 errno**。
- **174..177 保持 `ret >= 0`** 门控不变（那几条是纯改返回值，没有客户缓冲区）。

### 3.3 fakeroot 默认组表改为 1 个 `[0]`

实测官方伪造的身份是**自洽**的：`uid=gid=0` 且补充组里也有 `0`。
bxroot 原先 `ngroups = 0`，于是 `id` 输出 `gid=0 groups=0`（官方 `groups=0(root)`）。
改为 `groups[0]=0; ngroups=1` —— **与官方对齐而非与真实内核对齐**，
因为 fakeroot 的语义就是"让程序看到它以为的那个身份"。

## 四、★ 回归抓到我引入的一个崩溃（值得记录）★

第一版实现只在最外层判了 `bxroot_fakeroot_ids != NULL`，然后在里面直接
调用 `bxroot_fakeroot_res_ids(...)`。跑回归时：

```
❌ 身份 syscall 伪装  rc=139
[proroot] SIGSEGV pc=0x0 lr=... x8=0x94      ← 0x94 = 148
```

**根因**：`syscall_guard.c` 有三种编译方式，其中身份单测
（`test_id_syscall_guard.c`）只提供 `bxroot_fakeroot_ids` 的强定义，
另两个 weak 符号仍是 **NULL**。对 NULL 函数指针的调用直接跳到地址 0。

**教训**：**每个 weak 符号必须单独判 NULL**，外层判据**不能**替代内层 ——
三个符号是**独立解析**的。已修（`if (bxroot_fakeroot_res_ids == NULL) break;`）。

> 这件事本身说明**测试是有效的**：它精确地在引入后立刻抓住了崩溃，
> 而不是让它在生产里以"偶发段错误"的形式出现。

## 五、验证

### 修后三侧对照（逐行）

```
########## syscall 层（syscall(158)）##########
官方  : A) = 1 errno=0    B) = 1 first=0 errno=0    C) = 1 errno=0
bxroot: A) = 1 errno=0    B) = 1 first=0 errno=0    C) = 1 errno=0     ✅ 一致

########## 符号层（getgroups）##########
官方  : A) = 1 errno=0    B) = 1 first=0 errno=0    C) = 1 errno=0
bxroot: A) = 1 errno=0    B) = 1 first=0 errno=0    C) = 1 errno=0     ✅ 一致

########## getresuid ##########
                    官方               bxroot 修前        bxroot 修后
all-NULL            rc=0               rc=-1/EFAULT       rc=-1/EFAULT  ← 见下
only-&r             rc=0 r=0           rc=-1/EFAULT       rc=0 r=0      ✅
all-3               rc=0 0/0/0         10655×3            rc=0 0/0/0    ✅
```

### 唯一残留的有意差异：`all-NULL`

官方把它也伪装成成功（`rc=0`），本实现保留 `EFAULT`。
**理由**：三个指针全 NULL 意味着**没有任何输出位置**，那是调用方的错误；
原生内核（容器外）也返回 EFAULT。官方在此处比内核"更宽容"，
这更像是它实现的副作用而非有意设计。**保留内核语义更安全** ——
若将来证明某些程序依赖官方的宽容，再改。

### 回归

`sh test/RUN_ALL.sh --quick` → **17/17**（既有 16 项一项没红）。
`sh test/RUN_ID_SYSCALL.sh` → 37 用例 / 0 失败。

## 六、状态与遗留

| 缺口 | 状态 |
|---|---|
| 174..177 读身份 | ✅ 已修（前一个任务） |
| **B：148/150/158 查询族** | ✅ **本任务已修** |
| C：降权族（`setuid`/`setgid`/`setgroups`…） | ❌ **未修** —— 实测 `chage -l root` 官方 rc=0 / bxroot rc=1。机制已查清（官方有**用户态身份账本**：setter 写、getter 读；bxroot 的 `sigsys.c` 一律回 ENOSYS）。最小集合 `{143,145}`，但完整对齐需要账本。见 `docs/身份查询与降权族-原始数据.md` |
| D：NSS 用户库查询（`getent`/`pwd.getpwnam`） | ❌ 未修 —— 四层排除已做，**根因未定位**。见 `docs/缺口D-NSS用户库查询失败.md` |

> **缺口 B 的修复让 `id` 的组名解析相关行为更接近官方**，但
> `passwd -S root` 仍失败 —— 它的阻塞点是**缺口 D**（NSS），
> 不是 setter 族（子代理实测：它零 SIGSYS 命中）。三个缺口互不替代。

---

# 附：缺口 C（降权族）后续修复

> 本节在缺口 B 修完后追加。缺口 C 原本标为"未修"，本轮一并解决。

## 缺陷

```
########## 官方 ##########                    ########## bxroot ##########
$ chage -l root                               $ chage -l root
Last password change : Aug 05, 2025           chage: failed to drop privileges
...（正常输出，rc=0）                          (Function not implemented)  rc=1
```

## ★ 关键：这是**两条**路径都没覆盖，修一条不够 ★

先前只修了 `syscall(143/144/...)` 层，但 `chage` **仍然失败**。追踪：

```
$ BXROOT_SIGSYS_LOG=1 chage -l root
[bxroot] sigsys: 模拟 syscall 143 -> ENOSYS
```

而 `readelf --dyn-syms chage` 显示它引用的是 **`setreuid` 符号**
（`objdump -d chage | grep -c svc` = **0**）—— glibc 的 `setreuid`
**包装函数自己发 svc**，既不经过 libc 的 `syscall()` 符号，
也不经过我们任何钩子，直接撞 proroot-ldso 的 seccomp 过滤器。

```
┌──────────────────────────────────────────────────────────┐
│ 三种发起方式，各自需要不同的拦截点：                        │
│  ① 程序调 setreuid(2) 符号   -> 符号层钩子                  │
│  ② 程序调 syscall(143,...)   -> syscall() 钩子              │
│  ③ 程序内联 svc #0           -> 两侧都拦不到（官方也不拦）    │
└──────────────────────────────────────────────────────────┘
```

**这正是本项目反复出现的「同一功能在不同路径上覆盖不全」模式** ——
修了 ② 就以为修完了，而真实程序走的是 ①。

## 修法：用户态身份账本（不是"返回 0"）

官方**有状态**：setter 生效后回读 getter 会变。

```
########## 官方 ##########            ########## bxroot（修前）##########
BEFORE: getuid=0 getgid=0              BEFORE: getuid=0 getgid=0
setgid(999) rc=0  setuid(999) rc=0     setgid(999) rc=-1 errno=38
AFTER : getuid=999 getgid=999          AFTER : getuid=0        ❌
```

只返回 0 会让程序看到**自相矛盾**的世界（"降权成功"却回读原身份），
比报错更难查。所以：

1. **`preload.c` 新增桥接 `bxroot_fakeroot_setter(op, a0..a2, ...)`**
   —— 复用 fakeroot 纯逻辑层的 `fakeroot_setuid/setgid/setresuid/...`
   （账本逻辑只有一份）。
2. **符号层补 9 个 setter 钩子**（`setuid`/`setgid`/`setreuid`/`setregid`/
   `setresuid`/`setresgid`/`setgroups`/`setfsuid`/`setfsgid`）—— 这一层
   **原先完全不存在**，是 `chage` 走的路径。
3. **修好 getter 的硬编码**：`getuid/getgid/geteuid/getegid` 原先写的是
   `if (g_config.fakeroot) return 0;` —— **永远返回 0，不读账本**。
   改为读 `g_fakeroot_state.ruid/rgid/euid/egid`（判据用 `g_fakeroot_on`，
   与 `bxroot_fakeroot_ids()` 同一个）。

## ★ 一处与上游的差异，我选择**跟官方而不是跟纯逻辑层** ★

`fakeroot_setgroups()` 带一条 CAP_SETGID 闸门；而**上游 PRoot 对
`setgroups` 是无条件成功**：

```c
/* termux-proot/src/extension/fake_id0/fake_id0.c:1011-1017 */
case PR_setgroups:
        /*TODO: need to really emulate*/
        poke_reg(tracee, SYSARG_RESULT, 0);
        return 0;
```

实测差异：
```
官方 : setuid(999) -> 999/999/999，然后 setgroups rc=0
bxroot(先): 同样状态，setgroups rc=-1 EPERM   ← 不一致
```

处置：**不改** `fakeroot_setgroups()`（纯逻辑层的闸门有测试钉着、
且它是 PRoot setuid 族语义的一部分），而是在**桥接层**（case 7）
直接操作账本 —— 桥接的职责本就是"让 syscall/符号层与官方可观测行为一致"。

## 修后对照（逐行一致）

```
syscall 探针                     官方          bxroot 修后
before  r/e/s                  0/0/0          0/0/0
setgid(144)                    rc=0 errno=0   rc=0 errno=0
setuid(146)                    rc=0 errno=0   rc=0 errno=0
after   r/e/s                  999/999/999    999/999/999      ← 账本自洽
setgroups(0,NULL)              rc=0 errno=0   rc=0 errno=0

真实程序 chage -l root         rc=0 正常输出   rc=0 正常输出     ← ★
```

## 验证

- **判别力**：用 git 镜像的旧 guard 跑同一测试 → **11 条缺口 C 判据全红**
- 单测 `RUN_ID_SYSCALL.sh` → **60 用例 / 0 失败**
- 新增 `test/RUN_PRIVDROP.sh`（6 条判据，含真实程序 `chage` 与账本自洽性），
  已纳入 `RUN_ALL.sh` 第 9f 项
- 回归 **18/18**（既有 17 项一项没红）；门禁零告警

## ★ 副作用（与官方一致，但不是"正确"）★

这些调用"成功"后**内核身份没有真的改变**。对 `chage`/`passwd` 这类工具，
意味着它们会跳过后续权限检查却仍以原身份执行。官方就是这么做的 ——
这是**兼容性取舍**，不是安全建议。已在 `preload.c` 与测试注释中写明。
