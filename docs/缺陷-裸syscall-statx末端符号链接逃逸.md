# 缺陷：裸 syscall(statx/newfstatat) 末端符号链接逃逸到外层命名空间

日期：2026-09-20（第十五轮验收，v12 子代理 `/tmp/relprobe` 探针）
基准版本：`cd8a8f3661a968ee9b86e9c4d381d505`（修复后）

## 症状

同一符号链接路径，两条入口给出**不同结果**：

```
libc stat("absleaf")          → 0 字节   ✅（容器自己的 /etc/hosts）
syscall(SYS_statx,…,"absleaf") → 56 字节  ❌（外层 Android /system/etc/hosts）
```

Ubuntu 24.04 coreutils（`stat`/`ls`/`wc` 全走 statx）全部读到外层数据：

```
stat -c %s D/hosts   → 56   ❌
wc -c < D/hosts      → 56   ❌
cat D/hosts          → 0    ✅
```

v12 实测 `/tmp/relprobe` guest 7/11；修复后 11/11（宿主基准 11/11）。

## 根因（三层叠加，逐层剥开）

### 第一层：前缀翻译其实一直是生效的

`BXROOT_SCG=1` 开 trace 直接证明：

```
[bxroot] syscall_guard: 翻译 a1 /tmp/relprobe.d/absleaf
       -> /data/.../ubuntu/tmp/relprobe.d/absleaf
```

之前多轮怀疑"翻译没生效"是误诊——前缀加上了，问题在后面。

### 第二层：内核替我们跟随了叶子链接

翻译后路径 `<rootfs>/tmp/relprobe.d/absleaf` 交给内核，内核自己
readlink 跟随 `absleaf -> /etc/hosts`，**绝对目标从真实根开始解析**
→ 外层 56 字节。中间组件解析（`bxroot_resolve_intermediate_links`）
只处理路径**中间**的链接，叶子留给调用方 flags —— 对 open 是对的
（O_NOFOLLOW 语义），对 flags==0 的 statx 是**缺口**。

### 第三层：相对路径被门直接挡掉（REL 3 条全 FAIL 的原因）

```
if (looks_like_guest_abs_path(pth)) {      ← pth 是相对名，直接 false
    { 绝对化 }                             ← 永远执行不到
    translate_path(src, …)
}
```

门只认 `p[0]=='/'`，绝对化放在门**内**等于没有。修复：绝对化挪到
门**外**，先得到 `src`（相对→`<cwd>/<path>`），再对 `src` 过门。

## 修法（最终形态：四处协作，顺序是全部问题所在）

1. **`preload.c` 新增 `bxroot_resolve_leaf_links(path, out, size)`**：
   复用 `resolve_symlink_full`（与 libc stat 钩子同一条解析链，含
   ELOOP 环检测），保证 libc 入口与裸 syscall 入口对同一路径给出
   **同一个**最终路径。weak 导出，单测单独编译时缺失即不解析。

2. **`syscall_guard.c`：绝对化移到 `looks_like_guest_abs_path` 门外**。
   门只认 `p[0]=='/'`，绝对化放门内 = 相对路径永远进不来。

3. **叶子解析在 svc 前就地执行，解析前路径留存给 l2s 补丁**。
   这段代码被两次实测逼着重构，完整教训写在代码注释里：
   - v1（解析后改 tbuf，svc 前生效）：普通链接修好了，但 l2s
     结果补丁的 probe 拿到已展开的数据文件 → S_IFLNK 消失 →
     probe 失败 → nlink 停在 1（`/tmp/hl4c` 判决）。
   - v2（解析挪到 svc 后改 args）：l2s 修好了，但普通链接的内核
     结果已在 svc 时写成外层 56 字节，事后改 args 对本次调用无效
     （`/tmp/hlx` 判决，relprobe 9/11）。
   - v3（正解）：svc 前解析到**新槽**，`args[i]` 指新槽（内核见
     展开后路径）；`leaf_pre` 保存解析前的 tbuf，l2s 补丁 probe
     用它（原始链接形态）。两个需求分别服务两类路径。

4. **l2s probe 的 readlink ops 改用裸 `readlinkat`**。
   `bxroot_next_symbol("readlink")`（proroot linker 服务的
   RTLD_NEXT 链）返回的"下一层"**仍会做 l2s 反向重写**：
   `readlink(mid)` 应返回内核真值 `.l2s.a.txt0085.0002`，
   实测返回被改写后的 `'a.txt'` → `l2s_decode_ex` 失败 →
   `resolve_final` 失败 → nlink 补不上（`/tmp/hlh`、`/tmp/hlg`
   对比判决）。裸 syscall 不经任何符号层，内核给什么就是什么。

5. **裸 statx 补丁加懒启用**。
   l2s 是进程级状态：新进程从未 link 过时 `l2s_rt_enabled()==0`，
   补丁第一行就 return。更隐蔽的是**进程内时序**——同一进程里
   先调过 libc stat/lstat（那些钩子挂了懒启用）的话本补丁就
   "看起来正常"。判决（同进程对照）：
   ```
   冷裸 statx         → nlink=1 ❌
   一次 libc lstat 后 → nlink=2 ✅
   ```
   preload.c 的 statx 符号钩子早有同款处理；裸 syscall 这条是
   **最后一个没挂懒启用的入口**。同一句教训第三次应验：判据是
   "客户会走哪条路"，不是"我在哪条路上修过"。

6. **newfstatat(79) 的 flags 在 a3**（a2 是 buf 指针），statx(291)
   的 flags 在 a2 —— 掩码判定不能写统一的 `args[i+1]`。

## 为什么之前几轮反复没修好（方法论教训）

- **误诊一**：以为翻译没生效。开 `BXROOT_SCG=1` 看 trace 五分钟就
  能排除，但之前靠 strace 猜——strace 只能看到最终进内核的路径，
  分不清"没翻译"和"翻译了但内核又跟出去了"。
- **误诊二**：ABS 修好后 REL 仍 FAIL，第一反应是"绝对化没写对"，
  实际是**门的位置**问题。控制流顺序（门在绝对化之前）比内容更容易漏。
- **误诊三（历史回归复述）**：`translate_path(tbuf, tbuf, …)` 同缓冲
  自毁；正确写法源/目标必须分离。本轮把绝对化挪到门外时再次踩到
  `absb` 声明在门内、`SG_SLOT_SIZE` 未定义的编译错——该宏定义在门内
  代码里。教训：**门外的代码不能引用门内定义的宏**。

## 验证

| 探针 | 修复前 | 修复后 |
|---|---|---|
| `/tmp/relprobe`（宿主 11/11） | 7/11 | **11/11**（四遍稳定，含目录复用） |
| `/tmp/accept/accept`（FORTIFY 族） | 13/0 | 13/0 |
| `RUN_L2S_E2E`（l2s 端到端契约） | FAIL（nlink=1） | **PASS**（nlink=2） |
| 冷裸 statx nlink（`/tmp/hluc`） | 1 | **2** |
| `RUN_WARN_GATE` 零告警 | ✅ | ✅ |
| `RUN_ALL` 全量回归 | 24/2 | **25/1**（唯一失败是遗留的
  `RUN_UPSTREAM_CLI`，LD_PRELOAD 死路 + 无官方 runtime，与本修复无关） |

`realpath REL` 曾报 FAIL 是**脏目录残留**：早前旧探针在污染目录里
跑出 `cd_ok` 之后的 `chdir` 状态；`rm -rf /tmp/relprobe.d` 后四遍
全 PASS。探针本身幂等（自建目录），教训：**测前清态**。

## 后续：open64 相对路径缺口（第十六轮验收补充）

v13 验收子代理报告 dash 重定向缺口。定位与修复：

- **症状**：`cd /tmp/relprobe.d && wc -c < absleaf`（absleaf → /etc/hosts）
  返回 56（外层 /system/etc/hosts），而 `open("absleaf")` 返回 0
  （容器内容）。同一文件 open 与 open64 自相矛盾。
- **根因**：dash 的 `cmd < file` 走 **open64** 符号（readelf 实测
  `UND open64@GLIBC_2.17`）。open64 钩子没有 open() 的绝对化前置，
  相对路径 `translate_path` 返回 0 → 落到尾部 else 分支
  `real_open64(path)` 原样透传 → 内核按真实根解析绝对目标。
- **修法**：open64 钩子补 `bxroot_absolutize` 前置（与 open 同款，
  含尾部 else 分支改用 `eff`）。
- **openat64 无此问题**：它走 `resolve_host_path`，内部已含
  绝对化+翻译（本项目"同一功能多入口覆盖不全"的又一例，这次
  是反向——检查后确认无需修）。

修复后：`wc -c < absleaf` = 0（与宿主对照一致），open/open64
两个入口一致。

## 后续2：裸 openat(56) 叶子解析缺口（第十六轮复核补充）

复核子代理用清单外探针（`/tmp/openat_abs.c`）发现：裸
`syscall(SYS_openat, AT_FDCWD, "…/absleaf", O_RDONLY, 0)` 读 56
字节（外层），libc open/open64/stat/statx 全部 0（正确）。

- **根因**：syscall_guard 的叶子解析门控只列了 291/79，openat(56)
  虽有前缀翻译+中间解析，叶子仍由内核跟随 → 绝对目标按真实根
  展开。受影响的只有**不经 libc 符号的静态链接程序**（guard 层
  存在的全部理由——node/libuv 正是）。
- **修法**：need_leaf 判定改为按调用逐条列"flags 在哪、何时跟随"：
  statx=a2==0；newfstatat=a3==0；openat=flags 未置 O_NOFOLLOW(0x800)
  （与 libc openat 语义一致：O_NOFOLLOW 时内核自己看叶子）。

## 后续3：O_NOFOLLOW 语义（第十六轮 v14 验收补充）

v14 验收子代理发现裸 openat+O_NOFOLLOW 语义错误。排查发现**三层**：

1. **O_NOFOLLOW 常量写错**：第一版修 openat 叶子解析时写
   `flags & 0x800` —— 0x800 是 **O_APPEND**，O_NOFOLLOW 实为
   **04000000**（asm-generic/fcntl.h）。判定恒真：客户带
   NOFOLLOW 来看叶子（tar 判断"是不是链接"的标准手法）也被展开，
   内核本应回 ELOOP 却打开了目标。教训：**内核 ABI 常量必须核对
   头文件，不能想当然**。
2. **l2s 的 lstat ops 经 next_symbol 被下一层伪装**（islnk=0）：
   probe 第一步（磁盘真值判定）永远失败。修：`l2s_real_lstat` 改
   裸 `newfstatat(AT_SYMLINK_NOFOLLOW)` —— 与 readlink ops 改裸
   readlinkat 同一原则：l2s 内部 FS 探测一律不经符号层。
3. **l2s_open_path 缺懒启用**：纯读进程里 enabled==0，
   resolve_fake_link 直接 return → O_NOFOLLOW 打开 l2s 链接回
   ELOOP，而官方语义是"客户视角普通文件，应成功"（cp -a 的
   O_NOFOLLOW 打开正是这条路径）。

修复后：O_NOFOLLOW 对 l2s 链接返回数据文件内容（官方语义）；对
用户自己的普通符号链接保持 ELOOP（内核语义）。

## 后续4：O_NOFOLLOW 双语义与 errno 残留（v15/v16 验收补充）

1. **O_NOFOLLOW 常量按架构不同**：v15 验收抓到第二次写错 ——
   aarch64 上 O_NOFOLLOW = **0100000**（0x8000），不是 asm-generic
   的 00400000。对照实验（/tmp/nfo.c）：0100000 → ELOOP（真
   NOFOLLOW）；00400000 → 成功（另一位）。两次写错（0x800、
   00400000）都是"不核对就写数"。
2. **O_NOFOLLOW 双语义**：普通符号链接 → ELOOP（内核语义）；
   l2s 伪造链接 → 成功读数据文件（官方语义，cp -a 的 TOCTOU
   防护路径）。guard 侧 openat+NOFOLLOW 时调
   `l2s_rt_resolve_fake_link` 替换路径（need_leaf 三态：
   1=展开叶子 / -1=l2s 替换 / 0=不动）。
3. **errno 残留（D-2）**：raw_syscall6 成功路径原先不清 errno，
   翻译链上的探测调用留下 EINVAL/EEXIST，客户"成功后查 errno"
   被误导。修：成功路径 `errno = 0`，与 libc 行为对齐。

## 后续5：errno 残留（v16 验收 BXR-16-01）

l2s 翻译路径上成功 open 后 errno 残留 EINVAL。根因：open 家族
"先探后开"模式中，探测 open(q, O_NOFOLLOW) 对 l2s 链接必然 ELOOP，
随后解析+重开成功 —— errno 停在探测/解析链留下的值上。修：open/
open64/openat/openat64 四个钩子的"解析后重开成功"返回点统一
`errno = 0`（与 raw_syscall6 成功清 errno 对齐）。

## 涉及文件

- `src/runtime/preload.c`：`bxroot_resolve_leaf_links` 导出；
  `l2s_real_readlink` 改裸 `readlinkat`；`l2s_real_lstat` 改裸
  `newfstatat`；`l2s_open_path` 加懒启用；open64 钩子补绝对化
- `src/runtime/syscall_guard.c`：绝对化出门；statx/newfstatat/
  openat 叶子解析（svc 前）+ `leaf_pre` 留存；补丁段用 `leaf_pre`
  probe；懒启用；O_NOFOLLOW 常量修正（aarch64 0100000）+ 伪造
  链接替换；raw_syscall6 成功清 errno
