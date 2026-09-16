# l2s 在真实工具链下的缺陷 —— `tar` 误判与 `lstat` size（待修）

> 状态：**根因已定位，修复进行中**
>
> 这是「proroot 全功能」维度的一个真实缺陷。它不是理论风险 ——
> 实测 `tar` 归档会写出**宿主绝对路径**，`cp -a` 直接失败。

## 现象（同一探针，只换 runtime）

探针做四件事：`dd` 造一个文件 → `ln` 建硬链接 → `ls -l` / `stat` → `cp -a` / `tar`。

### 官方 proroot（**不传 `-L`**）

```
--- ls -l（用 lstat）---
  -rw-------. 2 root root 13 ... a        ← 普通文件、nlink=2、属主 root/root
  -rw-------. 2 root root 13 ... b
--- stat -c %s ---
  a size=13   b size=13
--- cp -a 后的大小 ---
  c size=13                                ← ✅ 成功
--- tar 归档后的大小 ---
  -rw------- root/root  13 ... a           ← ✅ 普通文件
```

### bxroot

```
--- ls -l（用 lstat）---
  -rwxrwxrwx. 2 root 0 66 ... a            ← nlink 对了，但 size=66 ❌
  -rwxrwxrwx. 2 root 0 66 ... b
--- stat -c %s ---
  a size=66   b size=66                    ← stat 路径也是 66 ❌
--- cp -a 后的大小 ---
  （无输出 —— cp -a 失败）                  ❌
--- tar 归档后的大小 ---
  lrwxrwxrwx root/0  0 ... a -> /data/data/com.dsh.client/files/linux/ubuntu/tmp/harm-1/a
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  ❌ tar 把它当【符号链接】归档，且写入了【宿主绝对路径】
```

## 三个后果

1. **归档泄漏宿主路径**（`/data/data/com.dsh.client/files/...`）——
   换台机器解档会指向不存在的位置
2. **`cp -a` 失败**
3. **size 错**（66 = 符号链接目标字符串长度，真实文件是 13 字节）

`size=66` 的来源已确认：宿主路径
`/data/data/com.dsh.client/files/linux/ubuntu/tmp/harm-1/.l2s.a0001` 恰好 64 字符左右。

## 关键结论：官方默认就是对的

**官方在不传 `-L` 的情况下，`cp -a` 与 `tar` 全部正确。**

所以这**不是**「要不要开 `-L`」的问题 —— 而是 **bxroot 的默认行为有缺陷**。

> ⚠️ 这一点我在定位过程中搞错过一次：我曾根据 proot 源码里 `-L` 的注释
> 推断「官方靠 `-L` 才正确」，并据此给子代理下了任务。**官方对照实测推翻了它。**
> `-L` 是 proot 的**可选附加修正**，而官方默认行为本身已正确。

## 根因分析（待子代理实测确认）

两个信号**自相矛盾**：

| 信号 | bxroot 返回 | 官方返回 |
|---|---|---|
| `lstat().st_mode` | `S_IFREG`（普通文件）✅ | 同 |
| `lstat().st_size` | 符号链接目标长度 ❌ | 真实文件大小 ✅ |
| `readlink()` | **成功返回**还原后的客户路径 | 预计 **`EINVAL`** |

`tar` 判断"是不是符号链接"时，看到 `st_mode` 说"普通文件"、但 `readlink` **有结果**
—— 它信了后者，于是按符号链接归档。

**官方为什么没这个问题**：官方的 `readlink(伪造链接)` 很可能返回 `EINVAL`，
与 `S_IFREG` **自洽**。

★ 但 `readlink` 返回还原名是 **`l2s_rt_rewrite_readlink` 的有意设计**
（另一个子代理论证过）。所以这一条**不能贸然改** —— 它涉及两种合理设计取向的取舍：
- 让客户 `readlink` 拿到"看起来正常"的名字（当前设计）
- 与 `st_mode` 自洽（官方做法）

**待实测确认后由多方权衡决定，不由单个 agent 单方面改。**

## 影响范围评估

| 项 | 结论 |
|---|---|
| **DSHA 是否受影响** | **不直接受影响** —— 实测 DSHA 的 `BxrootRuntime` **不传 `-L`**，且它的主路径（`dsh web`、pnpm 安装）不依赖 `lstat` 的 size |
| **proot 用户是否受影响** | **是** —— `tar` / `cp -a` / `rsync` / 任何用 `lstat` size 的工具都会出问题 |
| `-L` 选项 | proot 提供它作为修正开关；bxroot 目前标为"明确拒绝"。**但因为官方默认就对，真正的修法应是让默认行为正确**，`-L` 只是兼容性补充 |

## 为什么此前没被发现

- `test/RUN_L2S_E2E.sh` 只测 `nlink` 与 `S_ISLNK`，**没测 `size`**
- 三个 l2s 缺陷修复时聚焦在"客户能看到普通文件"，`size` 是更细的一层
- 是**用真实工具链（`tar`/`cp -a`）探针**才暴露的 —— 又一次印证：
  **单一入口、单一指标的覆盖不全**（与 `fstatat` 漏接那次同一类问题）

## 追加证据：`readlink` 让 `cp -a` 报 ELOOP

用常用工具逐个实测（bxroot 下）：

```
[readlink]     /data/data/com.dsh.client/files/linux/ubuntu/tmp/tl-1/a
[realpath -s]  /tmp/tl-1/a
[cat]          hello
[cp -a]        /usr/bin/cp: cannot open '/tmp/tl-1/a' for reading:
               Too many levels of symbolic links        ← ★ ELOOP ★
               FAIL
```

**这不是"看起来像自环"，而是下游真的踩到了 `ELOOP`。**

### 一个被推翻的判断

定位过程中我曾认为："`readlink` 返回的看起来像自环，但 `cat` 能正常读，所以只是看起来像。"

**那个判断是错的**：
- `cat` 能读 —— 因为它走 `open`，内核解析时用的是**磁盘真值**
- `cp -a` 失败 —— 因为它**读 `readlink` 的结果再自己解析**，于是踩到 `ELOOP`

所以 `readlink` 返回"指向客户自身的路径"是**真实的功能性破坏**，
不只是"与官方语义不同"。

### 两项缺陷互相加剧

```
cp -a 的判定链：
  ① 看 st_mode  → S_IFREG ✅（l2s 已修好）
  ② 看 readlink → 有结果 → 判定为符号链接 ❌
  ③ 解析该路径 → 自环 → ELOOP ❌
```

`st_size` 与 `readlink` **两者都必须修**。

## PRoot 的权威做法（逐行对照）

根因确认后，我把 PRoot 的 `link2symlink` 实现挖了出来
（`src/extension/link2symlink/link2symlink.c:860-890`）：

```c
intermediate_proc: size = my_readlink(intermediate, final);   // ① 解析到最终数据文件
final_proc:        status = lstat(final, &finalStat);          // ② stat 那个数据文件
                   finalStat.st_nlink = atoi(final + strlen(final) - 4);  // ③ 链长

                   if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
                       sysarg_stat = SYSARG_3;
                   else
                       sysarg_stat = SYSARG_2;

                   read_data(tracee, &statl, ...);              // ④ 读客户原本的
                   finalStat.st_mode = statl.st_mode;           //    保留 mode
                   finalStat.st_uid  = statl.st_uid;            //    保留 uid
                   finalStat.st_gid  = statl.st_gid;            //    保留 gid

                   write_data(tracee, ..., &finalStat, sizeof(finalStat));  // ⑤ ★整体替换★
```

**关键：PRoot 是「整体替换」`struct stat`** ——
把客户的整个结构体换成**数据文件的**，然后只保留 `mode` / `uid` / `gid` 三项。

也就是说 `st_size` / `st_ino` / `st_blocks` / 时间戳**全部来自数据文件**。

### bxroot 为什么错

`src/l2s/l2s-runtime.c` 第 587-590 行的注释写着：

> 注意 st_size/st_ino 的取舍：PRoot 只改 nlink，并把 stat 的其余部分换成数据文件的
> （见 handle_sysexit_end 的 finalStat）。本层采取同样的**最小改动**，只动 nlink
> 与 mode 的 S_IFLNK 位，其余字段保持内核给的值 —— 因为本层**拿不到 data 文件的 stat**
> （那需要一次额外的 lstat，在 **stat 热路径上代价太高**）。

**这段注释里有两处错误**：

1. **事实错误**：「PRoot 只改 nlink」—— 错。PRoot 是**整体替换**，
   注释的后半句「并把 stat 的其余部分换成数据文件的」才是对的。**两句自相矛盾**，
   而实现选择了错的那半句。
2. **取舍判断错误**：说「拿不到 data 文件的 stat」—— **其实拿得到**。
   `resolve_final()` 就在同一个文件里（第 266 行），且 `l2s_rt_patch_stat`
   **已经在调用它**。只差一次 `g_ops->lstat(final, &st)`，而 `g_ops` 里本就有 `lstat`。

至于「热路径代价太高」：那次 lstat 是**必要的** —— 否则客户拿到错误的 size，
后果是 `tar` 写坏归档。而且 **PRoot 自己就付了这个代价**。

### 一个容易踩的坑

`preload.c` 里的调用顺序是：
```c
fakeroot_patch_stat(buf, ...);   /* 先 fakeroot */
l2s_rt_patch_stat(buf, p);       /* 后 l2s */
```

所以 l2s 回填时**不能用 `final_st` 的 uid/gid 覆盖** —— 那会把 fakeroot 的伪装抹掉。
`uid`/`gid` 必须保留**当前 buf 里的值**。

## 复现

```sh
cd /root/proroot-work/agents/rename-bxroot
sh BUILD_RUNTIME.sh
cp build/libbxroot-runtime.so /tmp/bxroot-e2e/
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
       BXROOT_FAKEROOT=1 BXROOT_LINK2SYMLINK=1 BXROOT_GUEST_EXE=/bin/sh
timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 sh \
  --preload "$STAGE_LOAD/libbxroot-runtime.so" "$ROOTFS/bin/sh" "$STAGE_LOAD/sizeharm.sh" \
  2>&1 | grep -vE '^\[NEXT\]|^\[DLADDR\]'
```

探针源码：`/root/probe/sizeharm.sh`
