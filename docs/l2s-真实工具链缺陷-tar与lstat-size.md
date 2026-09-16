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
