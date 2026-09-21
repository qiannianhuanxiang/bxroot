# 缺陷：`bxroot-run` 未设 `BXROOT_L2S_DIR` → 默认散落布局 → 污染客户目录（git fsck 报错、git clone 失败）

> **状态：已修**（在 `tools/bxroot-run` 里补默认集中目录，与 launcher 的 fallback 对齐）。
> 由**第十一轮验收**（v11）独立发现。

---

## 一、现象（两条，同一个根因）

```
# 1. git fsck 报损坏（15 行），且 .git/objects 下残留内部文件
$ cd /tmp/repo && git init -q . && echo hi > f && git add -A && git commit -qm t
$ git fsck
bad sha1 file: .git/objects/45/.l2s.tmp_obj_5u16b40001.0002
bad sha1 file: .git/objects/45/.l2s.tmp_obj_5u16b40001
bad sha1 file: .git/objects/45/.l2s.tmp_obj_5u16b40001.0002.cnt
...

# 2. git clone 本地路径 100% 失败，且 **rc=0 但目标目录没建成**
$ git clone /tmp/repo /tmp/clone
fatal: failed to copy file to '/tmp/clone/.git/objects/45/.l2s.tmp_obj_5u16b40001.0002':
       No such file or directory
$ echo $?      → 0      ← ★ 脚本无从判断成败 ★
$ ls /tmp/clone → No such file or directory
```

`commit` 本身 rc=0、stderr 0 行 —— 单看提交是"成功"的，
所以这两个症状很容易被当成无关故障。

## 二、根因

bxroot 的 l2s 有两种布局：

| 布局 | 触发条件 | 中间层位置 |
|---|---|---|
| **集中目录** | 设了 `BXROOT_L2S_DIR` | 集中目录，**客户看不见** ✅ 生产选择 |
| **散落** | 未设 | **客户文件旁边** ❌ 客户 `ls -a`/`tar` 都看得到 |

而：

- `launcher.c`（约 1213 行）**只在显式 `--link2symlink` 时**才设
  `BXROOT_L2S_DIR=<rootfs>/.l2s`；
- `tools/bxroot-run` **直接调 bridge，绕过 launcher**，
   于是既没有开关、也没有 fallback。

⇒ **经 `bxroot-run` 跑的 guest 走的全是散落布局**。
l2s 的中间层/数据文件/`.cnt` 落成 `.git/objects/xx/.l2s.*`，
正好落在 git 的对象目录里 —— git 无法区分"运行时产物"与"损坏对象"。

## 三、修法

在 `tools/bxroot-run` 里补默认值（只在未显式设置时兜底，允许覆盖）：

```sh
# ${VAR:-} 而非 $VAR：本脚本跑在 `set -u` 下，直接引用未设变量会以
# "parameter not set" 终止（实测踩到）。
if [ -z "${BXROOT_L2S_DIR:-}" ]; then
    BXROOT_L2S_DIR="$ROOTFS_HOST/.l2s"
    export BXROOT_L2S_DIR
fi
```

与 launcher 的 fallback 语义完全一致（`<rootfs>/.l2s`）。
目录由运行时自建（`l2s_enable_core` 里的 `mkdirat`，EEXIST 视为成功），
不需要调用方准备。

### 为什么不在 l2s 层"清理残留"

残留是**布局的产物**，不是清理不及时。只要布局选错，
下一次 link 又会在客户目录里生成一批。改布局是治本。

## 四、验证

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `git fsck` 输出行数 | 15 | **0** |
| `.git/objects` 残留 `tmp_obj_*` | 有 | **0** |
| `git clone <本地路径>` | **失败**（rc=0、目录未建） | ✅ 成功，内容正确 |
| `git commit` rc / stderr | 0 / 0 | 0 / 0（不变） |
| l2s 单测 | 31/0 | 31/0 |
| l2s e2e | nlink=2 islink=false | 同 |
| accept 探针 | 13/0 | 13/0 |
| 硬链接矩阵 5 场景 | 9/9 | 9/9 |
| stderr 干净 | 0 | 0 |

## 五、方法论

★ **"默认值"也是一种行为契约** ★
l2s 的能力本身一直是对的（两种布局都能跑），
但 `bxroot-run` 这条**入口**没给默认值，于是走了一条
"生产明确不选"的路径 —— 与当初
"`--link2symlink` 被 launcher 解析后丢弃"是同一类故障：
**能力已实现，但入口没接上**。

**检查项**：新增一条入口（脚本/launcher/API）时，
要把它的**默认值**与既有入口逐个对齐 —— 不能只对齐"能力"。
