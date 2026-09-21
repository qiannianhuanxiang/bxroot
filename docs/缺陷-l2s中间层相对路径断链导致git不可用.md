# 缺陷：l2s 中间层符号链接的 target 用 cwd 相对路径 → 断链 → **git 完全不可用**

> **状态**：第一环已修（中间层 target 改用 basename）；第二环（`unlink` EINVAL）
> 已定位并交给后续处理。
> **影响**：`git add` / `git commit` 全线失败 —— 这是开发者最核心的工作流之一。

---

## 一、现象

```
$ cd /tmp/go && git init -q . && git config user.email t@t && git config user.name t
$ echo hi > f.txt && git add f.txt && git commit -qm first
fatal: ba856f78f34fcefae5d72ef4aec60e70a52ea4a0 is not a valid object
（rc=128；宿主上同命令 rc=0）
```

`git add` 也静默出错：`git hash-object -w` 打印了哈希，
**但对象文件从未出现在 git 期望的位置**。

## 二、根因（第一环）

这个环境（Android）**不允许真硬链接**，所以 bxroot 的 l2s 层
（link2symlink）把硬链接模拟成三元组：

```
<客户路径>  →  <中间层>  →  <数据文件>
tmp_obj_X      .l2s.tmp_obj_X0001    .l2s.tmp_obj_X0001.0002
```

`l2s_rt_link()` 首次建档时这样建立中间层：

```c
/* 内容搬到 final */
rename(oldpath, final);
/* 中间层 -> final     ← ★ 就在这里 ★ */
symlink(final, mid);
```

**`final` 是 `oldpath` 派生的 cwd 相对路径**：

```
final = .git/objects/45/.l2s.tmp_obj_X0001.0002      ← 相对 cwd
mid   = .git/objects/45/.l2s.tmp_obj_X0001           ← 相对 cwd
```

而**符号链接的 target 是相对"链接所在目录"解析的**，不是相对 cwd。
于是内核把它拼成：

```
<mid 所在目录>/.git/objects/45/.l2s.tmp_obj_X0001.0002
= /tmp/go/.git/objects/45/.git/objects/45/.l2s...0002
                        ^^^^^^^^^^^^^^^^^^^^^ 多了一层 → 必然断链
```

**触发条件**：**cwd ≠ 链接所在目录**。git 正是如此 ——
cwd 是仓库根，而对象写在 `.git/objects/xx/` 下。

### 为什么宿主上看不出来

宿主有真硬链接，**根本不走 l2s**。这个缺陷只在
"必须模拟硬链接"的环境（Android/bxroot）暴露。

## 三、第一环的修法

`final` 与 `mid` 由 `l2s_make_paths_ex()` 保证**恒同目录**
（`final = mid + ".<NNNN>"`，见 `l2s.c`），所以 target 只需 **basename**：

```c
const char *fbase = strrchr(final, '/');
fbase = (fbase != NULL) ? fbase + 1 : final;
symlink(fbase, mid);
```

★ 用 basename 而非绝对路径 ★ 更稳：绝对路径会让中间层在
rootfs 迁移/挂载点变化后失效；basename 天然免疫 cwd 变化。

**验证**：修复后中间层为
`.l2s.tmp_obj_TuL1H10001 -> .l2s.tmp_obj_TuL1H10001.0002`（正确，不含目录前缀）。

## 四、第二环：`.cnt` 按 **cwd** 解析（已修）

修完第一环后错误变了：

```
warning: unable to unlink '.git/objects/ba/tmp_obj_TuL1H1': Invalid argument
```

`Invalid argument` = **EINVAL**，来自 `l2s_rt_unlink()` → `read_nlink()`。

### 根因（由第十轮复核子代理用**判决性实验**钉死）

`read_nlink()` / `write_nlink()` 拿 `final` 拼出 `<final>.cnt`，
再经 `l2s_real_read_small()` / `write_small()` 用**裸
`syscall(SYS_openat, AT_FDCWD, p, …)`** 打开 —— 既不翻译 rootfs，
**也不按 mid 所在目录锚定** ⇒ **按进程 cwd 解析**。

git 的 cwd 是仓库根，而对象在 `.git/objects/xx/` 下 ⇒ 读不到 `.cnt`
⇒ EINVAL。

**判决性实验**（cwd 放同名 decoy）：

```
cwd=/tmp/piw,  文件在 sub/
  BEFORE: cwd/.l2s.tmpX0001.0002.cnt = 9      sub/.l2s.tmpX0001.0002.cnt = 2
  unlink("sub/tmpX") rc=0
  AFTER : cwd/...cnt = 8   ★ l2s 减的是 cwd 里那个 ★
          sub/...cnt = 2   （真文件没动）
```

对照：把 cwd 换成 mid 所在目录 → 立刻 `rc=0`。**cwd 是唯一变量。**

### 修法

在 `resolve_final()` **出口**统一锚定：target 是相对名时，用 **mid 的
dirname** 拼成可解析路径再返回。这样 6 个调用点全部受益。

★ 一并修掉的自我回归 ★ 我在 `probe_fake_link()` 里也加过锚定，
但那里 `path` 已是翻译后的绝对路径、`target` 可能也已是绝对路径
（readlink 钩子做过反向翻译）⇒ **双重锚定**，产出
`<rootfs>/tmp/x/<rootfs>/tmp/x/.l2s.a0002` → `resolve_final` 失败 →
**st_nlink/st_mode 的伪装完全不发生**。诊断输出一眼可见：

```
PSDBG mid=<rootfs>/tmp/l2sx//data/data/.../tmp/l2sx/.l2s.a0002
PSDBG resolve_final FAILED
```

判据：**只在 target 确实是相对名时才锚定**（`strchr(target,'/')==NULL`）。

## 四之二、第三环：`stat()` 传了"解析后"的路径（已修）

`stat()` 会先经 `stat_pre_resolve()` 把符号链接**解析到底**，
于是传给 `l2s_rt_patch_stat()` 的 `p` 已是**数据文件**路径
（`.l2s.x0009.0002`）—— 那是普通文件，`probe_fake_link()` 正确地
判定"不是伪造链接"，patch 于是静默不发生：

```
stat(a)  → nlink=1  size=64   ❌（内核给的是符号链接的元数据）
lstat(a) → nlink=2  size=5    ✅
```

**同一个路径 stat 与 lstat 给不同答案**本身就是缺陷（e2e 测试一直报这条）。

**修法**：patch 传**客户视角的路径**（`translated`），而不是我们自己
解析后的内部路径 —— l2s 要回答的正是"**客户眼中的这个路径**是不是
伪造链接"。`stat` 与 `stat64` 两处都改。

## 四之三、第四环：`.cnt` 归零后未删（已修）

回收了中间层与数据文件，却把 `<final>.cnt` 留在原地。后果：
`git fsck` 报 `bad sha1 file`（宿主 0 条）、下次同 basename 重建链时
读到脏计数、磁盘泄漏。

**修法**：归零分支里一并 `unlink(cnt)`，**忽略返回值**（ENOENT 是正常的，
且不该让"主体已回收"的 unlink 报失败）。

## 四之四、第五环：`syscall_guard.c` 单测链接失败（已修）

我给裸 syscall 层加的链接解析桥 `bxroot_resolve_intermediate_links()`
定义在 `preload.c`，而若干单测**单独编译 `syscall_guard.c`**
（`test_syscall_guard.c` / `test_rename_link_argpos.c` /
`test_id_syscall_guard.c`）⇒ `undefined reference`。

**修法**：`syscall_guard.c` 用 **weak 声明** + 调用前判空 ——
与 `proc.c` 引用 `bxroot_translate_path`/`bxroot_log` 是同一模式，
项目已有先例。缺失时语义 = "不做额外解析"（即修复前行为），安全。

## 五、方法论：为什么这个缺陷躲过了前八轮验收

前八轮的验收子代理都在测"**符号链接语义**"（stat/lstat/errno/绝对链接…），
没有一个测过"**需要硬链接的真实应用**"。

而 l2s（link2symlink）恰恰是 bxroot 在 Android 上**最核心的适配层** ——
因为它模拟的正是"内核不给你硬链接"这件事。

★ 教训 ★ **真实项目验收必须包含依赖硬链接的工具**。
`git` 是最典型的：它的对象存储用 `link()` 做去重，
用 `tmp_obj_*` + `rename()` 做原子写。这类"协议级依赖"比
单个 syscall 的返回值更难被发现，也更致命。

**后续验收清单应加入**：
```sh
git init/add/commit/log/status/diff/checkout    # 硬链接 + rename 协议
tar czf/xzf with hardlinks                       # 归档保留硬链接
cp -al  (archive link 模式)                       # 批量硬链接
```

---

## 五、第一环的**另一半**：`symlink(mid, oldpath)` 漏改（第十轮验收抓出）

第一环我修了「中间层 → 数据文件」那一处（`symlink(use, mid)`），
但**「客户路径 → 中间层」是另一个调用点**，当时没一并处理：

```c
/* 客户路径 -> 中间层，此时 oldpath 已经空出来。 */
symlink(mid, oldpath);      /* ← ★ mid 含目录，又是断链 ★ */
```

```
cd /tmp/lf && ln d1/a d1/b
  oldpath = d1/a       mid = d1/.l2s.a0001
  symlink("d1/.l2s.a0001", "d1/a")
  ⇒ 内核按**链接所在目录**（d1/）解析 target
  ⇒ d1/a -> d1/d1/.l2s.a0001    ★断链★
```

**症状极具迷惑性**：`link()` 返回 rc=0，**新名字 b 能读**，
而**原始名字 a 读不了**（ENOENT）—— 看起来像数据丢失。
只有**不含目录**的相对名（`ln a b`）恰好正确，所以测试容易漏。

**修法**：`oldpath` 与 `mid` **恒同目录** ⇒ target 就是 basename，
用 `l2s_relpath(mid, oldpath, …)` 统一处理（与第一环同一判据）。

**验证矩阵**（guest，全部应与宿主一致）：

| 场景 | 修复前 | 修复后 |
|---|---|---|
| `ln f g`（无目录） | ✅（碰巧对） | ✅ |
| `ln sub/f sub/g` | ❌ **f 断链** | ✅ 两个都能读 |
| `ln d1/f d2/g`（跨目录） | ❌ **f 断链** | ✅ |
| `cp -al src dst` | ❌ **src/a 断链** | ✅ |
| `cp -al` 深层 | ❌ | ✅ |

## 六、l2s 的**读路径懒启用**（第十轮自主发现）

`l2s_rt_enabled()` 是**进程级**状态，原先只在 `link()` 失败时置位。
后果：**任何只是"读"的新进程**都看不到伪装：

```
# 进程 A：建硬链接（触发 l2s 启用、留下 .l2s.* 产物）
$ echo A > f1 && ln f1 f2

# 进程 B：只是读（从未 link 过 → l2s 未启用）
$ ls -l f1 f2
lrwxrwxrwx f1 -> .l2s.f10001    ← ★客户看到内部名字★
$ stat -c '%h %F' f1            → 1 symbolic link     ❌
$ tar cf t.tar f1 f2            → 按符号链接归档       ❌
```

影响面：`ls -l` / `stat` / `tar` / **任何读既有 l2s 产物的新进程**。
（同进程内先 link 过的情形是对的——这正是它躲过多轮测试的原因：
验收探针往往在同一进程里做完 link+stat。）

**修法**：读路径懒启用。检测到路径最终目标带 `.l2s.` 前缀 →
`l2s_enable_core()`。挂点：stat 家族、readlink 家族。
普通文件一次 `lstat` 即返回，**零额外内核往返**。

`readlink` 上挂懒启用还有一层原因：`ls -l` 会**先 readlinkat 判断**
"是不是符号链接"。不接的话，`ls` 先看到中间层目标 → 认定是链接 →
**直接打印内部名**，stat 家族的伪装根本没机会生效。
（实测：只挂 stat 时 `ls -l` 仍错、C 探针对；两个都挂后一致。）

## 七、散落布局的 `git fsck` 噪音（说明，不修）

无 `BXROOT_L2S_DIR` 时中间层在客户文件旁边，`git fsck` 会报
`bad sha1 file: .l2s.*`（**rc=0**，警告级）。这是**布局固有**：
git 无法区分"对象目录里的非对象文件"是运行时产物还是损坏。

生产走 `BXROOT_L2S_DIR`（集中目录），实测：

```
commit-rc=0  stderr=0  residue=0  fsck 干净
```

与参考实现一致，不作为缺陷。

## 八、终态验证（全部通过）

| 检查 | 结果 |
|---|---|
| 硬链接矩阵 5 场景 × 2 个名字 | ✅ 9/9 可读 |
| git 生产模式（rc/stderr/residue/fsck） | ✅ 全净 |
| l2s 单测 | ✅ 31/0 |
| l2s e2e（nlink=2 islink=false size=5） | ✅ |
| accept 探针 | ✅ 13/0 |
| 全量回归 | ✅ 24 通过 / 1 失败（既有项） |
| 告警门禁 | ✅ 零告警 |
| stderr 干净 | ✅ 0 行 |
