# 方法论：本机的"宿主基线"**本身就跑在 proroot 下** —— 会把 proroot 的属性误判成 bxroot 缺陷

> 这是本轮（第十轮）最重要的**方法论**发现，直接影响了此前多轮验收的结论可信度。

---

## 一、事实

本机（开发容器）**不是**干净的宿主：它运行在**外层 proroot** 里。
`/proc/self/maps` 可见：

```
libproroot-bridge.so
libproroot-linker.so
libproroot-runtime.so      ← ★ 外层 runtime 在跑 ★
```

于是所有被我们当作"宿主对照/基线"的命令，**其本身已被 proroot 的
路径翻译层处理过**。已确认受影响的行为至少有：

| 现象 | 真实来源 |
|---|---|
| 宿主 `link()` 成功、返回 `nlink=2` | **proroot 的 l2s 伪装**，不是真硬链接 |
| 宿主 `ln f1 f2` 后 `f2` 读作符号链接 | proroot 把硬链接落成符号链接 |
| 宿主 `realpath(link→/etc)` 的某些差异 | proroot 自己也做绝对链接解析 |
| 宿主 raw syscall 路径下 `errno` 被清零 | proroot 的裸 syscall 处理 |

**没有 `LD_PRELOAD`、`maps` 里也没有 bxroot** —— 所以这不是 bxroot，
而是外层。但它足以让"宿主 vs guest"的对比得出**错误结论**。

## 二、本轮踩到的实例：`tar` 的 ELOOP 假缺陷

### 现象（看起来像 bxroot 的严重缺陷）

```
guest: tar cf t.tar f1 f2
       tar: f2: Cannot open: Too many levels of symbolic links
       tar: Exiting with failure status due to previous errors
```

而 `f1`/`f2` 在目录里 `ls` 显示为普通文件、`stat` 报 `nlink=2`。
看起来是"bxroot 把真硬链接误判成伪造链接"。

### 真相

```
$ cd /tmp/l2sX && tar cf t.tar f1 f2     # ★ 宿主，不经 bxroot ★
tar: f2: Cannot open: Too many levels of symbolic links
```

**宿主报一模一样的错。** 因为：

1. 宿主 shell 里的 `ln f1 f2` **已经被 proroot 的 l2s 接手**，
   磁盘上留下的是 `f2 -> ../../tmp/l2sX/f1`（符号链接）；
2. `tar` 用 `open(..., O_NOFOLLOW)` 打开成员（防止 TOCTOU 的标准做法）
   —— 撞上符号链接 → **ELOOP 是正确行为**；
3. 看到的 `nlink=2`／"普通文件"是 proroot 的**伪装**。

**与 bxroot 无关。**

## 三、危害：这个陷阱会系统性地制造假缺陷与假修复

- **假缺陷**：把 proroot 的属性当成 bxroot 的 bug（本轮 `tar`、
  以及 v9 子代理报的 `errno2` 差异、另有三处它自己排除掉的）；
- **假修复**：更危险 —— 若为"修"这个而改动 bxroot 的 `O_NOFOLLOW`
  语义，会**真的破坏** bxroot 本来正确的行为。

v9 验收子代理独立得出同一结论并明确写下：

> "A plain non-proroot baseline host would remove these false trails —
> highest-value fix to the test setup."

## 四、应对（已落实到本轮流程）

1. **判据升级**：不要问"宿主和 guest 是否一致"，而要问
   **"哪一侧才是正确语义"**。宿主这一侧**也需要被质疑**。
2. **先做宿主自证**：任何疑似缺陷，先在宿主上复现同一条命令。
   宿主也失败 ⇒ 不是 bxroot 的（至少不是它独有的）。
3. **优先使用「语义绝对判据」而非「宿主对照」**。本项目已有先例：
   `/tmp/accept`、l2s 单测用**绝对断言**（`st_nlink` 应为 2、
   `is_link` 应为 false），不依赖宿主基线 —— 这类判据不受本陷阱影响。
4. **注意 proroot 的 l2s 与 bxroot 的 l2s 是两套独立实现**：
   - proroot：中间层放**集中目录**，链接 target 形如 `../../tmp/x/f1`
   - bxroot：中间层放**客户文件旁**（或 `BXROOT_L2S_DIR`），
     带 `.l2s.` 前缀
   两套实现产物的**互操作**不是任何一方的缺陷 —— 测 bxroot 时
   应在**干净目录**里由 guest 自己创建链接，不要复用宿主建好的。

## 五、教训

★ **"对照组"本身也可能是被测系统的一部分** ★
本机把 proroot 当"干净宿主"用了十轮，直到 `tar` 这个假缺陷才暴露。

**结论：没有可信的干净基线时，宁可用绝对语义判据，
也不要拿一个同样被翻译层污染的环境当"真值"。**

---

## 六、实例二：`cp -al` 在本环境**宿主与 guest 都失败**

```
$ cd /tmp/x/src && mkdir -p ../dst && cp -al . ../dst
cp: cannot create hard link '../dst/./sub/f' to './sub/f': Permission denied
```

**宿主（不经 bxroot）报同样的错。**

原因链：
1. 本环境的 `link()` 在 `/tmp` 上被拒（EACCES）—— Android 的
   `protected_hardlinks` / SELinux；
2. proroot 的 l2s 会把硬链接落成**符号链接**（`f -> ../../tmp/x/src/f`
   这种不带 `.l2s.` 前缀的形态）；
3. `cp -al` 再次 `link()` 它 → 被拒；
4. bxroot 的 l2s **不认** proroot 造的链接（判据是 basename 带
   `.l2s.` 前缀），所以也不会接管。

★ 这是**两套 l2s 实现产物互操作**的问题，不是任何一方的缺陷 ★
与本文件第四节第 4 点是同一条判据：**不要复用宿主建好的链接**。

**对验收的影响**：若验收项目用 `cp -al` 做硬链接搬运，
**宿主自身就会失败**，应标注为 ENVN/A 而非 bxroot 缺陷。
由 **bxroot 自己创建**的硬链接（`ln f g`、`ln sub/f sub/g`、
跨目录 ln）在本环境全部可用（已验证 5 场景）。
