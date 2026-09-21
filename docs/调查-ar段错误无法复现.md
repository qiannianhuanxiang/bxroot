# 调查：`ar` 在非 `/tmp` cwd 下段错误（**无法复现**，疑为中间调试构建的产物）

> **结论：在当前版本（md5 `0390ef00…`）下无法复现。**
> 报告的原始观察来自一个**中间调试构建**（md5 `407b0669…`），
> 那版含 14 处未清理的调试 `fprintf(stderr, "[dbg] …")`，
> **每一个 stat/open 都打一行**。清理后重测，全部通过。

---

## 一、原始报告（第七轮验收子代理）

```
$ cd /root/bxr-v7 && ar rcs libbxrv7.a src/bxr_path.o src/bxr_probe.o src/bxr_etc.o
malloc(): invalid size (unsorted)
[proroot] SIGSEGV pc=0x78aabac4d8 ... code=-6
make: *** [Makefile:22: libbxrv7.a] Error 139
```

- 报称：非 `/tmp` cwd 下 10/10 失败；`/tmp` 下 0/15 失败
- 后果：**任何含静态库的 C 项目在新目录下 `make` 都会失败**，
  且留下 8 字节的截断 `.a`，静默破坏后续链接
- 子代理的观察还提到 cwd 长度无关、目录年龄无关；
  **同一目录多次运行结果会翻转**（0/10 → 10/10 → 0/10），
  自述"consistent with a genuine race/heap corruption"

★ 注意最后这条 ★ 子代理自己已经注意到**结果会翻转** ——
那是"与某个瞬态条件相关"的强信号，而不是"cwd ≠ /tmp 这条固定规则"。

## 二、本次复核（当前版本）

### 2.1 `ar` 在多个 cwd 下重复测试

```
for d in /root /root/bxr-v7 /usr/bin /var /etc /home /run /tmp; do
    cd $d && ./tools/bxroot-run -- /usr/bin/ar rcs /tmp/art.a /root/artest/a.o
done
```

| cwd | 失败 |
|---|---|
| `/root` | **0/4** |
| `/root/bxr-v7` | **0/4** |
| `/usr/bin` | **0/4** |
| `/var` | **0/4** |
| `/etc` | **0/4** |
| `/home` | **0/4** |
| `/run` | **0/4** |
| `/tmp` | **0/4** |

### 2.1b 扩展 cwd 矩阵（每个 5 次，共 40 次）

```
for d in /tmp /tmp/abc /root /root/bxr-v8 /var /usr/bin /etc /home; do
    cd $d && bxroot-run -- /usr/bin/ar rcs /tmp/art2.a /root/artest/a.o
done
```

**全部 0/5 失败 —— 40/40 通过，cwd 完全无关。**

### 2.2 用真实项目的完整构建压力测试

```
for d in /root/bxr-v7 /root /var /usr/bin; do
  for i in 1 2 3; do
    cd $d && bxroot-run -- make -C /root/bxr-v7 clean
    cd $d && bxroot-run -- make -C /root/bxr-v7
  done
done
```

**12/12 全部成功**（含 `ar rcs` 那一步）。

### 2.3 找不到残留的垃圾文件

子代理提到"dozens of zero-byte `stXXXXXX` litter files"。
`find /root/bxr-v7 /root/artest -name 'st??????'` **无结果**。

## 三、最可能的原因：调试构建

两次观察之间，`src/runtime/preload.c` 里存在 **14 处调试输出**：

```
[dbg] stat: pre p=…        ← 每一次 stat
[dbg] stat: rr=…
[dbg] full: step cur=…     ← 每一层链接展开
[dbg] mid: expand cur=…
[dbg] open: ELOOP q=…
```

这些是修环子代理为定位 ELOOP 环而加的，**未清理就交付**了。
实测它们的量级：一次 `make` 产生**上千行** stderr
（本项目实测输出 2 万余行、约 1.4 MB）。

**它们为什么可能造成 `malloc(): invalid size`**：

- `fprintf` 会走 stdio 缓冲，**内部会 malloc/realloc**；
- 这些调用发生在 **`stat`/`open` 钩子内部** —— 而钩子又被
  glibc 内部（`fopen`、`ld.so`、`malloc` 的某些路径）调用；
- 于是形成"**分配器在被分配器调用期间再次内存分配**"的嵌套。
  glibc 的 malloc 通常能扛住，但在 `ar` 那种大量临时分配 +
  多线程/信号并存的程序里，这种嵌套足以触发堆元数据损坏。

★ 已排除的解释 ★ bxroot **不钩** `malloc`/`calloc`/`realloc`/`free`
（`nm -D` 实测 0 个导出），所以不存在"fprintf → malloc → 钩子 → fprintf"
这一经典死循环。剩下的机制就是上面的**重入式分配**。

## 四、无法 100% 归因的部分

诚实说明：**我没有在旧版本上复现出崩溃**（旧 `.so` 已被覆盖）。
所以"调试 fprintf 导致"是**最可能的解释**，不是已证实的结论。

支持它的证据：
1. 中间版确有高危的调试输出，且量级极大；
2. 清理后 8 个 cwd × 4 次 + 12 次完整构建，**零失败**；
3. 子代理自述"结果会翻转"——与"某次构建恰好带/不带调试输出"吻合。

不支持/存疑：
- 子代理称它也见过**宿主上**（无 bxroot）的 `mkstemp` 探针段错误 ——
  若属实，说明环境本身也有瞬态问题，两者的贡献无法分离。

## 五、留给后人的检查项

若将来再遇到 `ar`/`gcc` 段错误或 `malloc(): invalid size`：

1. **先确认 runtime 是否有调试输出**：
   ```sh
   strings build/libbxroot-runtime.so | grep -c '\[dbg\]'
   ./tools/bxroot-run -- /bin/echo x 2>&1 >/dev/null | wc -l    # 应为 0
   ```
2. 再按 cwd 矩阵复现（本文件 §2.1 的命令）；
3. 只有当"stderr 干净 + 多 cwd 稳定复现"同时成立，才应判定为
   真实缺陷 —— 否则先怀疑调试构建或环境瞬态。

★ 一条通用教训 ★ **调试输出不能留在交付版本里**。
本次它不只是"噪音"：它出现在**每次文件操作**的热路径上，
既污染所有 guest 程序的 stderr，又引入了本文件讨论的堆损坏风险。
修环子代理的修复本身是对的（环已正确返回 ELOOP），
但**没有清理调试代码就交付**，代价是下一轮验收报了 BLOCKED。
