# 缺陷：l2s 集中目录未做正向翻译 → 容器视角入参时建档失败（`nlink` 恒为 1）

> **状态：已修**（`l2s_enable_core()` 把翻译结果回写 `cfg.l2s_dir`）。
> 由第十一轮诊断子代理用 strace 钉死根因，第十二轮修复。

---

## 一、现象

```
$ BXROOT_L2S_DIR=/tmp/l2sp3 ./tools/bxroot-run -- /tmp/hl2/t
stat : nlink=1 islink=0 size=5      ← 期望 nlink=2
lstat: nlink=1 islink=0 size=5
```

而**不设** `BXROOT_L2S_DIR` 时同一个二进制给出正确的 `nlink=2`。

## 二、根因（strace 判决性证据）

```
mkdirat(AT_FDCWD, "/data/data/.../ubuntu/tmp/l2spI", 0700) = 0
                  ^^^^^^ 已翻译 → 成功
renameat(AT_FDCWD, ".../hl2/a", AT_FDCWD, "/tmp/l2spI/.l2s.a0001.0002") = -1 ENOENT
                                          ^^^^^^^^^^^^ 未翻译 → ENOENT
```

**同一进程、同一时刻**：mkdir 用翻译后的路径建好了目录；
rename 却打到另一个（不存在的）目录。

### 病根

`src/runtime/preload.c` 的 `l2s_enable_core()`：

```c
cfg.l2s_dir = getenv("BXROOT_L2S_DIR");     /* 容器视角 */
...
if (cfg.l2s_dir != NULL) {
    char mkdir_path[MAX_PATH_LEN];
    const char *target = cfg.l2s_dir;
    if (translate_path(cfg.l2s_dir, mkdir_path, ...) > 0)
        target = mkdir_path;                 /* ★ 只给 mkdir 用，没回写 ★ */
    syscall(SYS_mkdirat, AT_FDCWD, target, 0700);
}
l2s_rt_init(&L2S_OPS, &cfg);                 /* ★ 仍是容器视角 ★ */
```

而 l2s 层全部经 `L2S_OPS`（`l2s_real_rename/symlink/lstat/readlink`，
都是裸 syscall 或 dlsym 拿真符号，**不做任何翻译**）落盘。
`preload.c` 自己的注释就写着"l2s 层拿到的是已经翻译过的宿主路径" ——
于是拼接出的 `mid`/`final` 是容器视角 → 内核按真实根解析 → ENOENT。

### 对照实验（同一二进制，只换视角）

| `BXROOT_L2S_DIR` | 结果 |
|---|---|
| 不设（散落） | `nlink=2` ✅ |
| `/tmp/l2spA`（容器视角） | `nlink=1` ❌ |
| `<rootfs>/tmp/l2spB`（内核视角） | `nlink=2` ✅ |

## 三、修法

**翻译一次，两处共用，把结果回写 `cfg.l2s_dir`**（功能改动 5 行）：

```c
char l2s_dir_buf[MAX_PATH_LEN];   /* ★ 函数作用域 ★ */
if (cfg.l2s_dir != NULL) {
    if (translate_path(cfg.l2s_dir, l2s_dir_buf, sizeof(l2s_dir_buf)) > 0)
        cfg.l2s_dir = l2s_dir_buf;
    syscall(SYS_mkdirat, AT_FDCWD, cfg.l2s_dir, 0700);
}
```

★ **缓冲区必须在函数作用域** ★ `l2s_rt_init` 做的是
`g_cfg = *cfg` **浅拷贝、不 strdup**，而 l2s 层每次
link/unlink/stat 都读 `g_cfg.l2s_dir`。块作用域会悬垂。

### 为什么没有"客户视角"的反向需求

逐处核对确认 `l2s_dir` 是**纯内部磁盘布局参数**，从不需要呈现给客户：
- 拼 `mid`/`final` → 交给 `g_ops`（裸 syscall）→ 必须内核视角；
- `l2s_decode_ex` 的 `strcmp(dir, l2s_dir)` 判等 → 两边同改后依然自洽
  （改前反而是视角混用）；
- 唯一"给客户看名字"的出口 `l2s_rt_rewrite_readlink` 用的是
  basename 解析出的 `orig_name`，与 `l2s_dir` 无关。

## 四、这是实现缺陷，不是"用法要求"

有人可能认为"集中目录要求调用方传内核视角路径"。**不是**：
`l2s_enable_core` 自己就对 mkdir 做了翻译，注释明确写着
"否则会把目录建到宿主视角的路径上" —— 说明作者意图是**接受容器视角入参**，
只是翻译结果漏了回写。

## 五、风险与验证

- **散落布局零影响**：`l2s_dir == NULL` 时整块不执行；
- **已传内核视角的调用方零影响**：`translate_path` 幂等
  （launcher 默认 `cfg.rootfs` 即内核视角、`RUN_L2S_E2E.sh` 同）；
- 唯一受影响的就是原先坏掉的那条。

| 场景 | 修复前 | 修复后 |
|---|---|---|
| 容器视角 `/tmp/l2spX` | `nlink=1` ❌ | **`nlink=2`** ✅ |
| 内核视角 `<rootfs>/tmp/...` | `nlink=2` | `nlink=2` ✅ |
| 默认（`<rootfs>/.l2s`） | `nlink=2` | `nlink=2` ✅ |
| 显式清空（真散落） | `nlink=2` | `nlink=2` ✅ |

strace 佐证：修复后 `renameat` 目标已带 rootfs 前缀并返回 0，
三条 symlink 全部发生。

## 六、补的测试

`bxroot-run` 兜底后，**"不设 `BXROOT_L2S_DIR`"已不再走散落布局**，
散落这条端到端路径失去覆盖（只剩注入内存 FS 的单测在测，
而那条路径与真实 stat 钩子不同、测不出布局问题）。

因此新增 `test/RUN_L2S_SCATTERED.sh`：显式清空 `BXROOT_L2S_DIR`
强制走散落布局，再验一次硬链接契约，并挂进 `RUN_ALL.sh`。
已做负控（把期望改成 `nlink==3` → FAIL），确认它真能检出缺陷。
