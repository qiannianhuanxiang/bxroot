# `dsh web` 段错误 —— 排查记录

> 状态：**未解决**，但根因范围已用严格实验压缩到极小。
> 本文记录**已排除的假设**与**确凿的事实**，避免后人重复劳动。
> 同时记录一次我自己的**方法论错误**（把顺序调用误判为递归）。

## 一、现象

| 命令 | 结果 |
|---|---|
| `dsh --version` | ✅ `0.1.5-rc.2` |
| `dsh --help` | ✅ 完整帮助 |
| `dsh web --help` | ❌ **信号 11（SIGSEGV）** |
| `dsh plugin --help` | ⚠️ rc=1（正常报错） |

官方 proroot 运行时下 `dsh web --help` **正常**。

## 二、已修的真实缺陷（本轮产出）

### 2.1 `dlsym` 转发器的无限递归

`preload.c` 里曾有一组 `dlsym`/`dlerror`/`dladdr`/`dl_iterate_phdr`
转发器，写法是：

```c
void *dlsym(void *handle, const char *symbol) {
    static void *(*fn)(void *, const char *) = NULL;
    if (fn == NULL)
        fn = (void *(*)(void *, const char *))dlsym(RTLD_NEXT, "dlsym");
    ...
}
```

**这是必然无限递归**：解析 `RTLD_NEXT` 要调 `dlsym`，而符号解析先命中
我们自己 —— 每层吃一个栈帧直到栈耗尽。

实测证据（core dump）：

```
崩溃 PC = 本 .so + 0x6c44，正是 dlsym 入口
主线程 sp == x29（栈指针追平帧指针 = 栈耗尽）
```

**修法**：不再导出它们。理由：
- 这四个函数**没有路径语义**，没有必须接管的理由；
- 本文件内部有 **144 处 `dlsym(RTLD_NEXT, ...)`** 依赖 libc 原生
  `dlsym`，导出包装器反而污染了主路径；
- 客户 `dlsym(RTLD_DEFAULT, "dlsym")` 依然由 libc 满足。

**效果**：崩溃点从"我们的 dlsym"移走 —— 修复确实生效，但还有第二个障碍。

### 2.2 `statx` 层的 NULL 指针解引用

```c
if (pth[0] == '/')     /* ← NULL 时立即 SIGSEGV */
```

而 **NULL 对内核是合法入参**：

```
statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...) = -1 errno=14(EFAULT)
```

已收敛到 `looks_like_guest_abs_path()` 一处判定。

### 2.3 静态缓冲改线程局部

`syscall()` 会在任意线程被调用，`static char tbuf[4096]` 有竞争风险，
已改 `_Thread_local`。

## 三、一次方法论错误（重要）

我加了这样的诊断：

```c
static _Thread_local int d291;
if (number == 291) { d291++; printf("depth=%d", d291); }
```

输出 `depth=1,2,3,...,400`，我据此判定**"无限递归"**并加了重入守卫。

**但那个结论是错的**：`d291` 只增不减，**顺序调用**也会让它单调递增。
要区分"嵌套"与"顺序"，必须在**函数返回前递减**。

加上线程 ID 后看到真相：

```
[D] tid=21724 depth=1   caller=0x18ac080
[D] tid=21724 depth=2   caller=0x18ac080
...
```

**同一线程、同一调用者、单调递增** = libuv 在模块解析时**连续调用**了
数百次 `statx`，不是嵌套。重入守卫因此**没有**解决问题（但保留它作为
对理论递归的防御，成本可忽略）。

**教训**：计数器的**递减**比递增更重要 —— 只有它才能区分嵌套与顺序。

## 四、严格判决实验（可复现）

用同一份源文件构建三个变体，只改**替换策略**这一处：

| 变体 | 做法 | 结果 |
|---|---|---|
| A | 翻译 + 替换成**翻译结果** | ❌ 信号 11 |
| B | 翻译但**不替换**参数 | ✅ rc=1 |
| C | 替换成**原路径副本** | ✅ rc=1 |

**A 与 C 的唯一差别是替换进去的字符串内容**（都执行了同样的"替换地址"
动作，都用同样的缓冲大小）。所以：

> 崩溃不是由替换动作、指针、缓冲或线程竞争造成的，
> 而是**翻译后的路径内容让 node 走进了更深的代码**。

## 五、已排除的假设（每条都有实验）

| 假设 | 排除方式 | 结果 |
|---|---|---|
| `pth[0]` 解引用 NULL | 加安全判定 | 仍崩 |
| `tbuf` 多线程竞争 | 改 `_Thread_local` | 仍崩 |
| 425 拦截的 errno 不对 | 试 ENOSYS/EINVAL/EPERM/EOPNOTSUPP | 全部仍崩 |
| 425 拦截逻辑 | 只留拦截、去掉翻译 | rc=1 不崩 → 非此项 |
| 翻译函数本身 | 翻译但不替换 | rc=1 不崩 |
| 参数替换动作 | 替换成原路径副本 | rc=1 不崩 |
| **无限递归** | 加 thread ID 后证伪 | **是顺序调用** |
| 追踪日志代码 | 开关 SCG 对照 | 两者都崩 → 无关 |
| 真发系统调用 | 291 一律早返回 | 仍崩 → 在翻译代码内 |
| 路径翻译结果错误 | 与官方逐字节对比 statx 返回值 | **完全一致** |

最后一条尤其说明问题：官方与 bxroot 对同一路径的 `statx` 返回**相同**
（都是 0 / mode 040700），所以差异不在翻译正确性。

## 六、崩溃现场（core dump 分析）

```
si_signo = 11
PC = libc + 0xa2ed0        ← 在 .text 内（合法的 strlen 向量化实现）
x0 = 0xffffffffffffffff    ← strlen((char*)-1)
sp == x29                  ← 栈指针追平帧指针
```

反汇编 `libc+0xa2ed0`：

```asm
a2ec4:  and  x4, x0, #0xfff     ; 页内偏移
a2ec8:  cmp  x4, #0xfe0
a2ecc:  b.hi a2fa4              ; 跨页则走慢路径
a2ed0:  ldp  x2, x3, [x0]       ; ★ 一次读 16 字节（strlen 向量化）
```

即 **`strlen` 收到 `(char*)-1`**。

## 七、下一步

1. 在 `statx` 返回后立刻检查 node 侧的下一步动作 —— 用
   `--require` 注入探针，在 `Module._resolveFilename` 上加日志。
2. 怀疑方向：**翻译后路径让 node 成功 stat 到原本"不存在"的目录**，
   从而进入 `healProfilesModuleFallback` 的某条分支（该函数名出现在
   官方自己的错误栈里）。
3. 可用 `dsh --profile web --dump-config` 复现（不经 web 服务器）。

## 八、诚实的边界

**这个问题我没有解决。** 已确认的是：
- 触发点是 `syscall_guard` 的路径翻译（禁用即不崩）；
- 但翻译结果**本身是对的**（与官方逐字节一致）；
- 崩溃发生在 node 内部，`strlen((char*)-1)`。

我**没有**证明"翻译内容如何导致 node 拿到 -1 指针"这一环。
把它写成已解决是不诚实的。
