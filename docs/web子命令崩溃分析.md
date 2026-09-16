# `dsh web` 段错误分析（未解决，但根因已缩小到确凿范围）

> 状态：**未修复**。本文记录已排除的假设与确定的事实，避免后人重复劳动。
> 结论修正：**这不是 `syscall_guard` 的 bug** —— 见第四节。

## 一、现象

| 命令 | 结果 |
|---|---|
| `dsh --version` | ✅ `0.1.5-rc.2` |
| `dsh --help` | ✅ 完整帮助 |
| `dsh web --help` | ❌ **信号 11（SIGSEGV）** |
| `dsh plugin --help` | ⚠️ rc=1 |

官方运行时下 `dsh web --help` **正常**。崩溃时无任何输出（静默）。

## 二、已排除的假设（每条都有实验）

| 假设 | 排除方式 | 结果 |
|---|---|---|
| `pth[0]` 解引用 NULL | 加 `looks_like_guest_abs_path()` | 仍崩 → 非此项 |
| `tbuf` 多线程竞争 | 改 `_Thread_local` | 仍崩 → 非此项 |
| 425 拦截逻辑 | 只留拦截、去掉路径翻译 | rc=1 不崩 → 非此项 |
| 翻译函数本身 | 翻译但**不替换参数** | rc=1 不崩 → 非此项 |
| 参数替换动作 | 替换成**原路径副本** | rc=1 不崩 → 非此项 |
| `syscall_guard` 整体 | 完全不含它的构建 | rc=1 不崩 → **它参与了触发** |

## 三、确定的因果链

逐层二分得到：

```
不含 syscall_guard              → rc=1   不崩
只含拦截、不含路径翻译           → rc=1   不崩
翻译但不替换参数                 → rc=1   不崩
替换成【原路径副本】             → rc=1   不崩   ★关键
替换成【翻译后的路径】           → 信号 11 崩   ★关键
```

**最后两行的对比是决定性的**：两者都执行了"替换地址"这个动作，
唯一差别是**替换进去的字符串内容**。所以：

> 崩溃不是由 `syscall_guard` 的代码缺陷造成的，而是因为
> **翻译后的路径让 node 成功 stat 到了目标**，从而走进了后续
> 一段会崩溃的代码。

对照证据：官方运行时也走同一条路径
（`[proroot-canon] enter: /root/.dsh/profiles/web/.dsh-module-fallback/node_modules`）
且**不崩** —— 说明那段后续代码在官方运行时下是好的。

## 四、崩溃点的位置线索

崩溃前最后处理的路径（`BXROOT_SCG=1` 追踪）：

```
/root/.dsh/profiles/node_modules
/root/.dsh/profiles/node_modules/dunder-proto
/root/.dsh/profiles/node_modules.lock
/root/.dsh/profiles/web/node_modules
/root/.dsh/profiles/web/.dsh-module-fallback/node_modules   ← 最后一个
```

该目录在宿主侧**存在且为空**：

```
ubuntu/root/.dsh/profiles/web/.dsh-module-fallback/
└── node_modules/        （空目录）
```

调用链（来自 dsh 自身的错误栈）指向：

```
healProfilesModuleFallback
  .../dsh-app-boot/lib/index.js:660
composeProfile
  .../dsh/lib/profile-boot-Dk-7KqJc.js:234
```

## 五、下一步

1. 在 `healProfilesModuleFallback` 之后设断点式日志（node 侧 `--require` 注入），
   确认崩溃发生在该函数的哪一步。
2. 怀疑方向：**空目录 + 后续的目录遍历/链接操作**。bxroot 的 l2s 层与
   官方实现不同（中间层用 `.cnt` 旁挂、不改名数据文件），在空目录上可能
   有未覆盖的分支。
3. 用 `dsh web` 之外的入口复现（`dsh --profile web --dump-config`）看是否同样崩。

## 六、本轮顺带修掉的两个真实缺陷

即便崩溃未解决，下面两个修复是实打实的：

### 6.1 `syscall` 层的 NULL 指针解引用

原先写 `pth[0] == '/'`，遇到 `statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...)`
直接段错误。而 **NULL 对内核是合法入参**（翻译成 EFAULT）：

```
statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...) = -1 errno=14(EFAULT)
```

已收敛到 `looks_like_guest_abs_path()` 一处判定。

### 6.2 静态缓冲改线程局部

`syscall()` 会在任意线程被调用，原先的 `static char tbuf[4096]`
在 node 的多线程场景下有竞争风险。已改 `_Thread_local`。
（**注**：实验表明它不是本次崩溃的原因，但它是正确的加固。）
