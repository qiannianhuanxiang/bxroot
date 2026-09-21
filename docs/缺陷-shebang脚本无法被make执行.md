# 缺陷：`make` 无法执行 `#!` 脚本配方（execveat / posix_spawn 两条路都漏）

> **状态：已修复。** 由**独立测试子代理**发现并定位，修在两处。
> `/usr/bin` 下 568 个文件里 **93 个是 `#!` 脚本**（`which`、`ldd`
> 都在其中），所以这不是边角情形。

---

## 一、现象

```makefile
# Makefile
all:
	./gen.sh            # gen.sh 是 #!/bin/sh 脚本
```

```sh
$ make
loader: reject ./gen.sh: bad read
proroot-ldso: failure rc=5
make: *** [Makefile:2: all] Error 2
```

**最误导人的一点**：加个元字符就正常 ——

```sh
$ printf 'all:\n\t./gen.sh && true\n' > Makefile && make
GEN-SH-RAN            # 通过
```

也就是说**只有"直接执行"那条路坏**，而报错信息
（`bad read`）指向**脚本本身**，完全没提真正的原因。

## 二、根因：两条独立的路都漏了

### 2.1 `posix_spawn` 路径没有 shebang 重写

GNU make 对**不含元字符**的配方会**短路**：不经过 shell，
直接 `posix_spawn` 那个脚本。而 bxroot 的结构是：

| 路径 | shebang 重写 |
|---|---|
| `px_do_execve`（execve/execvp/execvpe） | ✅ 有 |
| `px_do_spawn`（posix_spawn/posix_spawnp） | ❌ **没有** |

于是脚本被原样交给 linker，linker 只认 ELF，读文本就报 `bad read`。

**为什么加元字符就好了**：`&&` 迫使 make 走 `/bin/sh -c`，
而那条路最终落到 `execve` → 有 shebang 重写。

### 2.2 顶层启动没有 shebang 支持

`bxroot-run` 是**启动** guest 的入口，而 bxroot 的运行时是
**被启动的那个进程**加载的 —— 所以 bxroot 内部的 shebang 重写
在这一步**帮不上忙**（它只能管进程内发起的 exec）。

实测触发的常见命令：

```sh
$ bxroot-run -- /usr/bin/which gcc
proroot-ldso: failure rc=22
$ bxroot-run -- /usr/bin/ldd --version
proroot-ldso: failure rc=22
```

两者都是 `#! /bin/sh` 脚本（`which` 甚至是指向
`which.debianutils` 的**绝对目标符号链接**）。

## 三、修法

**3.1 `px_do_spawn` 加 shebang 重写**（`src/proc/proc.c`）

复用现成的 `px_rewrite_shebang()`，不复制判据：

```c
sb_rc = px_rewrite_shebang(host, path, argv, ...);
if (sb_rc > 0) { px_cfg_str(host, ..., sb_host); argv = sb_argv; }
```

放在**链接展开之后**（解释器路径也要翻译；且脚本本身可能是绝对链接）。

★ 一个必须注意的坑 ★ `sb_argv` **必须声明在函数作用域**，不能放块内 ——
`argv` 会被重定向到它并一直用到函数末尾。放块内就是野指针，
症状是"偶发读到垃圾 argv"。这与 `px_do_execve` 里同名变量的教训
完全一样（**gcc 的 `-Wdangling-pointer` 正是抓这个的**，
本项目的告警门禁是零容忍，所以第一次编译就被拦下了）。

**3.2 `bxroot-run` 顶层脚本改写**（`tools/bxroot-run`）

读第一行取解释器，按内核语义构造 argv：

```
[interp, script, 原argv[1..]]
```

实测 argv 语义正确（与内核一致）：

```sh
$ bxroot-run -- /tmp/sr/args.sh A B C
argc=3 args=[A B C]
```

## 四、验证

| 命令 | 修复前 | 修复后 |
|---|---|---|
| `make`（脚本配方） | ❌ `bad read` rc=5 | ✅ `GEN-SH-RAN` rc=0 |
| `make`（脚本配方，绝对路径） | ❌ rc=5 | ✅ rc=0 |
| `bxroot-run -- /usr/bin/which gcc` | ❌ rc=22 | ✅ `/usr/bin/gcc` |
| `bxroot-run -- /usr/bin/ldd --version` | ❌ rc=22 | ✅ 打印版本 |
| 脚本 argv 透传 | — | ✅ `argc=3 args=[A B C]` |
| `make`（ELF 配方） | ✅ | ✅（未回归） |

回归：`test/RUN_ALL.sh` 各步通过；D4 单跑 **117 cases / 904 checks /
PASS**；告警门禁零告警。

## 五、方法论

**这个缺陷是"独立测试者"发现的，不是作者发现的。** 值得记下来：

- 作者视角容易测"我设计的路径"（`execve`、`posix_spawn` 我实现了）；
- 独立测试者**真的去写一个 Makefile 并用脚本配方**，于是撞上
  "我没想到的那条路"；
- 而且它还**继续往下定位到 `execveat` / `posix_spawn` 这一层**，
  没有停在"报错了"。

这正是"派子代理去真做一个项目"这个验收方式的价值 ——
**设计者的测试覆盖不到自己没想到的用法**。


---

## 六、续：顶层裸名启动的 PATH 搜索（易用性补齐）

修完 shebang 之后发现一个相邻的易用性问题：

```
$ bxroot-run -- python3 -c '…'
bxroot-run: python3: No such file or directory      # 之前
proroot-ldso: failure rc=2                          # 更早
```

裸名（不含 `/`）直接交加载器必然失败。普通 shell 会去 PATH 里找，
包装脚本也应当如此——已补（`tools/bxroot-run` 的裸名分支）：

- 按 rootfs 内实际存在的标准目录逐个探测（存在且可执行才用），
  对齐 `px_resolve_exec_path` 的语义；
- 找不到时给出人话：`<name>: command not found (searched guest PATH)`，
  **退出码 127**（与 shell 一致；之前是 rc=2 + 一句加载器黑话）。

验收：`bxroot-run -- python3 …`、`-- gcc …` 等裸名全部可用；
绝对路径与 shebang 路径不受影响。
