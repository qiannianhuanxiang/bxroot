# proroot 容器内「裸相对文件名原地改写」堆溢出缺陷

> **状态**：已定位、已最小化、有完整控制实验。**这是官方 proroot 的缺陷，
> 不是 bxroot 的**（但有间接影响，见下）。
>
> **发现场景**：在 proroot 容器内构建上游开源 proot 时，`make` 稳定
> 失败在 `loader.exe` 规则上。追下去发现根因与 proot 无关，是 proroot
> 自身的一个路径处理缺陷。

---

## 一、缺陷一句话

**在 proroot 容器内，对「不含目录分量的相对文件名」执行"读入→原地写回"
的文件改写工具（`strip` / `objcopy` 等 BFD 系）时，工具进程 100% 死于
`malloc(): corrupted top size`（SIGABRT/SIGSEGV，rc=139）。**

加上任何一个目录分量（`./x`）或改用绝对路径（`/abs/x`）即**完全正常**。

---

## 二、最小复现

```sh
mkdir -p /tmp/repro && cd /tmp/repro
gcc -O0 -o hello -xc - <<'EOF'
#include <stdio.h>
int main(void){ printf("OK\n"); return 0; }
EOF

cp hello x
objcopy x          # ← 崩溃
```

实测输出：

```
malloc(): corrupted top size
[proroot] SIGSEGV pc=0x... lr=0x... fault=0x...6047 code=-6
（寄存器转储 + fp 链回溯）
rc=139
```

### 三行对照（决定性）

```sh
cd /tmp/repro
objcopy x          # rc=139  崩溃
objcopy ./x        # rc=0    正常
objcopy /tmp/repro/x   # rc=0    正常
```

**唯一的自变量是路径形态**。同一目录、同一文件、同一命令、同一时刻。

---

## 三、触发条件（逐条实测锁定）

| 维度 | 触发崩溃 | 正常 | 说明 |
|---|---|---|---|
| **路径有无目录分量** | `x`（裸名） | `./x`、`/abs/x` | ← **唯一的决定性变量** |
| **是否原地改写** | 原地（无 `-o`） | `-o outfile` | 写回原文件才触发 |
| 工具 | `strip`、`objcopy` | `cat`/`cp`/`mv`/`chmod`/`stat`/`wc`/`head`/`gzip`/`readelf` | 只有 **BFD 系原地改写**类 |
| 文件类型 | ELF、**纯文本** 都崩 | — | 崩溃**早于**解析文件内容 |
| 文件名长度 | 1 / 2 / 4 / 8 / 16 / 32 / 48 / 64 字符 全崩 | — | 与长度无关 |
| 文件大小 | 67 KB ~ 308 KB 全崩 | — | 与大小无关 |
| 所在目录 | `/tmp`、`/tmp/*`、仓库目录 全崩 | — | 与目录无关 |
| 出现概率 | **30/30 = 100%** | — | 确定性缺陷，非竞态 |

### 一个容易误判的细节

`readelf -h x` 返回 rc=1 且报 `Error: x: Failed to ...`，但这是**无关的
另一件事**（对 `!` 之类的非常规输入）。真正说明问题的是 `objcopy`/`strip`
**在纯文本文件上也崩** —— 也就是它在读文件内容之前就出事了。

---

## 四、最可能的机制（基于证据的推断，非结论）

BFD 系工具原地改写的典型流程是：

```
open("x", O_RDWR)           ← 拿到 fd
... 读、重建 ...
fstat / ftruncate / fseek / 写回
```

对照实验显示：`open("x", O_RDWR)`、`fstat`、`ftruncate`、`mmap`、
`posix_fallocate` 这些**底层调用单独做都没问题**（见
`/tmp/rp2.c` 探针，19 项全过）。所以触发点不在单个 syscall，而更可能在：

**proroot 对「无目录分量的相对路径」做翻译时，把结果写进了一个
长度估计不足的缓冲区** —— 因为裸名翻译后要多加 rootfs 前缀
（`x` → `<长rootfs路径>/x`），长度增长远大于 `./x` 那种情形带来的差异。
纯文本文件也崩，与"翻译发生在读取之前"一致。

> ⚠️ 这一段是**推断**。能确定的是触发条件（上表），机制未做反汇编确认。
> 若需要坐实，下一步应反汇编 proroot 的路径翻译函数，找那个缓冲区。

---

## 五、对我们（bxroot）的直接影响

### 5.1 它污染过我们的对照实验

本缺陷第一次暴露时的现象是"`strip` 在 proroot 内崩、在 bxroot 下成功"，
看起来像 **bxroot 的优势**。**那是错的** —— 当时的 A 侧用了裸名、B 侧
用了绝对路径，**变量没控住**。

统一成裸名后：bxroot 侧同样 rc=139。原因见 5.2。

**教训**：对照实验里"看起来一边好一边坏"时，先检查两侧的**自变量清单**，
不要急着归因于被测对象。本项目已因此误判过一次（见
`docs/两处控制实验缺陷更正.md`），这是第二次同类失误。

### 5.2 bxroot 也躲不过（因为外层的 ptrace 还在）

bxroot 是 LD_PRELOAD 架构，但**它自己此刻跑在 proroot 容器里**，
外层 proroot 依然 ptrace 跟踪所有后裔进程。所以：

```
$ /tmp/bxroot-bin -r / -w /tmp/bare2 /usr/bin/strip x
[bxroot-launcher] stat(//usr/bin/strip) OK, mode=755, size=203160
malloc(): corrupted top size
[proroot] SIGSEGV ...          ← 注意是 [proroot] 在处理这个信号
rc=139
```

**判据**：崩溃报告的前缀是 `[proroot]` 而不是 bxroot 的任何日志 ——
说明崩在 proroot 的处理链路上，bxroot 无从干预。

推论：**这不是 bxroot 需要"修"的东西**。真要绕开，只能在 proroot 之外
的环境里跑（那时也不存在这个缺陷）。

### 5.3 但它是一条可用的"bxroot 无需 ptrace"佐证

本缺陷在 proroot 侧的表现，反过来给 bxroot 的**架构选择**提供了一个
具体例子：ptrace 方案要在**每条**路径翻译上做内存操作，一处缓冲区
长度算错就影响**所有**被跟踪进程（包括与容器无关的工具）；而
LD_PRELOAD 方案的错误只影响主动加载了 runtime 的进程。

值得记一笔，但**不要**把它渲染成"bxroot 更好" —— 单点证据不足以支撑
架构比较，且 bxroot 有自己的架构级限制（见
`docs/已知限制与架构能力边界.md`）。

---

## 六、对上游开源 proot 构建的影响（实际踩到的）

`tests/GNUmakefile` / `src/GNUmakefile` 的 loader 打包规则：

```make
loader$1.exe: loader/loader$1
	$$(Q)cp $$< $$@
	$$(Q)$(STRIP) $$@        # ← 裸相对名 + 原地改写 = 必崩
```

后果：上游 proot **在本容器内无法按默认方式构建**（`make` 报
`Error 139` / `Deleting file 'loader.exe'`）。

### 两个绕法（都已实测）

**绕法 1：不打包 loader（推荐）**

```sh
cd /tmp/proot-src/src
rm -f execve/enter.o       # 必须删，否则宏不生效（见下）
PROOT_UNBUNDLE_LOADER=/tmp/proot-src/src/loader \
  make -f GNUmakefile -j1 HAS_LOADER_32BIT= proot
```

两个必须同时做的点：

- `HAS_LOADER_32BIT=` 置空：本容器无 `gcc-multilib`，`-m32` 会直接报错
  中断构建（aarch64 上本来也不该编 32 位 loader）。
- `PROOT_UNBUNDLE_LOADER` **必须同时删掉 `execve/enter.o`**：该宏只影响
  `CFLAGS`，而 `enter.o` 若已按"内嵌 loader"编过，就不会重新编译，
  链接时表现为
  `undefined reference to '_binary_loader_exe_start'`。
  ★ 这个坑很隐蔽 —— 报错指向链接器，原因却在"目标文件过期"。

**绕法 2：先手工造出 `loader.exe`**

```sh
cp loader/loader loader.exe && strip loader.exe   # 仍崩，见下
```

对**裸名**无效（就是本缺陷本身）。必须用目录分量：

```sh
cp loader/loader ./loader.exe && strip ./loader.exe   # rc=0
```

即：把 `$(STRIP) $$@` 换成 `$(STRIP) ./$$@` 也能过。但这属于改上游
Makefile，仅在必须打包 loader 时用。

---

## 七、复现脚本

见 `docs/raw/proroot-bare-filename-crash.sh`（自带断言，可直接跑）。

---

## 八、诚实标注：未做的事

- **没有**反汇编 proroot 的路径翻译代码去坐实"缓冲区长度估计不足"
  这个机制推断。本报告给的是**触发条件的完整刻画**，不是根因代码定位。
- **没有**测试 proroot 的其它版本/其它 Android 设备，所以不知道这是
  普遍问题还是本机/本版本特有。
- **没有**穷举所有 BFD 系工具，只测了 `strip` 和 `objcopy`
  （两者都崩），以及 `readelf`（不崩，因为它是只读工具）。
