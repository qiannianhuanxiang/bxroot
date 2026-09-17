# `pthread_create` 栈哨兵修复报告

- 修复日期：2026-09-17
- 工作副本：`/root/proroot-work/agents/rename-bxroot`
- 改动文件：`src/runtime/preload.c`（定点替换，未整文件重写）
- 新增文件：`test/RUN_PTHREAD_CREATE.sh`、`test/pthread_create_probe.c`
- 结论：**已实现并验证通过**；同时**推翻了调查报告 §2.4 的三条结论**

---

## 0. 一句话摘要

`pthread_create` 在 bxroot 下确实有真实缺陷（128K 档 EINVAL、135168~262143 档
栈真的不够用而 SIGSEGV），**已修好**，修后与官方逐档一致（含压力测试 31/1）。

但**调查报告 §2.4 的机理描述是错的**：所谓"proroot 加载器塞的溢出哨兵"
**根本不存在**，它是 glibc 自己的常态输出；官方那条 `b.eq` 也不是"跳过修正"，
而恰恰是**进入修正流程**。报告给的修法骨架能"碰巧"修好，但**会破坏 guardsize**。
本报告以实测为准，逐条给出证据。

---

## 1. 修前基线（红色）

### 1.1 四档栈大小

```
$ sh run.sh bx $S/libbx-runtime.so $KROOT/root/pthfix/thrprobe
PAGESIZE=4096  _SC_THREAD_STACK_MIN=131072
默认属性           stack=默认 -> pthread_create rc=0 (OK)
默认属性             线程返回 0x1234
PTHREAD_STACK_MIN      stack=显式 -> pthread_create rc=22 (Invalid argument)
最小+4K              stack=显式 -> pthread_create rc=0 (OK)
[exit=139]   ← 256K 档直接 SIGSEGV，连结果都没打印出来
```

官方侧同一探针 **四档全 rc=0**。

### 1.2 真实栈大小（关键：这说明"rc=0"根本不够）

单看返回值会漏判。用 `pthread_getattr_np` 读回线程**真实**拿到的栈：

```
请求       官方真实栈   bxroot 修前
131072     262144        rc=22 EINVAL（未创建）
135168     262144        rc=0 → **135168**   ← 只有 132K！
147456     262144        rc=0 → **147456**   ← 只有 144K！
262144     262144        262144
524288     524288        524288
```

**官方把"小于 256K"的请求一律抬到 256K**；bxroot 不给下限，于是
135168 档"成功"创建了一个只有 132K 栈的线程 —— 调用方随后在深调用链上
撞守卫页就是 SIGSEGV。这才是"135168 → rc=0 但随后 SIGSEGV"的真正原因。

### 1.3 压力测试

```
官方        : STRESS 成功 31 / 失败 1
bxroot 修前 : 迭代 0: pthread_create rc=22 (Invalid argument) → SIGSEGV
```

---

## 2. ★ 逐条更正调查报告 §2.4 ★

报告里的现象每一项我都复现了，但**归因**有三处错误。以下每条都有原始输出。

### 更正 1：「溢出哨兵」不存在，`addr + region == 0` 是 glibc 的常态输出

报告说：

> proroot loader 给线程栈塞了一个**溢出哨兵**：实测
> `size=131072 addr=0xfffffffffffe0000 region=131072`，即 `addr + region == 0`。

**实测：这个值在原生环境（无任何 runtime）里一模一样。**
先把 `pthread_attr_t` 的字段偏移标定清楚（`offsets` 探针，`sizeof=64`）：

```
attr_init                   +16=0x1000
                            getstacksize=8388608 getguardsize=4096 getstack(addr=(nil) region=0)
setstacksize(131072)        +16=0x1000  +32=0x20000
                            getstacksize=131072 getguardsize=4096 getstack(addr=0xfffffffffffe0000 region=131072)
setguardsize(8192)          +16=0x2000  +32=0x20000
                            getstacksize=131072 getguardsize=8192 getstack(addr=0xfffffffffffe0000 region=131072)
setstacksize(262144)        +16=0x2000  +32=0x40000
                            getstacksize=262144 getguardsize=8192 getstack(addr=0xfffffffffffc0000 region=262144)

pthread_attr_setstack(&b, 0x71595e2000, 524288) rc=0
setstack 后                 +8=0x8  +16=0x1000  +24=0x7159662000  +32=0x80000
                            getstacksize=524288 getguardsize=4096 getstack(addr=0x71595e2000 region=524288)
```

即字段布局是 `+16=guardsize`、`+24=stackaddr字段`、`+32=stacksize`。
反汇编 libc 的 `pthread_attr_getstack`（@0x82f20）只有 4 条有效指令：

```asm
82f30: ldp  x4, x5, [x3, #24]     ; x4 = [attr+24] = stackaddr 字段
82f38: sub  x3, x4, x5            ; x5 = [attr+32] = stacksize
82f3c: str  x3, [x1]              ; *addr   = stackaddr - stacksize
82f40: str  x5, [x2]              ; *region = stacksize
```

**`region` 就是 stacksize 本身**，`addr` 是 `stackaddr字段 - stacksize`。
只设过 stacksize 时 `stackaddr字段 == 0`，于是 `addr = -stacksize`、
`region = stacksize`，**和恒为 0** —— 这是 `0 - size + size` 的恒等式，
不是任何加载器塞的东西。（`setguardsize` 不改这个结果，可证与 guard 无关。）

**两侧 attr 的原始 64 字节逐字节相同**（`attrdump` 探针）：

```
=== 官方 runtime ===                    === bxroot runtime ===
setstacksize 后 raw:                    setstacksize 后 raw:
  0000000000000000 0000000000000000       0000000000000000 0000000000000000
  0010000000000000 0000000000000000       0010000000000000 0000000000000000
  0000020000000000 0000000000000000       0000020000000000 0000000000000000
  ...                                    ...
getstack -> addr=0xfffffffffffe0000      getstack -> addr=0xfffffffffffe0000
            region=131072                            region=131072
pthread_create rc=0                      pthread_create rc=22
```

**attr 完全一样，结果却不同** —— 这一条就足以否掉"哨兵导致 EINVAL"的假设。

> 顺带更正源码旧注释的推理：它说"不带任何 bxroot 代码时同样发生
> → 是 proroot 加载器缺陷"。**前提为真、结论为假** ——
> 那个现象在**没有 proroot 的原生环境里同样存在**（见 §3）。

### 更正 2：官方 0x10540 的 `b.eq` 是【进入修正】，不是【跳过】

报告（及源码旧注释）说：

> 官方那条判据恰好会跳过这种情况（`cmn x7,x6 / b.eq`）

**读反了。** 看分支目标 `0x105f4` 的实际代码：

```asm
   10538: ldr  x7, [sp, #136]      ; x7 = region
   1053c: cbz  x7, 105f4           ; region==0 → 105f4
   10540: cmn  x7, x6              ; addr + region == 0 ?
   10544: b.eq 105f4               ; 是 → 105f4
   10548: orr  w27, w23, #0x1
   1054c: cbnz w21, 10600          ; 日志开 → 10600（记日志）
   10550: ldr  x27, [sp, #96]
   10554: ... blr x4               ; ← 这里是【直通】创建
   ; ---- 10650 起的修正段 ----
   105f4: cbz  w21, 1064c          ; 日志关 → 1064c
   1064c: cbnz w23, 10550          ; getstacksize 失败 → 直通
   10650: mov  w0, #0x4b           ; _SC_THREAD_STACK_MIN
   10654: bl   __sysconf
   1065c: lsl  x23, x0, #1         ; 2 × PSM
   10660: mov  x2, #0x40000        ; 256K
   10668: csel x23, x23, x2, cs    ; 取较大者
   10674: b.ls 10550               ; 已经够大 → 直通
   10678: ldp  q29, q28, [x19]     ; 复制整个 attr
   10694: bl   pthread_attr_setstacksize   ; 改副本
   106a0: mov  x19, x27            ; 用副本创建
```

**`0x105f4` 正是落地修正的那条路**：它一路走到 10650 的 `sysconf`/
`csel`/`setstacksize`，最后在 `0x106a0` 把 `x19` 换成副本再创建。
而 `!b.eq`（真显式栈区）分支在 0x10548 记下日志标志后，经
`0x10600 → 0x1064c → 0x10650` **汇入同一段修正代码**。
即：**两条路都做修正**，`b.eq` 只决定"要不要先记日志"。

这条更正一石二鸟：

- 解释了报告作者"逐位照抄官方判据，131072 照样 EINVAL"的原因 ——
  他照抄的那份把 `b.eq` 当成"跳过"，命中后**提前 return 直通**，
  压根没走到修正段（他的 `thrfix2.c` 里那句
  `if (addr && ((unsigned long)addr + region) == 0) return real(...)`
  就是这个误读的产物）；
- 也说明"官方判据无效"这个结论是**误读造成的假象**，不是事实。

### 更正 3：真正的差距是「栈下限」，与哨兵、与加载器都无关

用 `dlopen("libc.so.6")` 绕过一切钩子直调真 `pthread_create`（`bound` 探针）：

```
PSM=131072  guardsize默认=4096
  size=131072  rc=22 Invalid argument
  size=135168  rc=22 Invalid argument
  size=136192  rc=22 Invalid argument
  size=137216  rc=22 Invalid argument
  size=138240  rc=22 Invalid argument
  size=139264  rc=0 OK
```

**原生、官方、bxroot 三侧结果完全一致。** 即 glibc 要求
`stacksize >= PTHREAD_STACK_MIN(128K) + guardsize(4K)` 再对齐到页，
真正下界是 **139264（136K）**。这纯粹是 libc 的既有语义 ——
官方 runtime 也**没有**改掉它（官方 139264 以下一样 EINVAL），
官方只是把 < 256K 的请求**抬到 256K**，于是调用方碰不到那个下界。

**所以官方与 bxroot 的真实差距是：官方给栈下限，bxroot 不给。**
这才是本符号必须补的理由。

---

## 3. 根因与修法

### 3.1 根因

bxroot 原先不导出 `pthread_create`，于是：

| 请求栈 | 官方 | bxroot 修前 |
|---|---|---|
| 131072 | 抬到 262144，rc=0 | **rc=22 EINVAL** |
| 135168~262143 | 抬到 262144，rc=0 | rc=0 但**真的只给那么小** → 深调用链 SIGSEGV |
| ≥262144 | 原样直通 | 一致 |

### 3.2 修法（`src/runtime/preload.c`）

```c
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg)
{
    static int (*real_fn)(...) = NULL;
    ...
    /* 懒解析真实现；★ 命中自己即判为失败（自递归防护）★ */
    if (real_fn == NULL) {
        void *p = bxroot_next_symbol("pthread_create");
        if (p == (void *)(uintptr_t)&pthread_create) p = NULL;
        real_fn = (int (*)(...))p;
    }
    if (real_fn == NULL) return EAGAIN;        /* 官方 0x106fc: mov w23,#0xb */

    if (attr == NULL) return real_fn(thread, attr, start_routine, arg);
    if (pthread_attr_getstacksize(attr, &size) != 0)
        return real_fn(thread, attr, start_routine, arg);   /* 保守直通 */
    if (pthread_attr_getstack(attr, &addr, &region) != 0)
        return real_fn(thread, attr, start_routine, arg);   /* 保守直通 */

    /* ★ 真显式栈区 → 原样转发（判据见 §2 更正 1/2） */
    if (region != 0 && (uintptr_t)addr + region != 0)
        return real_fn(thread, attr, start_routine, arg);

    psm  = sysconf(_SC_THREAD_STACK_MIN);
    want = 262144;
    if (psm > 0 && (size_t)psm * 2 > want) want = (size_t)psm * 2;

    if (size >= want) return real_fn(thread, attr, start_routine, arg);

    memcpy(&clean, attr, sizeof(clean));       /* ★ 复制，不是 init */
    if (pthread_attr_setstacksize(&clean, want) != 0)
        return real_fn(thread, attr, start_routine, arg);   /* 保守直通 */

    rc = real_fn(thread, &clean, start_routine, arg);
    return rc;
}
```

### 3.3 ★ 我对报告 §2.4 修法的两处修正（以实测为准）★

#### (a) 判据不能用 `addr != NULL`

报告骨架写：

```c
int sentinel = (addr != NULL && (uintptr_t)addr + region == 0);
if (!sentinel && region != 0) return real(t, a, fn, arg);  /* 真显式栈区，别动 */
```

由 §2 更正 1，**只要设过 stacksize，`addr` 就非空**（= `-stacksize`），
所以 `!sentinel && region != 0` 这个"直通"条件**永远不成立**
（`sentinel` 恰好抵消了 `region != 0`）→ 每次创建线程都被替换掉 attr。
本实现改用 `region != 0 && addr + region != 0` 作为"真显式栈区"判据，
并已实测真 `pthread_attr_setstack` 的调用方被正确原样转发（见 §4.2）。

#### (b) ★ 必须用 `memcpy` 复制，不能用 `pthread_attr_init` ★

报告骨架（以及我的第一版实现）用 `pthread_attr_init` + `setstacksize`
造"全新 attr"。实测**与官方不等价**：

```
请求 stacksize=128K + guardsize=16384 时的【真实】guard：
  官方      : 真实栈=524288  guard=**16384**  ← 保留调用方的设置
  init 写法 : 真实栈=524288  guard=**4096**   ← 被静默改回默认
  本实现    : 真实栈=524288  guard=**16384**  ← 与官方一致 ✅
```

官方在 `0x10678~0x10690` 是把调用方整个 64 字节**逐字节复制**再只改
stacksize，因此 guardsize 被保留。调用方特意放大 guard 是为了防栈溢出，
被静默改回默认属于"修边缘情况而破坏正常路径"。故改为 `memcpy`。

> 同时更正报告那句"沿用原 attr 会把哨兵 `addr` 一起带过去，等于没修"——
> **这句也是错的**（attr 里没有哨兵）。复制是对的，但理由只是
> "形参是 `const`，不能就地改"。

#### (c) 保留报告正确的两点

- 官方解析不到真实现时返回 **EAGAIN(11)** 而非 `ENOSYS` —— 已保持
  （`0x106fc: mov w23, #0xb`）。
- "必须丢弃原 attr"这个**操作层面**的判断是对的（虽然理由给错了）：
  必须换成只改了 stacksize 的副本，否则 128K 档依然 EINVAL。

### 3.4 `262144` 这个下限值（任务要求实测确认）

- `sysconf(_SC_THREAD_STACK_MIN)` 在本环境返回 **131072**（PAGESIZE=4096），
  故 `2 × PSM = 262144`，与官方硬编码的 `0x40000` **完全吻合**；
  `MAX(2×PSM, 256K)` 的写法也与官方 `10660~10668` 逐位一致。
- 256K 作为下限是恰当的：它是 glibc 真实下界 139264 的约 1.9 倍，
  实测官方抬到 256K 后不再 SIGSEGV，bxroot 修后同样不再 SIGSEGV。
- `sysconf` 失败（返回 -1）时只用 256K，**不能拿 -1 去乘**。

### 3.5 自递归防护（任务点名的坑）

`bxroot_next_symbol` 语义 = `dlsym(RTLD_NEXT)`，调用方必然在本库内部，
本身不会成环；但仍加了两道防线：

1. **显式比对函数地址**，命中自己即判为解析失败 → `EAGAIN`；
2. ★ **刻意不补 `dlsym(RTLD_DEFAULT, …)` 兜底** ★ —— 我第一版写了这个兜底，
   实测它**有害**：
   - 冗余：无 linker 服务时 `bxroot_next_symbol` 已退回 libc 的
     `dlsym(RTLD_NEXT, …)`，RTLD_NEXT 会正确跳过本库命中真 libc；
   - 危险：`RTLD_DEFAULT` 从搜索链**最前面**找，而本库正是 LD_PRELOAD
     最前面那个 → 必然先命中自己，把"本来能解析"的场合变成 EAGAIN；
   - 有副作用：本库的 `dlsym` 是已实现的钩子，调用它会写 dl-error 状态，
     等于为一个兜底去**篡改 `dlerror()` 的内容**。

实测两条路径都不崩（200 轮小栈线程创建全成功）：

```
=== 非 proroot 环境（LD_PRELOAD 直载，无 linker 服务）===
  本程序里 pthread_create ptr = 0x74e0f9c4b0
  来自: .../libproroot-runtime.so        ← 注意：本机 shell 已被官方 runtime 占用
  200 轮小栈线程创建: 成功 200
=== 无自递归崩溃 ===

=== 真机容器（ldso 服务路径）===
  来自: .../root/pthfix/stage2/libbx-runtime.so      ← 正确解析到本库、由内部转发
  200 轮小栈线程创建: 成功 200
=== 无自递归崩溃 ===
```

---

## 4. 修后验证（全部为原始输出）

### 4.1 四档栈大小 —— 修前红 / 修后绿

修前（用私有"删掉钩子"的对照产物 `BXROOT_SO=/root/pthfix/prefixbuild/build/libbxroot-runtime.so`）：

```
--- 用例 1：四档栈大小 ---
   ❌ size=131072  rc=3  RESULT size=131072 真实栈=0 create_rc=22 ret_ok=0 (Invalid argument)
   ❌ size=135168  rc=139  Segmentation fault
   ✅ size=262144  RESULT size=262144 真实栈=262144 create_rc=0 ret_ok=1
   ✅ size=524288  RESULT size=524288 真实栈=524288 create_rc=0 ret_ok=1
--- 用例 2：与官方真实栈大小对照 ---
   ❌ size=131072  官方 [真实栈=262144] != bxroot [真实栈=0]
   ❌ size=135168  官方 [真实栈=262144] != bxroot []
   ❌ size=147456  官方 [真实栈=262144] != bxroot [真实栈=147456]
   ❌ size=262143  官方 [真实栈=262144] != bxroot [真实栈=262128]
   ✅ size=262144  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=524288  官方 真实栈=524288 = bxroot 真实栈=524288
--- 用例 3：压力测试（与官方逐字对照）---
   ❌ 官方 [STRESS 成功 31 / 失败 1] != bxroot [Segmentation fault]

----------------------------------------
❌ 通过 4 / 失败 7
```

修后（默认产物）：

```
$ sh test/RUN_PTHREAD_CREATE.sh
== pthread_create 栈下限修正：A/B 对照 ==
--- 用例 1：四档栈大小 ---
   ✅ size=131072  RESULT size=131072 真实栈=262144 create_rc=0 ret_ok=1
   ✅ size=135168  RESULT size=135168 真实栈=262144 create_rc=0 ret_ok=1
   ✅ size=262144  RESULT size=262144 真实栈=262144 create_rc=0 ret_ok=1
   ✅ size=524288  RESULT size=524288 真实栈=524288 create_rc=0 ret_ok=1
--- 用例 2：与官方真实栈大小对照 ---
   ✅ size=131072  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=135168  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=147456  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=262143  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=262144  官方 真实栈=262144 = bxroot 真实栈=262144
   ✅ size=524288  官方 真实栈=524288 = bxroot 真实栈=524288
--- 用例 3：压力测试（与官方逐字对照）---
   ✅ 官方 [STRESS 成功 31 / 失败 1] = bxroot [STRESS 成功 31 / 失败 1]
----------------------------------------
✅ pthread_create 对照全部通过（11 项）
```

`thrprobe`（报告作者原始的探针）修后：

```
$ sh run.sh bx $S/libbx-runtime.so $KROOT/root/pthfix/thrprobe
PAGESIZE=4096  _SC_THREAD_STACK_MIN=131072
默认属性           stack=默认 -> pthread_create rc=0 (OK)
默认属性             线程返回 0x1234
PTHREAD_STACK_MIN      stack=显式 -> pthread_create rc=0 (OK)
PTHREAD_STACK_MIN        线程返回 0x1234
最小+4K              stack=显式 -> pthread_create rc=0 (OK)
最小+4K                线程返回 0x1234
256K                   stack=显式 -> pthread_create rc=0 (OK)
256K                     线程返回 0x1234
[exit=0]
```

### 4.2 边界回归（证明"没破坏正常路径"）

```
$ sh run.sh bx $S/libbx-runtime.so $KROOT/root/pthfix/thredge
  ✅ attr=NULL                          rc=0 ret=0x1234
  ✅ 默认 attr 不被改动           rc=0 真实栈=8388608 (期望 8388608)
  ✅ 大栈直通不缩水              rc=0 真实栈=524288 (期望 524288)
  ✅ 显式栈区原样转发           rc=0 addr=0x7656b00000 (期望 0x7656b00000) size=524288 ret=0x1234
  ✅ 调用方 attr 未被就地改     rc=0 size=131072 (期望 131072) guard=8192 (期望 8192)
  ✅ 小栈抬升后可用              rc=0 真实栈=524288 guard=16384 (调用方请求 16384)
边界结果: 6 通过 / 0 失败
```

### 4.3 压力测试（连跑 3 次稳定）

```
  第 1 次: 官方[STRESS 成功 31 / 失败 1]  bxroot[STRESS 成功 31 / 失败 1]
  第 2 次: 官方[STRESS 成功 31 / 失败 1]  bxroot[STRESS 成功 31 / 失败 1]
  第 3 次: 官方[STRESS 成功 31 / 失败 1]  bxroot[STRESS 成功 31 / 失败 1]
```

**与官方"31/1"逐字一致**，连"迭代 0 线程结果异常"这一条都一样。
（那 1 个失败是官方本身在该档位的固有语义 —— 第 0 轮
`psm + 0*4096` 返回 0 但线程结果异常 —— 不是我引入的。）

### 4.4 两侧对照（`PROROOT_*` / `BXROOT_*` 各设各的）

```
=== 官方 runtime 的 strings ===
  PROROOT 串数: 43
  BXROOT  串数: 0          ← 官方确实不读 BXROOT_*

=== bxroot runtime 的 strings ===
  PROROOT 串数: 5
  BXROOT  串数: 16
```

现场证明：**只给 bxroot 传 `BXROOT_*`、完全不传 `PROROOT_*`** 也能跑通：

```
$ env -u PROROOT_ROOTFS -u PROROOT_TMP_DIR -u PROROOT_GUEST_EXE \
    BXROOT_ROOTFS=$KROOT ... --preload $S/libbx-runtime.so .../thrprobe
PAGESIZE=4096  _SC_THREAD_STACK_MIN=131072
默认属性           stack=默认 -> pthread_create rc=0 (OK)
PTHREAD_STACK_MIN      stack=显式 -> pthread_create rc=0 (OK)
最小+4K              stack=显式 -> pthread_create rc=0 (OK)
256K                   stack=显式 -> pthread_create rc=0 (OK)
[exit=0]
```

### 4.5 构建与回归

```
$ sh BUILD_RUNTIME.sh
   起始优化   : -O2
   gcc ICE（-O2 第 3 次），重试
   ✅ 链接成功（-O2，第 4 次尝试）
   产物: .../build/libbxroot-runtime.so
   大小: 230024 字节
   导出符号（nm -D --defined-only）: 355
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
```

```
$ sh test/RUN_ALL.sh --quick
======================================================
 回归汇总
======================================================
  ✅ 编译告警门禁       ✅ 零告警（检查了 11 个编译单元）
  ✅ l2s 运行时            RESULT: PASS
  ✅ l2s×fakeroot 协同     RESULT: PASS
  ✅ fakeroot 纯逻辑       RESULT: PASS
  ✅ 系统调用参数位置 RESULT: PASS
  ✅ rename/link 双路径    RESULT: PASS
  ✅ 身份 syscall 伪装    RESULT: PASS
  ✅ crash 崩溃处理器    RESULT: PASS
  ✅ D4 进程管理             断言门禁：通过
  ✅ 运行时构建          ✅ D4 进程管理符号全部导出（复用产物核对）
  ✅ proot CLI 兼容         RESULT: PASS
  ✅ l2s 端到端契约      RESULT: PASS
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/waitid 均已导出
  ✅ dl 家族契约          ✅ dl 家族契约全部通过
------------------------------------------------------
  通过 14 / 失败 0
  ✅ 全部通过
```

> 说明：任务书里写的期望是 **12/12**，实测当前 `RUN_ALL.sh` 是 **14 个步骤**
> （多出"身份 syscall 伪装"、"dl 家族契约"两步）。我核对过：
> 工作副本的 `test/RUN_ALL.sh` 与 git 镜像 `/tmp/bxroot-git` 里的那份
> **逐字节相同**（`run_step` 步骤名清单 diff 为空，均为 27 处/14 步），
> 也就是说这两步在基线里就已经存在，是本轮之前别人加的，
> **不是我为了凑数改的**。我**没有**改动 `RUN_ALL.sh` 的任何判据。

```
$ sh test/RUN_WARN_GATE.sh
  警告集 : -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter
✅ src/runtime/preload.c              0 条
✅ src/runtime/syscall_guard.c        0 条
✅ src/runtime/sigsys.c               0 条
✅ src/runtime/crash.c                0 条
✅ src/runtime/livepatch.c            0 条
✅ src/runtime/fakeroot.c             0 条
✅ src/l2s/l2s.c                      0 条
✅ src/l2s/l2s-runtime.c              0 条
✅ src/launcher/launcher.c            0 条
✅ src/bridge/bridge.c                0 条
✅ src/proc/proc.c                    0 条
---------------------------------------------------------------------
✅ 零告警（检查了 11 个编译单元）
```

### 4.6 并发安全自查（三个 agent 同改 preload.c）

```
grep -c "audit_"   src/runtime/preload.c              = 19
grep -c "audit_open" src/runtime/preload.c            = 9      (判据 >=2 ✅)
nm -D build/libbxroot-runtime.so | grep -c audit_     = 5      (判据 5  ✅)
```

> 关于 `grep -c "audit_" == 5` 这条判据：**基线本来就是 19**（不是 5）。
> 原因是该计数包含注释里出现的 "audit_*"（`audit_open`/`audit_close`/
> `audit_log_*` 等字样），而**导出符号数**才是 5。两条我都贴在上面，
> 修复前后均未变化 —— 我没有碰 audit 相关代码。

`pthread_create` 已导出、`dlsym` 家族未受影响：

```
$ nm -D --defined-only build/libbxroot-runtime.so | grep pthread
000000000000d650 T pthread_create
0000000000018b94 T pthread_sigmask
$ nm -D --defined-only build/libbxroot-runtime.so | grep -E " (dlsym|dlerror|dlopen|dl_iterate_phdr)$"
000000000000cd60 T dl_iterate_phdr
0000000000007f10 T dlerror
000000000000d564 T dlopen
0000000000007f60 T dlsym
```

---

## 5. 交付物

| 文件 | 说明 |
|---|---|
| `src/runtime/preload.c` | 新增 `#include <pthread.h>`；新增 `pthread_create` 钩子；**更正约 5193 行起那段被推翻的长注释**（原文"已回退·不做"→ 改为三条更正 + 本实现说明）；`5193..` 处无任何整文件重写，全部 `edit` 定点替换 |
| `test/RUN_PTHREAD_CREATE.sh` | 新增 A/B 验收脚本（11 项判据，支持 `BXROOT_SO=` 覆盖以复现红色基线） |
| `test/pthread_create_probe.c` | 新增探针（`<size>` 单档读回真实栈 / `--stress` 压力测试） |
| `docs/pthread_create栈哨兵修复.md` | 本报告 |

**未改动**（遵守文件范围）：`src/l2s/`、`src/proc/proc.c`、
`src/runtime/syscall_guard.c`、`src/launcher/launcher.c`、
`test/RUN_ALL.sh` 判据、`test/RUN_WARN_GATE.sh`。

---

## 6. 遗留与建议

1. **报告 §2.4 的机理描述需要更正**（哨兵不存在、`b.eq` 方向读反、
   根因是 glibc 栈下限而非加载器）。本报告 §2 已给出全部反证，
   建议 `docs/高频符号缺口调查.md` 的 §2.4 按本报告更正，
   以免后续有人照着"哨兵"去找一个不存在的 bug。
2. **`test/RUN_PTHREAD_CREATE.sh` 没有接进 `test/RUN_ALL.sh`** ——
   它需要真实的官方库目录（`/data/app/...`），在纯 Ubuntu 容器里不存在。
   接入会让 `RUN_ALL.sh` 在无 proroot 的环境里变红。如需接入，
   建议在 `RUN_ALL.sh` 里按"探测不到就 SKIP"的方式调用。
3. 本环境下 `135168` 档（`psm + 4096`）在**官方与 bxroot 下都会**让
   `thrstress` 的第 0 轮线程返回异常 —— 这是该档位的固有语义
   （请求 132K，被抬到 256K 后线程结果仍异常），**不是缺陷**。
   两边逐字一致，所以保留为"与官方对齐"的证据而非修复目标。
