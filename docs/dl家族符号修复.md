# dl 家族符号修复：`dlerror` 与 `dl_iterate_phdr`

- 修复日期：2026-09-17
- 修改文件：`src/runtime/preload.c`（定点 edit，**不整文件重写**）
- 新增文件：`test/dltest.c`、`test/RUN_DL_TESTS.sh`、`test/RUN_ALL.sh` 新增一项（**只增不改判据**）
- 产物：`build/libbxroot-runtime.so` md5 `9401ddb2b650930803bd31cc2ee08a41`
- 官方对照：`work/parity/off/libproroot-runtime.so` md5 `f14a074b41afb0424145f2c39401a1cc`
- 探针目录：`/root/dlfix/`（= `<ROOTFS>/root/dlfix/`，§0.1 的同一 inode 关系）

> **★ 关于产物 md5（并发编辑说明）★**
> 本任务进行期间**有其它 agent 在同时改 `src/runtime/preload.c`**（已被告知）。
> 上表是**最终冻结状态**的 md5。修复完成后的基线验证用
> `e51ad038b5b4bec62ecc40a20797e292`；此后另一个 agent 回退了它的
> `pthread_create` 钩子，md5 变为 `9401ddb2b650930803bd31cc2ee08a41`。
> **§3/§4 的全部结论已在该新产物上复测通过**（dlerror 契约、模块视图 4 个对象、
> `RUN_ALL --quick` 14/14、`RUN_WARN_GATE` 零告警）。
> 我的改动**未被并发编辑破坏** —— 逐项核对：`bxroot_dl_err` 18 处、
> `bxroot_dl_error_set2` 定义 1 处 + 调用 4 处、`dlerror` 定义 1 处、
> `dl_iterate_phdr` 定义 1 处、`audit_` 19 行、`getpid` 定义 0 处。

---

## 0. 结论速览

| 符号 | 修前（bxroot） | 修后（bxroot） | 官方 |
|---|---|---|---|
| `dlerror` 失败 `dlsym` 后 | **NULL** ❌ | `undefined symbol: <名>` ✅ | 同 |
| `dlerror` 读一次即清 | ✅（本来就是 NULL） | ✅ | 同 |
| `dlerror` 带句柄失败 | **NULL** ❌ | `ldso_runtime dlsym: symbol '<名>' not found` ✅ | 同 |
| `dl_iterate_phdr` 模块视图 | **1 个** ❌ | **4 个**（与官方**集合完全一致**）✅ | 4 个 |
| 自递归 | （修前未导出，无此路径） | **无转发路径 → 结构性不可能** ✅ | 官方也没有防护 |
| 无限自递归崩溃 | 薄转发写法 **100% SIGSEGV**（实测复现） | **不发生** ✅ | — |
| 嵌套 `dl_iterate_phdr` | ✅ | ✅（**不误伤**） | ✅ |

**测试判别力（同一脚本 `test/RUN_DL_TESTS.sh`）：**

```
修前产物（libbx-runtime.so）：FAIL 6 条，exit 1
修后产物（libbxroot-runtime.so）：PASS 11 条 / FAIL 0 条，exit 0
```

---

## 1. 官方做法（全部从二进制实读，不照抄调查报告的转述）

### 1.1 `dlerror`（官方 @0x22fa0）：自己的 TLS 变量，读一次即清

```asm
0000000000022fa0 <dlerror@@Base>:
   22fa0: mrs  x1, tpidr_el0              ; x1 = TLS 基址
   22fac: adrp x0, 60000
   22fb0: ldr  x2, [x0, #1224]            ; TLS 描述符（0x604c8）
   22fb4: add  x0, x0, #0x4c8
   22fb8: blr  x2                          ; 取 TLS 偏移 → x0
   22fbc: ldr  w3, [x1, x0]                ; 读"有错吗"标志
   22fc0: add  x2, x1, x0
   22fc4: cbz  w3, 22fdc                   ; 无错 → 返回 NULL
   22fc8: add  x2, x2, #0x10               ; 错误串在 TLS 偏移 +0x10
   22fcc: str  wzr, [x1, x0]               ; ★ 清除标志（读一次即清）★
   22fd0: ldp  x29, x30, [sp], #16
   22fd4: mov  x0, x2
   22fd8: ret
```

**布局从反汇编坐实**（不是猜的）：

| 偏移 | 内容 | 证据 |
|---|---|---|
| `+0x00` | `int` 有错标志 | `ldr w3,[x1,x0]` / `str wzr,[x1,x0]` |
| `+0x04` | 12 字节对齐空洞 | `add x2,x2,#0x10` 跳到 +0x10 |
| `+0x10` | `char[128]` 错误串 | `snprintf(x0 = tls+off+0x10, x1 = 0x80, …)` |

`readelf -rW` 证实 `0x604c8` 是 `R_AARCH64_TLSDESC`（索引 1010），**不是** `dlsym`
—— 即 `__libc_dlerror_result` 那类**官方自己的** TLS 变量。

### 1.2 官方 `dlsym`（@0x22e90）：失败时亲手写这个槽

```asm
   22e90: stp  x29, x30, [sp, #-32]!
   22e9c: mov  x19, x1                     ; x19 = symbol
   22ea0: cbz  x0, 22f14                   ; handle==NULL        → RTLD_DEFAULT 分支
   22ea4: cmn  x0, #0x1
   22ea8: b.eq 22f8c                       ; handle==RTLD_NEXT   → next_from 分支
   22eac: cmn  x0, #0x2
   22eb0: b.eq 22f14                       ; handle==RTLD_DEFAULT(-2) → 同上
   22eb8: adrp x2, b1000                   ; （以下：调用方传进来的"真 dlsym"缓存）
   22ec0: ldr  x2, [x2, #3944]
   22ec4: cbz  x2, 22ed4
   22ec8: blr  x2
   22ecc: mov  x2, x0
   22ed0: cbnz x0, 22f24                   ; 成功 → 清标志
   22ed4: mrs  x4, tpidr_el0               ; ── 失败路径 A ──
   22edc: ldr  x1, [x0, #1224]
   22ee0: add  x0, x0, #0x4c8
   22ee4: blr  x1
   22ee8: add  x5, x4, x0
   22eec: mov  w6, #0x1
   22ef0: mov  x3, x19                     ; x3 = symbol
   22ef4: adrp x2, 36000
   22ef8: mov  x1, #0x80                   ; ★ 缓冲 128 字节 ★
   22efc: add  x2, x2, #0xc38              ; 格式串 @0x36c38
   22f00: str  w6, [x4, x0]                ; ★ 置标志 = 1 ★
   22f04: add  x0, x5, #0x10               ; 目标 = TLS + off + 0x10
   22f08: bl   snprintf@plt
   22f14: mov  x1, x19                     ; ── RTLD_DEFAULT / NULL ──
   22f18: bl   ldso_service_dlsym@plt
   22f1c: mov  x2, x0
   22f20: cbz  x2, 22f4c                   ; 失败 → 路径 B
   22f24: mrs  x1, tpidr_el0               ; ── 成功 ──
   22f2c: ldr  x3, [x0, #1224]
   22f30: add  x0, x0, #0x4c8
   22f34: blr  x3
   22f38: str  wzr, [x1, x0]               ; ★ 成功必清标志 ★
   22f4c: mrs  x4, tpidr_el0               ; ── 失败路径 B ──
   22f6c: adrp x2, 36000
   22f70: mov  x1, #0x80
   22f74: add  x2, x2, #0xc68              ; 格式串 @0x36c68
   22f78: str  w6, [x4, x0]
   22f80: bl   snprintf@plt
   22f8c: xpaclri                          ; ── RTLD_NEXT ──
   22f90: mov  x0, x30
   22f94: bl   ldso_service_dlsym_next_from@plt
```

### 1.3 ★ 格式串原文（从官方 `.rodata` 实读，**不是转述**）★

```python
>>> d = open('libproroot-runtime.so','rb').read()
>>> for a in (0x36c38, 0x36c68, 0x36c80):
...     print(hex(a), repr(d[a:d.index(b'\0',a)]))
0x36c38 b"ldso_runtime dlsym: symbol '%s' not found"
0x36c68 b'undefined symbol: %s'
0x36c80 b'dl_iterate_phdr'
```

原始字节区域（含相邻串，证明没有读错偏移）：

```
b"de=%lo\n\x00getpwuid\x00\x00\x00\x00\x00\x00\x00\x00"
b"ldso_runtime dlsym: symbol '%s' not found\x00\x00\x00\x00\x00\x00\x00"
b"undefined symbol: %s\x00\x00\x00\x00"
b"dl_iterate_phdr\x00dladdr\x00\x00/usr/lib"
```

**两条串对应哪条分支 —— 由反汇编指令直接坐实（不是推测）：**

| 分支 | 地址 | 格式串 |
|---|---|---|
| `ldso_service_dlsym` **服务版**失败 | `0x22f4c` → `add x2,x2,#0xc68` | `undefined symbol: %s` |
| "真 dlsym" 缓存存在但返回 NULL | `0x22ed4` → `add x2,x2,#0xc38` | `ldso_runtime dlsym: symbol '%s' not found` |

**实测印证**（隔离垫片 `dlshim.so`，只实现 dlsym/dlerror/dl_iterate_phdr）：

```
2) dlsym(不存在)=(nil)  dlerror = <undefined symbol: bxroot_definitely_no_such_symbol_42>
8b) dlsym(libm句柄,不存在)=(nil) dlerror = <ldso_runtime dlsym: symbol 'no_such_in_libm_xyz' not found>
```

> **对调查报告 §5 第 5 点的修正**：报告说"读到代码里 `stp` 了两个指针、用 `csel` 选，
> 但没完全还原选择条件"，并**建议**只照抄 `undefined symbol: %s`。
> 实测还原结果是：**两条都要**，选择条件就是"失败发生在服务分支还是缓存分支"。
> 本实现两条都保留（§2.1）。

### 1.4 ★ 官方 `dlopen` **不写** dlerror 槽（纠正一个常见预期）★

全库 `ldr x?,[x0,#1224]` 的出现点**穷举**：

```
dlsym@@Base:            22edc / 22f2c / 22f54
dlerror@@Base:          22fb0
dlopen@@Base:           231b8 / 23518
```

`dlopen` 那两处读的是**同一个 TLS 基址加不同偏移**：

```asm
   231b8: ldr  x2, [x0, #1224]      ; TLS 描述符
   231c0: blr  x2
   231c4: add  x0, x27, x0
   231c8: ldr  w0, [x0, #144]       ; ★ +0x90，不是 +0 ★
```

`+0x90` 是 `ldsomutex`（`0x604a8` 的 `R_AARCH64_TLSDESC`），且 `dlopen` 只对它
`strb`，**没有**写 dlerror 槽。它把错误原因 `snprintf` 到栈上 256 字节缓冲再
`write(2,…)` 到 stderr（`0x23418` `mov w0,#2; bl write@plt`）。

**实测印证**：官方侧 `dlopen(不存在)` 之后 `dlerror()` 就是 **NULL**。

→ 所以 glibc 里"`dlopen` 失败也能 `dlerror`"的语义，**官方并没有接**。
本实现与官方保持一致，**不替官方臆造这条语义**。

### 1.5 `dl_iterate_phdr`（官方 @0x22fec）：先 libc 版，非 0 直接返回，0 再兜服务

```asm
0000000000022fec <dl_iterate_phdr@@Base>:
   22ff8: adrp x21, b1000
   22ffc: add  x21, x21, #0xf68          ; x21 = &静态缓存槽
   2300c: ldr  x2, [x21, #8]             ; 读缓存
   23010: cbz  x2, 2304c                 ; 空 → 去解析
   23014: mov  x1, x20                   ; data
   23018: mov  x0, x19                   ; callback
   2301c: blr  x2                        ; 调"真正的 dl_iterate_phdr"
   23020: cbnz w0, 2303c                 ; ★ 非 0 → 直接返回 ★
   23024: ldr  x21, [sp, #32]
   23028: mov  x1, x20
   2302c: mov  x0, x19
   23038: b    ldso_service_dl_iterate_phdr@plt   ; ★ 0 → 再兜一层 ★
   2303c: ret
   ; ---- 解析路径 ----
   2304c: adrp x1, 36000
   23050: mov  x0, #-1                   ; RTLD_NEXT
   23054: add  x1, x1, #0xc80            ; "dl_iterate_phdr"（.rodata 实读）
   23058: bl   dlsym@plt
   2305c: str  x0, [x21, #8]             ; 填缓存
   23064: cbnz x0, 23014
   2307c: b    ldso_service_dl_iterate_phdr@plt
```

**关键认识**：即便在官方 runtime 上，**真正干活的是 libc 的 `dl_iterate_phdr`**；
官方额外做的**唯一一件事**就是那一层 `ldso_service_dl_iterate_phdr` 兜底 ——
而正是这一层把模块视图从 1 个补成了 4 个（§3）。

**官方视图里主程序被回调两遍**（`phdr[0]` 与 `phdr[1]` 同 name 同 base），
原因就是"先 `bl` libc 版、再 `b` 服务版"两遍拼在一起。详见 §5.5。

---

## 2. 修法

### 2.1 `dlerror` + `dlsym`：**同源 TLS 状态**（路 A，与官方同构）

在 `preload.c` 里新增（位置在原 `dlsym` 之前、`dladdr` 之前）：

```c
struct bxroot_dl_error_state {
    int  flag;          /* +0x00：非 0 = 有未读错误 */
    int  _pad[3];       /* +0x04：对齐到 +0x10（与官方同布局） */
    char msg[128];      /* +0x10：错误串（官方 snprintf 用 0x80） */
};
static _Thread_local struct bxroot_dl_error_state bxroot_dl_err;
```

`dlsym` 的**每条退出路径**都过一遍同源状态（成功清 / 失败登记）：

```c
if (handle == RTLD_NEXT) {
    res = ldso_service_dlsym_next_from(__builtin_return_address(0), symbol);
    if (res != NULL) bxroot_dl_error_clear();
    else bxroot_dl_error_set2("undefined symbol: ", symbol, NULL);
    return res;
}
if (handle == NULL || handle == RTLD_DEFAULT) {
    res = ldso_service_dlsym(NULL, symbol);
    if (res != NULL) bxroot_dl_error_clear();
    else bxroot_dl_error_set2("undefined symbol: ", symbol, NULL);
    return res;
}
res = ldso_service_dlsym(handle, symbol);
if (res != NULL) bxroot_dl_error_clear();
else bxroot_dl_error_set2("ldso_runtime dlsym: symbol '", symbol, "' not found");
return res;
```

`dlerror` 只读这份状态、读一次即清：

```c
char *dlerror(void) {
    if (!bxroot_dl_err.flag)
        return NULL;
    bxroot_dl_err.flag = 0;          /* 读一次即清（官方 str wzr） */
    return bxroot_dl_err.msg;
}
```

**为什么不复刻 glibc 的 `__libc_dlerror_result`**：客户程序只会通过 `dlerror()`
访问，不会读布局；glibc 的布局是私有且随版本漂移的。官方用的也只是
"自己的一个 TLS 变量"。这与官方同构，不是偷懒。

### 2.2 `dl_iterate_phdr`：接上 `ldso_service_dl_iterate_phdr`

```c
if (bxroot_dl_has_service()) {
    return ldso_service_dl_iterate_phdr(callback, data);   /* linker 私有模块视图 */
}
/* 降级：非 proroot 环境才转发 libc（这条路才可能成环，防护只放这里） */
```

符号声明本来就在 `preload.c` 里（`extern int ldso_service_dl_iterate_phdr(...)`，
`dladdr` 已在用），`nm -D --undefined-only` 一直有这条未定义引用 —— 无需新增声明。

### 2.3 ★ 自递归防护：**根本不存在转发路径** ★

这是本修复最关键的一点。`dlerror` 是**本库导出的符号**，因此：

```
ldso_service_dlsym_next_from(retaddr, "dlerror")  →  解析回本库自己的 dlerror
```

**实测复现（这是报告结论的独立验证）**，垫片 `dlbad2.c`（无条件转发）：

```
A) 3 轮失败 dlsym+dlerror
[dlbad2] 第0次: 解析到 0x788c9b1460；本库 &dlerror=0x788c9b1460  ★同一个★ → 无条件转发即无限自递归
[dlbad2] 第1次: 解析到 0x788c9b1460；本库 &dlerror=0x788c9b1460  ★同一个★ → 无条件转发即无限自递归
[dlbad2] 第2次: 解析到 0x788c9b1460；本库 &dlerror=0x788c9b1460  ★同一个★ → 无条件转发即无限自递归
Segmentation fault
```

**报告 §2.3 "不做自递归防护 100% 崩" 的结论：实测成立。**

另一版垫片 `dlbad.c`（带自打印检测）连刷数百行同样的行，同样是无限自递归。

**本实现的防护不是"判一下再转发"，而是"根本没有转发路径"**：

| 手段 | 说明 |
|---|---|
| ① 无转发 | `dlerror` 与 `dlsym` 同源，同一份 TLS 结构；`dlerror` 只读它，不需要也不可能从 libc 的 dlerror 取任何东西 |
| ② 不调用外部函数 | `bxroot_dl_error_set2` 手工逐字节拼串，**不调 `snprintf`/`strlen`** —— 任何"调用出去"都可能经 PLT 绕回本库 |
| ③ `_Thread_local` 不解析符号 | TLS 访问器由 ld.so 装载时经 `R_AARCH64_TLSDESC` 填好，**不经过符号解析**（实测本容器 `-fPIC` 共享库生成的就是 TLSDESC） |

**这比"加一个自检判据"更强**：判据可能因 `dl_iterate_phdr` 残缺而失效
（报告 §2.3 实测自检垫片拿到 `base=0x0`、**没拦住**），而"没有转发路径"
不存在失效的可能。**这正是两个符号必须一起修的原因。**

### 2.4 降级路径（非 proroot 环境）的两道防护 + 不误伤嵌套

`dl_iterate_phdr` 只有"无 linker 服务"那条路可能成环，所以防护**只放那里**：

```c
if (bxroot_dl_has_service())
    return ldso_service_dl_iterate_phdr(callback, data);   /* 无环：服务不回调本函数 */

/* 降级路径 */
if (bxroot_dl_iterate_fallback_busy) return -1;            /* ② 重入截断 */
bxroot_dl_iterate_fallback_busy = 1;
if (fn == NULL) fn = bxroot_next_symbol("dl_iterate_phdr");
if (fn == NULL || (void *)fn == (void *)&dl_iterate_phdr) { /* ① 自身地址判据 */
    bxroot_dl_iterate_fallback_busy = 0;
    return -1;
}
rc = fn(callback, data);
bxroot_dl_iterate_fallback_busy = 0;
```

> **★ 这里踩过一个坑，写下来避免后人重复 ★**
>
> 初版把重入哨兵**无差别地罩在服务路径上**，结果 `dl_iterate_phdr` 的
> **合法嵌套**（在回调里再遍历一次）被误伤成 `-1`。glibc 允许嵌套、
> 官方也允许（实测官方嵌套返回 0、内层回调 5 轮）。
> **"加防护"必须加在真正有环的那条路上**，否则就是用一个缺陷换另一个缺陷。
> 现在服务路径不加哨兵 —— 嵌套调用照常可用（§4.4 E1、§5.6）。

---

## 3. 实测对照：修前 / 修后 / 官方

**环境**：本容器（Android aarch64 / Ubuntu rootfs / 官方 proroot bridge+linker）。
两侧**各设各的前缀**（官方只认 `PROROOT_*`，bxroot 只认 `BXROOT_*`；
给官方传 `BXROOT_*` 会被静默忽略，那就不是对照实验）。

### 3.1 `dlerror` 契约 —— 探针 `dlprobe`

```
========== 官方 runtime（PROROOT_*）==========
=== A) dlerror 契约 ===
1) 初始 dlerror()            = NULL (正确)
2) dlsym(不存在)=(nil)  dlerror = <undefined symbol: bxroot_definitely_no_such_symbol_42>
3) 再读一次 dlerror()        = NULL (正确·读一次即清)
4) dlsym(malloc)=0x7c338d8490  dlerror = NULL (正确)
5) 第二次失败 dlsym=(nil) dlerror = <undefined symbol: 另一个不存在的符号_zzz>
```

```
========== bxroot 修前（BXROOT_*）==========
=== A) dlerror 契约 ===
1) 初始 dlerror()            = NULL (正确)
2) dlsym(不存在)=(nil)  dlerror = <NULL (!! 缺陷)>
3) 再读一次 dlerror()        = NULL (正确·读一次即清)
4) dlsym(malloc)=0x73bcad8490  dlerror = NULL (正确)
5) 第二次失败 dlsym=(nil) dlerror = <NULL (!! 缺陷)>
```

```
========== bxroot 修后（BXROOT_*）==========
=== A) dlerror 契约 ===
1) 初始 dlerror()            = NULL (正确)
2) dlsym(不存在)=(nil)  dlerror = <undefined symbol: bxroot_definitely_no_such_symbol_42>
3) 再读一次 dlerror()        = NULL (正确·读一次即清)
4) dlsym(malloc)=0x739f0d8490  dlerror = NULL (正确)
5) 第二次失败 dlsym=(nil) dlerror = <undefined symbol: 另一个不存在的符号_zzz>
```

**修后 bxroot 与官方逐字一致。**

### 3.2 带句柄失败（第二条格式串）

```
bxroot 修前: 8b) dlsym(libm句柄,不存在)=(nil) dlerror = <NULL (!!)>
bxroot 修后: 8b) dlsym(libm句柄,不存在)=(nil) dlerror = <ldso_runtime dlsym: symbol 'no_such_in_libm_xyz' not found>
官方      : 8b) dlsym(libm句柄,不存在)=(nil) dlerror = <ldso_runtime dlsym: symbol 'no_such_in_libm_xyz' not found>
```

### 3.3 `dlerror` 是**同源**的（本库自己的诊断路径也受益）

`preload.c:731` 与 `proc.c:3049` 都写了 `dlsym(%s) 失败: %s` 配合 `dlerror()`。
用 `dlsym(RTLD_NEXT, <不存在>)` 复刻该失败路径：

```
### bxroot 修前 ###
dlsym(RTLD_NEXT, 不存在)=(nil)
dlerror() = <NULL (!! 诊断代码打不出原因)>

### bxroot 修后 ###
dlsym(RTLD_NEXT, 不存在)=(nil)
dlerror() = <undefined symbol: wait9999_nonexistent>

### 官方对照 ###
dlsym(RTLD_NEXT, 不存在)=(nil)
dlerror() = <undefined symbol: wait9999_nonexistent>
dlsym(RTLD_NEXT, newfstatat)=(nil)
dlerror() = <undefined symbol: newfstatat>
```

> **顺带发现**：`newfstatat` 在官方侧**解析不到**（glibc 2.33+ 已删除），
> 而 bxroot 侧仍能解析到 `0x7c2d9caea0`。这是**另一个**差异（不在本任务范围），
> 记录于此供后续排查。

### 3.4 `dl_iterate_phdr` 模块视图

`dlprobe`（列全部回调）：

```
========== 官方 ==========                       ========== bxroot 修前 ==========
   phdr[0] .../dlprobe  base=0x7c34cd5000 phnum=9    phdr[0] .../dlprobe base=0x73bde07000 phnum=9
   phdr[1] .../dlprobe  base=0x7c34cd5000 phnum=9    共 1 个模块   ← ★ 缺陷
   phdr[2] .../liboff-runtime.so
   phdr[3] .../libc.so.6
   phdr[4] .../ld-linux-aarch64.so.1
   phdr[5] .../libm.so.6
   共 6 个模块
```

```
========== bxroot 修后 ==========
   phdr[0] .../dlprobe base=0x73a0442000 phnum=9
   phdr[1] .../build/libbxroot-runtime.so base=0x73a03e5000 phnum=8
   phdr[2] .../libc.so.6 base=0x739f042000 phnum=10
   phdr[3] .../ld-linux-aarch64.so.1 base=0x73a03a1000 phnum=7
   phdr[4] .../libm.so.6 base=0x739e75f000 phnum=7
   共 5 个模块
```

**模块集合（去重后）与官方完全一致**（探针 `mods`）：

```
### 官方 ###                          ### bxroot 修后 ###              ### bxroot 修前 ###
  mods                                  mods                            mods
  liboff-runtime.so                     libbxroot-runtime.so          -> 去重后 1 个对象
  libc.so.6                             libc.so.6
  ld-linux-aarch64.so.1                 ld-linux-aarch64.so.1
  -> 去重后 4 个对象（原始回调 5 次）    -> 去重后 4 个对象（原始回调 4 次）
```

差异只有两点，**都是官方的问题，不是 bxroot 的**：
1. 官方**主程序回调两遍**（`原始回调 5 次` vs bxroot `4 次`）—— 见 §5.5；
2. 库名不同（各自装载自己的 runtime），这是**应该**不同的。

---

## 4. 验证（硬要求逐条）

### 4.1 两侧对照（各设各的前缀）

`/root/dlfix/run.sh` 同时注入 `PROROOT_*` 与 `BXROOT_*`，两侧各读各的。
官方侧 `PROROOT_ROOTFS/PROROOT_TMP_DIR/PROROOT_GUEST_EXE`，
bxroot 侧 `BXROOT_ROOTFS/BXROOT_TMP_DIR/BXROOT_WORKDIR/BXROOT_FAKEROOT/BXROOT_LINK2SYMLINK/BXROOT_GUEST_EXE`。
**官方侧用 `PROROOT_*` 才有效**（`strings` 里 `BXROOT` 计数为 0，报告 §0.2 已核实）。

### 4.2 自递归防护专项

探针 `dlstress`（3000 轮失败 dlsym+dlerror / 500 轮 dlopen 失败 / 4 线程 TLS / 自身基址 / 嵌套）：

```
############ 修后 bxroot：防护专项 ############
=== 1) 自递归防护：3000 轮失败 dlsym + dlerror ===
  ✅ 3000 轮全部正确，未爆栈（无限自递归会在此爆栈 SIGSEGV）

=== 2) dlopen 不存在的库 → dlerror 不许崩 ===
  ✅ 500 轮 dlopen 失败均正常返回，未崩

=== 3) TLS 线程隔离 ===
  ✅ 4 线程 × 2000 轮各自独立、读后即清

=== 4) 报告 §2.3 场景：从 dl_iterate_phdr 视图里找到 dl 库自身基址 ===
  dladdr(&dlsym) -> 1 fname=.../build/libbxroot-runtime.so fbase=0x794b5d0000
  dl_iterate_phdr 视图共 4 个已命名模块
  在视图中找到实现 dlsym 的那个库
  ✅ 自递归检测垫片可用（能拿到自身基址）
```

**对照：**

| 探针 | 官方 | bxroot 修前 | bxroot 修后 |
|---|---|---|---|
| 1) 3000 轮 | ✅ | ❌ 第 0 轮 `dlerror=NULL` | ✅ |
| 2) 500 轮 dlopen | ✅ | ✅ | ✅ |
| 3) 4 线程 × 2000 | ✅ | （未跑到） | ✅ |
| 4) 拿到自身基址 | ✅ | ❌ `base=0x0` | ✅ |

**修前第 4 项的输出正是报告 §2.3 描述的症状**（视图残缺 → 垫片拿不到基址 → 自检失效）。

### 4.3 无限自递归的**反面证据**（无防护薄转发必崩）

```
A) 3 轮失败 dlsym+dlerror
[dlbad2] 第0次: 解析到 0x788c9b1460；本库 &dlerror=0x788c9b1460  ★同一个★ → 无条件转发即无限自递归
Segmentation fault
```

同一探针下**本实现不崩**（§4.2 第 1 项 3000 轮通过）。

### 4.4 新增永久回归：`test/RUN_DL_TESTS.sh` + `test/dltest.c`

```
== dl 家族契约（dlerror / dlsym / dl_iterate_phdr）==

[A] dlerror 契约
  PASS A1 初始 dlerror() 为 NULL
  PASS A2 失败 dlsym 后 dlerror 非空             p=(nil) dlerror=<undefined symbol: bxroot_definitely_no_such_symbol_42>
  PASS A2b 错误串含符号名
  PASS A3 读一次即清（第二次为 NULL）
  PASS A4 成功的 dlsym 不产生错误
  PASS A5 带句柄失败也留痕                    <ldso_runtime dlsym: symbol 'no_such_symbol_in_libm_xyz' not found>

[B] 自递归防护（薄转发会在此无限递归 → SIGSEGV）
  PASS B1 3000 轮失败 dlsym+dlerror 不崩         3000 轮全部正确

[C] dlopen 失败路径
  PASS C1 200 轮 dlopen 失败不崩

[D] dl_iterate_phdr 模块视图
  PASS D1 模块视图 > 1（不是只有主程序） 视图 5 个已命名模块
  PASS D2 视图含实现 dlsym 的那个库          .../build/libbxroot-runtime.so base=0x7d689d8000
  PASS D3 dladdr(&dlsym) 有 fname/fbase

[E] dl_iterate_phdr 合法嵌套
  PASS E1 嵌套调用可用且不爆栈              rc=0 外层 5 轮，嵌套成功 30 次

== 结果：全部通过（失败 0 条）==
```

**判别力证明 —— 同一个脚本跑修前产物（6 条 FAIL、exit 1）：**

```
  PASS A1 初始 dlerror() 为 NULL
  FAIL A2 失败 dlsym 后 dlerror 非空             p=(nil) dlerror=<NULL>
  FAIL A2b 错误串含符号名
  PASS A3 读一次即清（第二次为 NULL）
  PASS A4 成功的 dlsym 不产生错误
  FAIL A5 带句柄失败也留痕                    <NULL>
  FAIL B1 3000 轮失败 dlsym+dlerror 不崩         第 1 轮出错
  PASS C1 200 轮 dlopen 失败不崩
  FAIL D1 模块视图 > 1（不是只有主程序） 视图 1 个已命名模块
  FAIL D2 视图含实现 dlsym 的那个库          (未找到) base=0x0
  PASS D3 dladdr(&dlsym) 有 fname/fbase
  PASS E1 嵌套调用可用且不爆栈              rc=0 外层 1 轮，嵌套成功 2 次

== 结果：有失败（失败 6 条）==
```

### 4.5 `sh BUILD_RUNTIME.sh`

```
== 构建 libbxroot-runtime.so ==
   编译器     : gcc (13)
   proc.c     : /root/proroot-work/agents/rename-bxroot/src/proc/proc.c
   起始优化   : -O2
   ✅ 链接成功（-O2，第 1 次尝试）
   产物: /root/proroot-work/agents/rename-bxroot/build/libbxroot-runtime.so
   大小: 229352 字节
   导出符号（nm -D --defined-only）: 353
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
```

### 4.6 `sh test/RUN_ALL.sh --quick`

```
▶️  dl 家族契约            ✅ rc=0  ✅ dl 家族契约全部通过
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
  ✅ 运行时构建          ✅ D4 进程管理符号全部导出
  ✅ proot CLI 兼容         RESULT: PASS
  ✅ l2s 端到端契约      RESULT: PASS
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/waitid 均已导出
  ✅ dl 家族契约          ✅ dl 家族契约全部通过
------------------------------------------------------
  通过 14 / 失败 0
  ✅ 全部通过
```

> **关于"12/12"**：任务书写的是 12/12，**实际当前仓库有 14 项**
> （`wait 家族钩子`已存在，我另加 `dl 家族契约`；加上原有的 12 项 = 14）。
> 关键判据是 **失败 0**，且我**没有改动任何既有判据**（§4.8）。

### 4.7 `sh test/RUN_WARN_GATE.sh`

```
== bxroot 编译告警门禁 ==
   编译器 : gcc (13)
   警告集 : -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter
   proc.c : src/proc
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

### 4.8 硬约束自查

| 检查 | 期望 | 实测 |
|---|---|---|
| `grep -c "audit_" src/runtime/preload.c` | 不变（19 行 / 5 符号） | **19** ✅ |
| `nm -D build/libbxroot-runtime.so \| grep -c audit_` | 5 | **5** ✅ |
| `getpid` 函数定义 | 只有注释、无定义 | **0 个定义**（仅 `5716` 行注释）✅ |
| `nm -D \| grep -c ' T getpid'` | 0 | **0** ✅ |
| `src/l2s/l2s.c` 未改动 | 是 | ✅（与 `11fc225` 逐字节相同） |
| `src/proc/proc.c` 未改动 | 是 | ✅ |
| `src/runtime/syscall_guard.c` 未改动 | 是 | ✅ |
| `src/launcher/launcher.c` 未改动 | 是 | ✅ |
| `test/RUN_WARN_GATE.sh` 未改动 | 是 | ✅ |
| `test/RUN_ALL.sh` 判据只增不改 | **删除 0 行 / 新增 23 行** | ✅ |

`preload.c` 改动规模：**删除 5 行 / 新增 384 行**；那 5 行删除**全部**属于
`dlsym` 函数体内部的重构（`if (bxroot_has_ldso_service())` 改为
`if (bxroot_dl_has_service())`，以及 3 条 `return` 改为先存 `res` 再登记状态），
**没有触碰任何其它函数**。

### 4.9 真实程序端到端（node，`dl_iterate_phdr` 的引用者）

```
### node — 官方 ###                       ### node — bxroot 修后 ###
node ok v24.19.0 modules 118              node ok v24.19.0 modules 144
```

node 在两侧都正常运行；`node[NNNNN]: pthread_create: Invalid argument`
是报告 §2.4 的**另一个**已知缺陷（本次任务范围外，未被本次改动影响）。

---

## 5. 对调查报告 `docs/高频符号缺口调查.md` 的核查

### 5.1 结论正确的部分（我独立复现）

| 报告结论 | 我的复现 |
|---|---|
| `dlerror` 实测错误串恒为 NULL | ✅ 复现（§3.1） |
| 官方 `dlerror` 读 TLS、读一次即清 | ✅ 反汇编逐条确认（§1.1） |
| 官方 `dlsym` 失败时亲手写该 TLS 槽 | ✅ 反汇编逐条确认（§1.2） |
| `dl_iterate_phdr` 官方"先 dlsym 填缓存、非 0 直接返回、0 再兜服务" | ✅ 一致（§1.5） |
| bxroot 模块视图 5 → 1 | ✅ 复现（修前 1 个，§3.4） |
| ★ **薄转发 `dlerror` 会解析到自己、100% SIGSEGV** ★ | ✅ **独立复现**（§2.3、§4.3） |
| ★ 因为 `dl_iterate_phdr` 残缺导致自递归检测垫片失效 ★ | ✅ 复现（`base=0x0`，§4.2 第 4 项） |
| `ldso_service_dl_iterate_phdr` 必须接上 | ✅ 生效（模块集合与官方一致，§3.4） |
| 官方只认 `PROROOT_*` | ✅ 一致（§4.1） |

### 5.2 ★ 需要更正/补充的点 ★

**（1）报告 §2.3 说"格式串有两条，但没完全还原选择条件、建议只照抄
`undefined symbol: %s`" —— 不准确。**

实测选择条件是明确的（§1.3）：`0x22f4c`（**服务分支**失败）用
`undefined symbol: %s`；`0x22ed4`（"真 dlsym"缓存分支失败）用
`ldso_runtime dlsym: symbol '%s' not found`。**两条都要保留**，本实现两条都实现了，
实测逐字匹配官方（§3.2）。只实现一条会让带句柄的失败路径没有错误串。

**（2）报告未提到的重要事实：官方 `dlopen` 失败时 `dlerror()` 也是 NULL。**

报告 §2.3 表格只列了"失败的 `dlsym` 后"，容易让人以为"官方在 dl 家族上
全面优于 bxroot"。实测：官方 `dlopen(不存在)` 之后 `dlerror()` **就是 NULL**
（§1.4、§3.1 第 6 行）。这是**官方与 glibc 的语义差异**，不是缺陷 ——
本实现**刻意与官方保持一致**，没有替官方加这条语义。

**（3）报告 §2.2 把"`phdr[0]` 与 `phdr[1]` 重复"称为"像是官方的一个小瑕疵、
但不确定、倾向认为是 bug" —— 现已定性：是官方实现的必然结果，不是随机 bug。**

原因就在官方的控制流里（§1.5）：它**先 `bl` libc 版（跑完整视图）、
再 `b` 服务版（又跑一遍完整视图）**，两遍的回调拼在一起，于是每个对象
（含主程序）都被回调两次。这是"两遍视图"的直接后果，**可稳定复现**
（我跑了多次，每次都是 `原始回调 5 次`）。

本实现**不复制这个重复**：直接用服务（一遍），因为服务本身就是完整视图，
模块**集合**与官方一致（§3.4）。这样"数模块数"的调用方拿到的是真实对象数。
这是**有意的偏离**，已在代码注释里写明理由。

**（4）报告 §5 第 4 点"官方默认配置下就会重复回调主程序"—— 实测确认，
但报告的观察"`phdr[0]` 与 `phdr[1]` 同 name 同 base"在多模块场景下
应表述为"**每个对象都回调两遍**"，不只主程序。** §3.4 官方输出里
`phdr[0]/phdr[1]` 是主程序，`phdr[2]~[5]` 是各一次 —— 因为官方先跑
libc 版时后面几个库可能还没装载，具体取决于时序；**稳定的是"主程序必重复"**。

### 5.3 报告中我**未能**复核的点

- §1.2"找不到注入者"：我同样没能定位（不影响本任务）。
- §0.3 引用数口径：与本次修复无关，未复核。

---

## 6. 我的**不确定项**（不假装确定）

1. **`_Thread_local` 在本项目的**其它 loader 组合**下是否都走 TLSDESC。**
   我实测了本容器（aarch64 glibc + proroot 自研 loader，`-fPIC` 共享库
   → `R_AARCH64_TLSDESC`），也实测了官方产物用的是 TLSDESC。
   但**没有**测其它架构/loader（例如 x86_64 或 musl）。
   若某环境退化成 `R_AARCH64_TLS_TPREL`/通用动态模型，`dlerror` 里
   第一次访问 TLS 可能触发 `__tls_get_addr` —— 那是个 libc 函数调用。
   **我认为这是安全的**（它由 ld.so 提供、不经过 dl 符号解析），
   但**没有实测**该路径。

2. **`bxroot_dl_service_state` 的缓存时机。** 我在第一次用到时判定并缓存
   （与既有 `bxroot_has_ldso_service` 同策略，且后者内部已缓存）。
   **没有实测**"一个进程里先无服务、后又有服务"的切换场景 ——
   在 proroot 下服务始终存在，非 proroot 下始终不存在，所以我认为
   该场景不现实，但**没有证据**。

3. **官方那 12 字节空洞的真实字段名未知。** 我只知道布局
   `{int; 12B; char[128]}`（从指令偏移读出），不知道官方在那里放了什么
   （也可能纯粹是 padding）。本实现把它当 padding 用。
   客户程序不会读它，所以**不影响兼容性**。

4. **`dlerror` 的 128 字节上限。** 官方 `snprintf` 用 `0x80`，我照抄
   （截断而非溢出）。**超长符号名会被截断**，行为与官方一致，但
   我**没有**实测超长名字下的逐字节一致性。

5. **`dl_iterate_phdr` 嵌套的深度上限。** 我测了深度 3（通过）。
   更深的嵌套（或回调里嵌套调用其它 dl 函数）**没有测**。
   服务路径无哨兵，理论上不设上限（与 glibc 一致）。

6. **我修复后 `dladdr` 未经回归影响的确认是间接的。** 我改动了
   `bxroot_has_ldso_service()` → `bxroot_dl_has_service()` 的调用点，
   `dladdr` 仍在用**旧的** `bxroot_has_ldso_service()`（未改），
   实测 `dladdr` 两侧正常（§3.4 D3、`dlprobe` E 段）。
   两个包装函数读同一个缓存，**行为一致**，但确实多了一层间接。

---

## 7. 复现方法

```sh
# 探针（已留在 /root/dlfix/ = <ROOTFS>/root/dlfix/）
/root/dlfix/dlprobe       # dlerror 契约 + 模块视图 + dladdr
/root/dlfix/dlprobe2      # 加盖句柄失败分支
/root/dlfix/dlstress      # 自递归防护 + TLS + 自身基址 + 嵌套
/root/dlfix/selfdiag      # 内部诊断路径
/root/dlfix/mods          # 模块集合（去重）
/root/dlfix/libbad2.so    # 反面证据：无防护薄转发 → SIGSEGV

# A/B（各设各的前缀）
R=/data/data/com.dsh.client/files/linux/ubuntu/root
sh /root/dlfix/run.sh off "$R/mmapprobe/stage/liboff-runtime.so" "$R/dlfix/dlprobe"
sh /root/dlfix/run.sh bx  "$R/proroot-work/.../build/libbxroot-runtime.so" "$R/dlfix/dlprobe"

# 永久回归
sh test/RUN_DL_TESTS.sh                      # 修后 → exit 0
BXROOT_DL_RT=/root/mmapprobe/stage/libbx-runtime.so \
BXROOT_DL_KRT=/data/.../root/mmapprobe/stage/libbx-runtime.so \
  sh test/RUN_DL_TESTS.sh                    # 修前 → exit 1（6 条 FAIL）
```

**踩过的坑（供后续 agent）：**
1. **`/tmp` 会在会话中途被清空**（本项目已知问题）—— 所有中间产物放 `/root/dlfix/`。
2. **`--preload` 必须传内核视角路径**，传宿主路径会
   `deps: failed to preload …` / `proroot-ldso: failure rc=2`。
   `$ROOTFS/root` 与 `/root` 同 inode，所以内核视角路径 = `$ROOTFS` + 宿主绝对路径。
3. **`/data/app/…/lib/arm64/libproroot-bridge.so` 可 exec 但不可 stat**
   —— `[ -f ]`/`[ -x ]`/`os.path.exists()` 全为假。脚本里若用它做守卫，
   会把测试**永远静默跳过**。必须用"真跑一下"探测。
4. **写 `dlerror` 探针时，`dlerror()?dlerror():"NULL"` 是错的** ——
   第一个 `dlerror()` 已经把状态清掉了，第二个返回 NULL。
   必须 `const char *e = dlerror();` 只调一次。
5. **测"嵌套 dl_iterate_phdr"必须用全局深度计数**。用"每次调用各自的计数器"
   会导致每次嵌套都从 0 重新开始 → **无限递归 → 爆栈**。
   我一开始就是这么写的，结果官方与本库**都**崩了 ——
   那是**探针自己的 bug**，不是被测 runtime 的（`fault=0x…fffc0` 紧贴栈顶 = 栈耗尽）。
   差点误判成"官方也崩"。

---

## 8. 收尾

- 全程**没有**用 `pkill`/`killall`/按名字杀进程；
- **没有**删除任何软件或无关文件；
- `/root/dlfix/`（= `<ROOTFS>/root/dlfix/`）是本轮唯一新增目录，可随时整目录删除；
- **没有**修改 `src/l2s/`、`src/proc/proc.c`、`src/runtime/syscall_guard.c`、
  `src/launcher/launcher.c`、`test/RUN_WARN_GATE.sh`（§4.8 逐字节核对）；
- `test/RUN_ALL.sh` **只新增了一项、删除 0 行**（§4.8）。
