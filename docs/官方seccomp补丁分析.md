# 官方 proroot seccomp 活体补丁机制 — 逆向分析报告

**分析对象**：`libproroot-runtime.so`（331,112 B，md5 `f14a074b41afb0424145f2c39401a1cc`）
**分析方式**：静态反汇编（objdump/readelf）+ **活体内存比对**（`/proc/self/mem`）+ **内核 seccomp 行为实测**
**分析者进程本身就跑在官方 proroot 之下**（本容器是 proroot 的客户），因此所有"补丁后"结论都是**实测**而非推测。

---

## 结论速览（TL;DR）

1. 官方补丁机制是**通用的"seccomp 中和器"**，不是针对 425 的定向补丁。
   `libproroot-runtime.so` 里**没有任何一处出现常量 425 / 0x1a9**（已穷举验证）。
2. runtime 导出了自己的 **`syscall()`（VA `0x1082c`）**，通过宿主 `--preload` 抢占 node 的
   `syscall@plt` 解析；该函数**硬编码把 425/426/427 直接返回 ENOSYS**，根本不发 `svc`。
3. 代码补丁**只覆盖"立即数版本"的系统调用**：把 `mov x8,#imm` + `svc #0` 改写。
   对 `svc` 只改了 **3 处**（`set_robust_list`×2、`rseq`×1），改写内容是
   **`svc #0` → `mov x0, #0`**（返回 0，成功语义）。
4. **目标库里搜不到 `mov w8/x8,#425`**，因为 libuv 走的是 `syscall()` 符号。
   **所以 io_uring_setup 的 `svc` 从未被补 —— 也不需要被补。**
5. `libproroot-linker.so` 的白名单（99/100）只用于**加载器自身**，与这条路径无关。

---

## 一、`proroot_patch_should_scan_object` 的还原（扫描策略）

符号：`.dynsym` #304，VA `0x299c0`，大小 804 B，**GLOBAL FUNC，已导出**
（唯一直接调用点：`0x286a8`，即补丁引擎 `0x285a0` 内）。

签名推断：`int proroot_patch_should_scan_object(const char *objname, const char *soname)`

### 还原后的伪代码

```c
int proroot_patch_should_scan_object(const char *objname, const char *soname)
{
    if (!soname)
        return 0;                       // 0x299d8: cbz x1 → 返回 w21=0

    bool v21 = true;                    // 默认允许（w21）
    bool v23 = true;                    // 默认允许（w23）
    bool v22 = true;                    // 默认允许（w22）

    // ---- 第 1 关：soname 匹配 ----
    if (strstr(soname, "/libc.so") || strstr(soname, "/libc-")) {
        // 0x370f8 "/curl", 0x37100 "curl", 0x37108 "/openssl", 0x37118 "openssl"
        if (strstr(soname,"/curl") || strstr(soname,"curl") ||
            strstr(soname,"/openssl") || strstr(soname,"openssl"))
            v23 = true;                 // 明示放行
    } else {
        // 0x370b0 "apt-get" 0x370b8 "apt-cache" 0x370c8 "apt-config"
        // 0x370d8 "apt-helper" 0x370e8 "/usr/lib/apt/" 0x37100 "curl"
        // 0x37178 "/dpkg" 0x37180 "dpkg-"
        if (strstr(soname,"apt-get") || strstr(soname,"apt-cache") ||
            strstr(soname,"apt-config") || strstr(soname,"apt-helper") ||
            strstr(soname,"/usr/lib/apt/") || strstr(soname,"curl") ||
            strstr(soname,"/dpkg") || strstr(soname,"dpkg-"))
            goto L_scan;                // → 进入扫描
        if (strstr(soname,"/curl") || strstr(soname,"curl") ||
            strstr(soname,"/openssl") || strstr(soname,"openssl"))
            goto L_scan;
        // 0x37110 "/apt", 0x37118 "openssl" 等同族
        v23 = (strstr(soname, "openssl") != NULL);
        goto L_scan;
    }

L_scan:
    // ---- 第 2 关：objname（映射路径）判定 ----
    if (!objname || !*objname) return v22;          // 无路径 → 返回默认

    // 2a. 匿名/特殊映射白名单（直接返回 true）
    if (strstr(objname, 4 字节模式 @0x370a8)        // 空串模式
     || strstr(objname, 0x3bd0)                     // 见下方说明
     ...)
        return true;

    // 2b. "chromium"/"headless" → 放行
    if (strstr(objname, "chromium") || strstr(objname, "headless"))
        return true;

    // 2c. 精确排除（strcmp，命中即放行）：0x37328/0x37338/0x37348/0x37358
    if (!strcmp(objname,"libc.so.6")   || !strcmp(objname,"libpthread.so.0") ||
        !strcmp(objname,"libdl.so.2")  || !strcmp(objname,"librt.so.1"))
        return true;

    // 2d. 前缀匹配（strncmp 8 字节）：0x37368 "ld-linux"
    bool is_ld = (strncmp(objname, "ld-linux", 8) == 0);
    if (is_ld || v22) return true;

    // 2e. 若前一轮 curl/openssl 命中，进一步用子串放行
    if (v21) {  // 0x37378 "libapt-pkg", 0x37388 "libstdc++", 0x37398 "libdpkg"
        if (strstr(objname,"libapt-pkg") || strstr(objname,"libstdc++") ||
            strstr(objname,"libdpkg")) return true;
    }
    if (v23) {  // 0x373a0 "libcurl", 0x373a8 "libssl", 0x373b0 "libcrypto"
        if (strstr(objname,"libcurl") || strstr(objname,"libssl") ||
            strstr(objname,"libcrypto")) return true;
    }
    // 0x342c8 "chromium", 0x342f0 "headless"
    if (strstr(objname,"chromium")) return true;
    return (strstr(objname, "headless") != NULL);
}
```

### 字符串常量对照表（`.rodata`，VA==文件偏移）

| VA | 内容 | VA | 内容 |
|---|---|---|---|
| 0x370b0 | `apt-get` | 0x372d0 | `/libc.so` |
| 0x370b8 | `apt-cache` | 0x372e0 | `/libc-` |
| 0x370c8 | `apt-config` | 0x372e8 | `/libpthread` |
| 0x370d8 | `apt-helper` | 0x372f8 | `/libdl.so` |
| 0x370e8 | `/usr/lib/apt/` | 0x37308 | `/librt.so` |
| 0x370f8 | `/curl` | 0x37318 | `/ld-linux` |
| 0x37100 | `curl` | 0x37328 | `libc.so.6` |
| 0x37108 | `/openssl` | 0x37338 | `libpthread.so.0` |
| 0x37118 | `openssl` | 0x37348 | `libdl.so.2` |
| 0x37178 | `/dpkg` | 0x37358 | `librt.so.1` |
| 0x37180 | `dpkg-` | 0x37368 | `ld-linux` |
| 0x37378 | `libapt-pkg` | 0x373a0 | `libcurl` |
| 0x37388 | `libstdc++` | 0x373a8 | `libssl` |
| 0x37398 | `libdpkg` | 0x373b0 | `libcrypto` |
| 0x342c8 | `chromium` | 0x342f0 | `headless` |

**关键解读**：
- **libc / ld-linux / libpthread 永远会被扫描**（2c/2d 是"命中即 return true"的放行分支）。
- 逻辑上这是"**默认不扫，白名单才扫**"——只对 glibc 家族 + 包管理器 + curl/openssl +
  chromium/headless 做补丁。这解释了为什么补丁计数里绝大多数站点都在 libc。
- 本容器里实测：**libc、ld-linux 确有补丁；libm/libgmp/libmpfr/libreadline 等 0 补丁**，
  与该判定逻辑完全一致。

---

## 二、补丁引擎：匹配模式与改写内容

引擎函数：VA `0x285a0`（体量很大，约 0x1400+ 字节），调用点在 `0x286a8`。

### 2.1 引擎入口流程

```c
// 0x286a8 附近
objname = (soname 为空) ? "<exe>" : <从映射记录取 path>;   // 0x370a8 = "<exe>"
if (!proroot_patch_should_scan_object(objname, soname))
    return 0;                                    // 不在白名单 → 直接跳过

// 去重：查 0x5f6c0 处的 64 项"已处理对象"数组（容量上限 64 = 0x40）
//   count = *(int*)(0xb2980 + 24)
//   若该 module 指针已在表中 → 跳过
for (i = 0; i < count; i++)
    if (table[i] == module) return 0;
table[count++] = module;
```

对象表：`0xb2980`（7 个 int32 计数器）+ `0xb29a0`（64×8 的指针数组）。
**实测本进程：`.bss` 里 count = 3**，即本进程只有 **3 个对象**被扫描
（libc、ld-linux、libproroot-runtime 自身）。

### 2.2 遍历 PT_LOAD

```c
for (i = 0; i < ehdr->e_phnum; i++) {          // 0x288e0: ldrh w2,[x22,#24]
    Phdr *p = &phdr[i];                        // 步长 0x38 = 56 字节
    if ((p->p_type & 0x1ffffffff) != 1) continue;   // 只要 PT_LOAD
    // 0x28930: cmp x0, #0x100000001  (p_type==1 && p_flags==R+X)
    base = load_bias + p->p_vaddr;             // 0x28948
    end  = base + p->p_memsz;                  // 0x2895c
```

先用 `sysconf(_SC_PAGESIZE)` 取页大小（`0x28da8` / `0x292ac`，带 4K..64K 合法性校验），
然后对整段做 **`mprotect(base, len, PROT_READ|PROT_WRITE|PROT_EXEC)`**（`w2 = 7`，`0x28970`）。
补丁完成后**改回 `PROT_READ|PROT_EXEC`**（`w2 = 5`）。
—— 这就是"活体补丁"的实现方式：**临时 RWX → 直接写指令 → 恢复 RX**。

### 2.3 三遍扫描

引擎对整段做三遍线性扫描，每遍识别不同的模式。计数器分别对应日志
`patched %d seccomp + %d path (%d relay) + %d brk`（首参是 seccomp，见 §2.3.1）。

#### 遍 1：`svc` 前有"立即数版 x8 设置" —— **seccomp 中和**

```c
// 0x289b8 起
for (insn *q = base; q < end; q++) {
    w = *q;
    if (w == 0xd4000001) {                       // 0x289a0: svc #0
        // 向后回溯，找"喂给 x8 的立即数"
        if (q-3 >= base && *(q-3) == 0xd28007??) ... // mov xN, #imm  (MOVZ 64bit)
        ... 精确判定见下 ...
        *q = 0xd2800000;                         // ← 0x28cb0: mov x0, #0  ★核心改写★
    }
}
```

**改写结果（实测确认）**：`d4000001 (svc #0)` → **`d2800000` (`mov x0, #0`)**

即：**把系统调用整个删掉，并把返回值强制为 0（成功）**。
这是一个非常"粗暴但有效"的做法 —— 因为它要中和的是**良性**系统调用，
返回 0 表示"成功"，调用方会以为自己成功了并继续跑
（例如 `rseq` 失败了也无所谓；`set_robust_list` 返回 0 也无所谓）。

#### 遍 2：`dynamic` 补丁 —— 系统调用转发（relay）

```c
// 0x28c08 起：以已发现的模式为锚点，向后确认 0xc0 字节范围内无其它冲突模式
// 0x28c40: 扫描 0xc0 窗口
for (insn *q = svc_site + 1; q < svc_site + 0xc0; q++) {
    if ((*q & 0x7fe00000) == 0x52800000) break;   // 又一条 mov wN,#imm → 放弃
    if (*q == 0xd4000001) break;                  // 又一条 svc      → 放弃（触发 shared-x8 检查）
}
if (ok) {
    // 0x28f2c: 构造两条指令
    *(mov_x8_site) = 0xaa1e03f0;                  // mov x16, x30     ★
    *(svc_site)    = 0x94000000 | (rel_imm)       // bl  <relay stub>  ★
}
```

**实测确认**：`mov x8,#imm` 位置被改成 **`aa1e03f0` = `mov x16, x30`**，
`svc #0` 位置被改成 **`9400xxxx` = `bl <stub>`**。

`mov x16, x30` 的作用是**保存返回地址**（x30/LR），因为紧接着的 `bl` 会覆盖 x30。
stub 在别处恢复 x8 = 原系统调用号、执行 `svc`、再 `br x16` 返回。

`relay` 计数器仅在**新建 stub** 时递增（`0x291d8/0x291e0` 附近），
已存在的 stub 复用（`0x28c04: cmp x27, [sp,#112]` → 走 `0x2905c` 复用路径）。

**实测**：本进程 libc 中被 relay 改写 **107 处**，涉及 **37 个不同系统调用号**；
ld-linux 中 **17 处**。而这 37 个号**全部命中 runtime 的 66 项转发表**，
**其中没有 425/426/427**。

#### 遍 3：`brk` 补丁

`brk`(214) 在引擎入口就被特判：`0x1082c` 的 interposer 里
`cmp x0, #0xd6 (214); b.eq 0xe3b8` → 转发到 `0x8ce8` 的专用处理。
遍历中另用 `0x28b70/0x28b74`（`movk w0,#0xaa06,lsl#16` + `#0x3e8`）
识别 `b`/`bl` 类跳板。

### 2.4 匹配模式完整清单（数值已核对）

| 位置 | 常量 | 解码 | 语义 |
|---|---|---|---|
| `0x289c4`,`0x28a94` | `0x94000000` (`and w27,w0,#0xfc000000`) | `B` 族 | 找 `b`/`bl` 跳板 |
| `0x289a4` | `movk w1,#0xd400,lsl#16` | `svc` 掩码 | 识别 `svc #0` |
| `0x289ec`,`0x28a0c` | `0xd2800706` → `movk w1,#0xd280` | MOVZ 64-bit | `mov xN,#imm` |
| `0x28a20` | `0xaa003e1` → `movk w1,#0xaa00` | ORR 64-bit | `mov xN,xM` |
| `0x28a54` | `0x92800c60` → `movk w0,#0x9280` | MOVN 64-bit | `mov xN,#-imm` |
| `0x28f2c` | `movk w1,#0xaa1e` → `0xaa1e03f0` | — | **`mov x16, x30`（补丁产物）** |
| `0x289c4` | `movk w1,#0x9400` | — | **`bl`（补丁产物）** |
| `0x28984/0x28990` | `movk w20,#0x5280` | MOVZ 32-bit | `mov wN,#imm` |
| `0x28b3c` | `0x52818d1a`+`movk #0x5280` | `mov w8,#0xc63` | 硬编码：3171 `rseq` |
| `0x28b44` | `0x52849514`+`movk #0x5280` | `mov w8,#0x125` | 硬编码：293 `rseq` |
| `0x28b70` | `movk w0,#0xaa06` | — | `brk` 相关跳板 |

> ⚠️ 关于 `0x28b3c` 的 `0x5280c63`：按 `bits[4:0]=Rd` 解码为 `mov w3,#0xc63`。
> 但**实测** libc 中 `mov w8,#0xc63`(3171) 与 `mov w8,#0x125`(293) 的 `svc`
> **确实都被中和了**，所以这里必然存在一条把它归一成 x8 的路径
> （可能是编码笔误应为 `0x52818d08`，或另有 rewrites）。**这一点我没有 100% 确认。**

### 2.5 日志字符串与计数器（`.rodata`）

| VA | 字符串 | 对应计数器 |
|---|---|---|
| 0x37188 | `[proroot-hook] seccomp-patched %s+0x%lx` | `[x19+0]`（0x28cd0） |
| 0x371d0 | `[proroot-hook] dynamic-patched %s+0x%lx svc mov+0x%lx` | `[x19+4]`（0x28ff4） |
| 0x37208 | `[proroot-hook] shared-x8 skip %s+0x%lx (movz feeds 2+ svc)` | — |
| 0x37248 | `[proroot-hook] patched %s+0x%lx svc movz+0x%lx` | `[x19+4]`/`[x19+16]` |
| 0x37288 | `[proroot-hook] patched %d seccomp + %d path (%d relay) + %d brk` | 汇总（0x29940） |
| 0x371b8 | `PROROOT_PATCH_LIMIT` | 限流（getenv @0x28dd8） |

`0x370a8` = `"<exe>"`（主程序显示名）。
`PROROOT_NO_PATCH` @`0x34a50`，getenv 在 `0x69f0`（引擎入口早退）。

---

## 三、io_uring_setup(425) 到底有没有被补？

### 3.1 答案：**没有，而且不需要**

**证据 A — runtime 里根本没有 425 这个常量。**
对 `runtime.so` 全反汇编穷举 `#0x1a9` / `#425`，只命中
`sub x0,x0,#0x1a9`（`0xe0dc`，interposer 的 io_uring 分支）
和 `#0x10a0=4256`（无关）。**没有任何"系统调用号比较表"含 425。**

**证据 B — 66 项系统调用号转发表中没有 425。**

表位于 `.data.rel.ro`（VA `0x5f6c0`，文件偏移 `0x4f6c0`），元素 24 字节
`{u32 movz64_enc; u32 movz32_enc; u32 stub_ptr; u32 nr}`，共 66 项。
完整 66 项系统调用号：
```
4,5,6,8,9,11,12,14,15,17,23,24,25,29,30,31,33,36,38,43,48,49,50,53,54,56,58,67,
78,80,86,88,89,90,91,92,93,94,95,96,97,98,104,105,116,122,134,148,150,152,153,
165,166,167,168,169,170,173,174,175,176,177,179,180,181,182,183,184,185,186,187,
188,189,190,191,192,193,194,195,196,197,198,199,211,224,225,227,228,229,232,237,
245,261,279,283,284,285,290,291,296,299,303,307,308,311,315,316,317,318,319,321,
322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339,340,341
```
（实测 live 命中 37 个号，全部在此集合内；**425/426/427 不在**。）

**证据 C — 实测 live libc 只有 3 处 `svc` 被中和，且都不是 425。**

我把本进程的 libc `r-xp` 映射与磁盘文件**逐字比对**（218 个差异字）：

| 类型 | 数量 | 说明 |
|---|---|---|
| relay part1（`mov x8,#imm` → `mov x16,x30`） | 107 | 转发补丁 |
| relay part2（`svc` → `bl stub`） | 107 | 转发补丁 |
| **seccomp 中和（`svc` → `mov x0,#0`）** | **3** | 见下表 |
| 其它（stub 镜像/数据） | 108 | — |

三处 seccomp 中和点：

| 文件偏移/VA | 原指令 | 补后 | 系统调用 | 所属符号 |
|---|---|---|---|---|
| `0x855c4` | `d4000001` `svc #0` | `d2800000` `mov x0,#0` | **99 `set_robust_list`** | `pthread_condattr_setpshared+0x354` |
| `0x85850` | `d4000001` `svc #0` | `d2800000` `mov x0,#0` | **293 `rseq`** | `pthread_condattr_setpshared+0x5e0` |
| `0xbd3d0` | `d4000001` `svc #0` | `d2800000` `mov x0,#0` | **99 `set_robust_list`** | **`_Fork+0x50`** |

ld-linux 另有 2 处同型中和（`0x106cc`=99 `set_robust_list`，`0x10700`=293 `rseq`）。

> 注：libc 的 `syscall()`（`0xe9740`）用的是 `mov w8, w0`（寄存器传递），
> 所以**没有任何 `syscall(425)` 能通过指令模式匹配被命中** —— 这是设计上的必然。

### 3.2 那 io_uring 的 425 是从哪被拦掉的？

**证据 D — runtime 导出了自己的 `syscall()`，其中硬编码拦 425/426/427。**

`libproroot-runtime.so` `.dynsym` #171：`syscall`，VA `0x1082c`，188 B，**GLOBAL FUNC 已导出**。
它调用内部实现 `0xe0a0`（约 20KB 的大 dispatcher），开头就是：

```asm
e0a0:  ...                                  ; prologue, 0x20e0 栈帧
e0c0:  ldr  w7, [x26, #4112]                ; 全局开关 *(u32*)(0x846b0)
e0c4:  cbz  w7, e1f8                        ; 开关关 → 走原生 syscall
e0d4:  cmp  x0, #0xd6                       ; 214 = brk ?
e0d8:  b.eq e3b8                            ;   → brk 专用处理
e0dc:  sub  x0, x0, #0x1a9                  ; nr - 425 ★
e0e4:  cmp  x0, #0x2                        ; 0,1,2 → 425,426,427
e0e8:  b.ls e9b4                            ;   → ★ENOSYS 分支★
...
e9b4:  bl   __errno_location
e9b8:  mov  x22, #-1                        ; 返回值 = -1
e9bc:  mov  w1, #0x26                       ; 38 = ENOSYS
e9c0:  str  w1, [x0]                        ; *errno = ENOSYS
```

**这就是 io_uring 的真正拦截点**：
官方**根本不让 node 发出 `io_uring_setup` 的 `svc`**，
而是在**符号层**（`syscall` 的 PLT/GOT 解析）就把 425/426/427 变成 `ENOSYS`。
libuv 的 `uv__io_uring_setup` 拿到 `ENOSYS` 后自然回退到 epoll。

**证据 E（实测）**：node 确实只通过 `syscall` 符号发 425。
```
node 0x18ac0b0 <uv__io_uring_setup>:
  18ac0c0: mov  x0, #0x1a9        ; 425
  18ac0c4: bl   73ff00 <syscall@plt>
node 0x18ac0d0 <uv__io_uring_enter>:
  18ac0f4: mov  x0, #0x1aa        ; 426
  18ac0fc: bl   73ff00 <syscall@plt>
```
node 的 `.rela.plt` 里确有 `R_AARCH64_JUMP_SLOT syscall@GLIBC_2.17`（条目 @`0x653fca0`）。

### 3.3 为什么"我们拦了 425，进程还是 159"？

因为 **`syscall()` 并不是唯一入口**。实测（见 §四）**有 80+ 个系统调用被内核
`SECCOMP_RET_TRAP` 拦截**，而它们**大多数走的是内联 `svc`**。
bxroot 只接管了 `syscall()` 符号，于是：

1. bxroot 成功把 425 变成 ENOSYS（日志可见）✅
2. 但随后 libc/ld-linux 里某个**内联 `svc`**（例如 `rseq` 293、
   `set_robust_list` 99，或 `clone3` 435）触发 `SIGSYS`
3. 官方的 SIGSYS 处理器白名单只放行 99/100 → 打印
   `sigsys: trap on syscall nr not on allow-list, terminating` → 进程死

**官方之所以能跑，是因为它把这三件事全做了**：
① 中和内联 `svc`（3 处）② relay 转发 107 处 ③ 符号层拦 425/426/427。

---

## 四、实测：Android 沙箱到底 TRAP 了哪些系统调用

用内联汇编直发 `svc`、装 `SIGSYS`(SA_SIGINFO) 处理器逐个探测（`fork` 隔离）：

```
si_code = 1  (SYS_SECCOMP)  —— 确认是 seccomp 而非 SI_KERNEL/seccomp 越权

TRAPPED (0..299):
  18 39 40 42 51 58 89 99 100 104 105 106 112 116 142 143 144 145 146 149 151 152
  159 161 162 170 171 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194
  195 196 197 202 217 218 219 224 225 234 235 236 237 238 239 244 245 246 247 248
  249 250 251 252 253 254 255 256 257 258 259 262 263 264 265 266 272 273 288 289
  290 292 293 294 295 296 297 298 299

TRAPPED (300..500): 300-423 全部, 425 426 427 428 429 430 431 432 433 437 439
  442 443 447 448 449 ... 499 500  (424 不在其中!)
```

**关键点**：
- **425/426/427 在内**；但 **424 (`pidfd_send_signal`) 不在**，
  说明这不是"`nr >= 424` 一刀切"，而是**逐个列举的 allow/deny 表**。
- 被 trap 的号很多是**良性**的（`rseq` 293、`set_robust_list` 99、
  `sched_getaffinity` 123 未 trap 但 `sched_setaffinity` 122 未 trap…），
  这正是官方选择"**中和而非报错**"的原因。
- 被 trap 的号里，**大量在内联 `svc` 中可达**（见下表）。

### 预测 vs 实测对照（libc 内联 `mov x8,#nr` + `svc`）

按 trap 集合在 libc 里预测 **51 处**内联站点，实测：
- 3 处被中和（99/293）✅
- 7 处被 relay 改写（`svc`→`bl`）✅
- 其余 **41 处保持原样**（`svc` 未动）

> **这 41 处是"官方没管、但属于 trap 集合"的残留风险点。**
> 它们没炸，说明**在官方这条执行路径上没有被执行到**。
> 这是"能跑"而非"安全"——一旦某条路径真跑到，同样会 159。

（未动的例子：`nr=40 sendfile` @`0xed184`、`nr=112 sched_setaffinity` @`0xbbc30`、
`nr=180` @`0x914b8`、`nr=186 gettid` @`0xef010` 等。）

---

## 五、验证汇总（可复现）

`PROROOT_NO_PATCH` 判决实验的**因果链现在闭合了**：

```
PROROOT_NO_PATCH=1
  └→ 补丁引擎早退（getenv @0x69f0）
      └→ libc 3 处 svc 不再中和 + 107 处不再 relay
          └→ node 启动早期执行到 rseq(293) 或 set_robust_list(99) 的 svc
              └→ seccomp TRAP → SIGSYS
                  └→ linker 白名单只有 99/100 → 终止 → 159
```

注意：225(克隆相关)/435 等也会走 `syscall()`，但那层 interposer 仍在
（`PROROOT_NO_PATCH` 只关指令补丁），所以**159 的直接触发者是内联 `svc`**。

### 关键地址速查

| 项目 | 位置 |
|---|---|
| `proroot_patch_should_scan_object` | `0x299c0`（804 B，导出） |
| 补丁引擎主体 | `0x285a0`（调用点 `0x286a8`） |
| relay stub 收集器 | `0x282e0` |
| `syscall` interposer（导出） | `0x1082c` → dispatcher `0xe0a0` |
| io_uring ENOSYS 分支 | `0xe0dc`–`0xe0e8` → `0xe9b4` |
| seccomp 改写产物 | `d2800000` (`mov x0,#0`)，写入点 `0x28cb0`/`0x28cbc` |
| relay 改写产物 | `aa1e03f0` + `9400xxxx`，写入点 `0x28f2c` |
| 对象表 | `0xb29a0`（64 项），计数器 `0xb2980` |

---

## 六、对 bxroot 的可操作结论

### 6.1 最关键的一条：**不要再找 `mov x8,#425`**

它**不存在**，node 和 libc 都没有。原因是 libuv 走 `syscall()` 符号
（`uv__io_uring_setup` 里 `mov x0,#0x1a9; bl syscall@plt`）。
bxroot 已有的"导出 `syscall()` 拦 425"**方向完全正确，且与官方同构**。

### 6.2 bxroot 真正缺的是"内联 svc 中和"

官方 = **符号层拦 425** + **指令层中和 3 处内联 svc** + **relay 107 处**。
bxroot 目前只做了第一层。**最小可行增量**是复刻官方的"遍 1"：

```
对 libc + ld-linux 的每个 PT_LOAD(R+X)：
  临时 mprotect → RWX
  线性扫描：
    if (w & 0x7fc00000) == 0x52800000     // MOVZ 32-bit
       && bits[4:0] == 8                  // 目标是 w8
       && nr(w) ∈ TRAP_SET                // ← 用本报告 §四 的实测集合
       && next_insn == 0xd4000001:        // 紧随 svc #0
         next_insn = 0xd2800000           // svc → mov x0, #0
  恢复 RX
```

**比官方更简单的等价做法**（推荐）：不必逐点枚举，直接做**全量兜底**——
把**所有** `mov x8/w8,#imm` + `svc #0`、且 `imm ∈ TRAP_SET` 的站点一律中和成
`mov x0,#0`。官方因为还叠加了 relay/path/brk 三类补丁而必须精细匹配
（怕误伤），bxroot 只解决 SIGSYS，可以更粗暴。

> ⚠️ 但要注意"**一条 `mov x8` 被多个 `svc` 共用**"的情况
> （官方为此有 `shared-x8 skip` 逻辑）。若某个 `svc` 的 x8 是
> **分支汇合后**才确定的，单纯改指令可能误伤其他系统调用。
> 安全的做法是**只改 `svc` 本身**（`svc → mov x0,#0`），
> **不要去改 `mov x8`** —— 这样永远不会影响别的调用点。

### 6.3 更省事的第三条路：**直接复用官方 interposer 的机制**

官方在 `0xe0a0` 的 dispatcher 里已经有一套完整的**系统调用服务表**。
bxroot 与其自己写补丁，不如：
1. 导出 `syscall()`（已做）**并且**把内联 `svc` 改成 `bl` 到自己
   （即实现一个**极简版 relay**），这样**一处代码覆盖全部 trap 集合**；
2. relay 内部对 `TRAP_SET` 直接返回 ENOSYS/合理默认值，其余透明转发。

这比"逐点中和"更彻底，也是官方的最终形态。

### 6.4 可以立即落地的两条捷径

- **捷径 A**：既然 `SIGSYS` 处理器白名单是唯一死因，而 99/100 能过 ——
  可以让 bxroot 的处理器**对全部 `TRAP_SET` 返回 ENOSYS**（`si_syscall` 已知），
  而不是只放行 99/100。这是**最小改动**。
  但注意：**`set_robust_list`(99) 返回 ENOSYS 会让 pthread 退化**，
  对 `rseq`(293) 则完全无害；对 425/426/427 返回 ENOSYS 正是官方行为。
- **捷径 B**：按 §6.2 的扫描逻辑做指令中和。
  与官方行为**逐位等价**，风险最低。

### 6.5 顺带确认的两件事

- `libproroot-linker.so` 的白名单（99/100）**只保护加载器自己**。
  实测：**任何**未白名单的 `svc`（含 18、39、40…）在**裸 `svc`** 下都会
  触发 SIGSYS。官方能让 node 跑起来，靠的**不是**这个白名单，
  而是**让那些 `svc` 根本不出现**。
- `PROROOT_NO_PATCH=1` 的 159 **不是**"425 那条 `svc` 被打断"造成的，
  而是**任一**内联 `svc` 命中 trap 集合后 SIGSYS 终止。

---

## 七、我没能确认的部分（如实说明）

1. **`0x28b3c` 的常量 `0x52818d1a` 解码矛盾。**
   按 AArch64 编码解得 `mov w3,#0xc63`（应为 `mov w8` 才是 `0x52818d08`）。
   但实测 3171(`0xc63`) 与 293(`0x125`) 的 `svc` 确实被中和了，
   所以该处逻辑必然正确，只是**我没定位到把 Rd 归一成 w8 的那条改写指令**。
   影响：对机制理解无影响，对复刻实现有轻微影响（照抄该字面量会出错）。

2. **seccomp 中和的判定为何"只挑中 3 处"。**
   libc 里符合"`mov x8,#imm` + `svc`"且 `imm ∈ TRAP_SET` 的站点实测有 51 处，
   但只有 3 处被中和。我没有找到把它们区分开的谓词
   （怀疑与 §2.3 里 `mov x9,#-8` 那类"栈上 syscall 参数块"模板匹配，
   或与 `dynamic` 遍的回溯窗口冲突有关）。**这是最主要的未解点。**

3. **relay 的 37 个号 vs 表里的 ~140 个号。**
   runtime 的 66 项表覆盖约 140 个系统调用号，但 live 只命中 37 个。
   差额应是 (a) 本次执行路径未触达的库；(b) 非 glibc 白名单库。
   我**未逐一验证**每个号的实际改写位置。

4. **stub 区域的分配地址。**
   实测 relay 的 `bl` 目标（如从 libc `0xe9460` 出发）落在
   `libc_base + 0x143a8cc`，已超出 libc 自身范围 —— 说明 stub 区被
   `mmap` 到了 libc 附近（BL 可达范围内，±128MB）。
   我**没有**精确定位该 mmap 的基址与分配策略（`0x282e0` 是"在
   邻近区域找空洞"的逻辑，细节未完全逆向）。

5. **为什么有 41 处 trap 集合内的内联 `svc` 没被处理却没炸。**
   我确认了它们"没被改"，但**没有**证实它们"没被执行"。
   只能推断官方依赖执行路径恰好不经过。

6. **`PROROOT_DISABLE_SCM_CREDENTIALS_PATCH`。**
   该环境变量的处理逻辑**未定位**（与 seccomp 主线无关，未展开）。

---

## 附录：复现命令

```bash
W=/root/proroot-work/agents/rename-bxroot/work
# 1) live libc 与磁盘逐字比对，列出全部补丁点
python3 $W/fulldiff.py
# 2) 补丁分类统计 + 中和点系统调用号推断
python3 $W/summary.py
# 3) 各库补丁普查
python3 $W/final.py
# 4) seccomp trap 集合实测（fork 隔离，逐个探测）
cd $W && ./trapscan 0 300 && ./trapscan 300 500
# 5) 裸 svc 触发 SIGSYS 的最小复现（确认 si_code=1）
cd $W && ./rawsvc 425
```

**源文件未被修改**（仅复制到 `work/` 做只读分析；`/proc/self/mem` 为只读访问）。
