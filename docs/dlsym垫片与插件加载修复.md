# `dlsym` 垫片与 `dsh web` 插件加载修复

> 任务：让 `dsh web` 的插件能加载。
> 验收点：`requireBuiltin("internal/modules/esm/loader")` 从 `Unsupported/no-context` 变成 `OK ✅`。
>
> **结论先行：已修复。验收点达成，且 `dsh web` 完整启动并对外提供 HTTP 服务。**
>
> 根因**不是一个而是两个**，必须同时修好才通：
> 1. **`dlsym` 未导出** → N-API 模块的 `dlsym(RTLD_DEFAULT, …)` 恒 NULL → `no-context`
> 2. **`dladdr` 的 `dli_fbase` 恒 NULL** → 插件的镜像一致性校验失败 → `no-realm`
>
> 只修第 1 个会停在 `no-realm`（这是本轮实际走过的中间态，有原始输出）。
>
> 所有结论均附**可复跑命令 + 原始输出**。本文严格区分「实测」与「未验证」。

---

## 0. 环境与复现基线

```sh
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"        # 内核视角（给 --preload）
STAGE_MKDIR="/tmp/bxroot-e2e"              # 容器视角（给 cp/mkdir）

export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
       BXROOT_FAKEROOT=1 BXROOT_GUEST_EXE=/usr/local/bin/node
unset NODE_OPTIONS

"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
  --preload "$STAGE_LOAD/libbxroot-runtime.so" \
  "$ROOTFS/usr/local/bin/node" "$STAGE_LOAD/napi.js"
```

**严格对照原则**：同 bridge、同 linker、同 node，**只换 `--preload`**。
对照组 `liboff-runtime.so` = 官方 `libproroot-runtime.so`（`/root/proroot-work/backup/`）副本。

### 0.1 ★ 一处必须记下的环境坑：bxroot linker 根本不能用 ★

任务描述里给的复现命令用的是 `$APP_LIB/libproroot-linker.so`（官方 linker）+ `--preload libbxroot-runtime.so`。
**这是正确的组合**。但本文档早期任务书里出现过「用 `build/libbxroot-linker.so` 当 linker」的方案，
这里明确记录**实测否定**：

```
$ nm -D --defined-only build/libbxroot-linker.so
0000000000000390 T dlclose
0000000000000430 T dlopen
00000000000002e0 T dlsym          ← 只有 3 个纯转发符号，92 行 stub

$ ... --preload probe5.so node nop.js   （用 bxroot linker）
（零输出）
Illegal instruction    rc=132
```

bxroot linker 在任何 `--preload` 下都**在客户程序跑到 main 之前就 SIGILL**（零输出）。
这是既有事实（`docs/parity-补齐报告.md` 已述），**不是本轮引入**。
因此本轮全部修复都在「官方 linker + bxroot runtime」这条真实链路上做。

### 0.2 `/tmp/bxroot-e2e/` 会被并发清理

本轮再次复现该现象（探针 `.node`、`.js` 一度消失，导致
`Cannot find module '/data/data/.../napi.js'` 这种**与被测问题无关**的报错）。
**判据**：报错里出现 `Cannot find module` + 内核视角路径时，先确认文件还在，不要当成缺陷。

---

## 1. 基线复现（改前）

### 1.1 bxroot：失败

```
$ sh run.sh build/libbxroot-runtime.so napi.js
node[1]: pthread_create: Invalid argument
=== N-API 模块加载与 dlsym 探测 ===
require(addon): OK
  导出: requireBuiltin, isAllowedInternalId, getBindingInfo, default
  requireBuiltin 抛错: node-addon-require-builtin unsupported: Unsupported/no-context (required V8 current-context symbols were not found)
rc=0
```

### 1.2 官方：成功

```
$ sh run.sh liboff-runtime.so napi.js
=== N-API 模块加载与 dlsym 探测 ===
require(addon): OK
  导出: requireBuiltin, isAllowedInternalId, getBindingInfo, default
  requireBuiltin(esm/loader): OK ✅
rc=0
```

**A/B 成立**：同命令、同参数，唯一变量是 `--preload` 的运行时。

---

## 2. 根因一：`dlsym` 未导出 → N-API 模块的符号视图为空

### 2.1 失败的符号是什么

`node-addon-require-builtin` 的 `.node` 里，查找函数只有 4 条指令
（反汇编 `LookupPlatformProcessSymbol` @0x1d464）：

```asm
1d478:  mov  x1, x0          ; name
1d47c:  mov  x0, #0x0        ; handle = NULL  ← 即 RTLD_DEFAULT
1d480:  bl   10280 <dlsym@plt>
```

它要找的符号（`strings` 可见）：

```
_ZN2v87Isolate10GetCurrentEv            ← Isolate::GetCurrent
_ZN2v87Isolate17GetCurrentContextEv     ← Isolate::GetCurrentContext
_PZN4node14PrincipalRealm22builtin_module_requireEv
```

### 2.2 探针：从 `.node` 内部测（真实语境）

按任务书的教训（探针必须放在被 proroot 加载器装入的语境里），
本轮**没有再写主程序探针**，而是编了一个真 N-API 模块 `probeapi2.node`
（`process.dlopen` 装入，与 addon 完全同一条路径）。

同一份 `.node`，两个运行时的原始输出：

```
######## 官方 runtime ########
---- probe @ .node 加载期（构造函数） ----
  dlsym(NULL, malloc)                            = 0x771d237490  [libc.so.6]
  dlsym(NULL, napi_create_function)              = 0x876a34      [node]
  dlsym(NULL, _ZN2v87Isolate10GetCurrentEv)      = 0xc03360      [node]
  &dlsym                                         = 0x771d6aae90  [liboff-runtime.so]

######## bxroot runtime ########
---- probe @ .node 加载期（构造函数） ----
  dlsym(NULL, malloc)                            = (nil)
  dlsym(NULL, napi_create_function)              = (nil)
  dlsym(NULL, _ZN2v87Isolate10GetCurrentEv)      = (nil)
  &dlsym                                         = 0x76e80c3590  [libc.so.6]
```

**判据**：`dlsym(RTLD_DEFAULT, …)` 在 bxroot 下对**一切符号**返回 NULL ——
不只是 V8 符号，连 `malloc` 也是 NULL。所以问题不在"缺某个符号"，
而在**符号视图整体为空**。

### 2.3 为什么"让 libc 接管"不成立

这里推翻的是**本仓库自己此前写在 `preload.c` 里的结论**：

> 原文（现已改写）：*「不导出比导出更正确。少这 4 个符号不影响任何真实功能
> （客户 `dlsym(RTLD_DEFAULT, "dlsym")` 依然由 libc 满足）」*

**实测证伪**：proroot 用**自研 loader**（官方 `libproroot-linker.so`，
自带 PT_LOAD 映射 / 重定位流水线），而 glibc 的 `dlsym` 依赖
**glibc 自己那套 loader 状态**。两者拼在一起就是不自洽：

| 组合 | `dlsym(RTLD_DEFAULT, …)` 结果 |
|---|---|
| 自研 loader + **自研** `dlsym`（官方 runtime 的做法） | ✅ 正确 |
| 自研 loader + **libc** `dlsym`（bxroot 改前） | ❌ 全 NULL |

所以修法不是"别导出"，而是"**像官方那样自己实现一个**"。

### 2.4 关键协议：linker 服务

官方 runtime 的 `dlsym`（@0x22e90）不调用 libc，而是走 linker 提供的私有服务：

```asm
22ea8:  b.eq  22f8c                      ; handle == RTLD_NEXT(-1)
22f8c:  mov   x0, x30                    ; ★ 传**调用方的返回地址**
22f94:  bl    ldso_service_dlsym_next_from@plt
22f14:  mov   x1, x19
22f18:  bl    ldso_service_dlsym@plt     ; handle == NULL / RTLD_DEFAULT(-2)
```

官方 linker 在**加载 runtime 时**按名字（`strings` 可见）把这 6 个服务填进 PLT：

```
ldso_service_dlsym
ldso_service_dlsym_next_from
ldso_service_dlsym_global
ldso_service_dl_iterate_phdr
ldso_service_find_object_by_addr
ldso_service_find_object_by_handle
```

### 2.5 ★ 等价性实测（这是本轮最重要的安全性依据）★

把内部解析从 libc 换成服务，**必须证明语义不变**，否则会静默改坏 141 处钩子的真身解析。

在**同一个函数**里同时取两个值，对 `preload.c` 内部解析的**全部 133 个符号名**逐一比对：

```c
a = dlsym(RTLD_NEXT, name);                                  /* libc 原生 */
b = ldso_service_dlsym_next_from(__builtin_return_address(0), name);  /* linker 服务 */
```

原始输出（官方 linker 上下文）：

```
=== probe12: libc RTLD_NEXT vs linker 服务 等价性 ===
小结: 共 133, 相等 133（其中同为 NULL 2）, 不等 0
```

- **相等 133 / 不等 0** ⇒ 换用服务是**行为保持**的。
- 那 2 个「同为 NULL」是 `newfstatat` / `newfstatat64` ——
  glibc 2.33+ 已删除这两个导出（只是 `fstatat` 的旧别名），
  `preload.c` **本来就有** `fstatat` 回退，属预期。

> **给后续排查者的提示**：看到 `[NEXT] newfstatat = (nil)` **不要**当成缺陷。
> 判据是「libc 的 `dlsym(RTLD_NEXT,"newfstatat")` 是否也是 NULL」——
> 本实测证明两者同为空。

### 2.6 实现

`src/runtime/preload.c` 新增：

```c
extern void *ldso_service_dlsym(void *handle, const char *name);
extern void *ldso_service_dlsym_global(const char *name);
extern void *ldso_service_dlsym_next_from(void *retaddr, const char *name);

__attribute__((noinline))
static void *bxroot_next_symbol(const char *name) {
    if (bxroot_has_ldso_service())
        return ldso_service_dlsym_next_from(__builtin_return_address(0), name);
    return dlsym(RTLD_NEXT, name);   /* 非 proroot 环境的回退 */
}

void *dlsym(void *handle, const char *symbol) {
    if (symbol == NULL) return NULL;
    if (bxroot_has_ldso_service()) {
        if (handle == RTLD_NEXT)
            return ldso_service_dlsym_next_from(__builtin_return_address(0), symbol);
        if (handle == NULL || handle == RTLD_DEFAULT)
            return ldso_service_dlsym(NULL, symbol);
        return ldso_service_dlsym(handle, symbol);   /* 具体句柄 */
    }
    return NULL;
}
```

并把文件内 **141 处** `dlsym(RTLD_NEXT, "x")` 机械替换为 `bxroot_next_symbol("x")`
（只换函数名，签名与语义不变；§2.5 已证明等价）。

### 2.7 ★ 三个必须记住的陷阱（本轮全部踩过并有实测）★

#### 陷阱 A：`dlsym` 里不能"取真身再转交"

直觉写法是「先用服务取到真 `dlsym`，再把具体句柄转交给他」。**实测会自引用**：

```
$ probe16（本 .so 导出 dlsym，无 runtime preload）
&本.so dlsym = 0x7b9e6074a8
service_global(NULL,"dlsym") = 0x7b9e6074a8   (是否==本.so? ★是★)
```

`ldso_service_dlsym(NULL, name)` 是**全局查找**，会优先命中搜索链最前面的本库。
转交即自递归。加一层「等于自己就返回 NULL」的防御后，症状变成
`Module did not self-register`（node 的 `dlsym(handle, …)` 拿到 NULL）——
**这个报错是本轮实际观察到的中间态**，不是推测。

> ✔ 正确做法：贴**具体句柄**的查找直接用服务的带句柄入口
> `ldso_service_dlsym(handle, symbol)`。实测它正确解析：
> ```
> service dlsym(libc_handle, "malloc")                     = 0x…8490 [libc]
> service dlsym(node_addon_handle, "napi_register_module_v1") = 0x…2020 [该 .node]
> ```
> 而那个 handle 正是本库 `dlopen` 返回的（本库 `dlopen` 纯转发给 libc），类型一致。

#### 陷阱 B：`dlopen` 的真身解析**不能**走服务（否则栈耗尽）

把 `dlopen` 也改成走服务后**段错误**。加诊断输出后看到：

```
[DLOPEN-RES] q=0x7b769a99b0 [.../libbxroot-runtime.so] dlopen_self=0x7b769a99b0 SELF!
```

**服务把本库自己的 `dlopen` 返回了回来** → 调用它无限递归 → 栈耗尽。

**为什么 `bxroot_next_symbol` 没这个问题、`dlopen` 有**：
`next_from(retaddr, …)` 用 `retaddr` 定位"调用方在 link_map 中的位置"，再从**其后**搜索。
- `bxroot_next_symbol` 是 `static` + `noinline`，**调用方必然在本库内部** → 搜索起点在本库之前 → 正确越过本库；
- `dlopen` 是**导出符号**，调用方可能在库外（libc / ld.so 初始化 / node 的装载路径）→ "其后"绕回本库 → 命中自己。

> ✔ 结论：`dlopen` 保持原有已验证写法 `dlsym(RTLD_NEXT, "dlopen")`。
> 这**不会**成环：本库的 `dlsym` 在 `RTLD_NEXT` 分支走服务、不回到 libc 的 `dlsym`，
> 故不存在 dlsym↔dlopen 相互调用。

#### 陷阱 C：`bxroot_has_ldso_service()` 不能在构造函数里缓存死

本库的构造函数在某些 loader 场景下**早于** linker 填完 PLT。
判定改为首次使用时求值 + 结果缓存（`static int cached = -1`），
一次查表成本，热路径上早已被"指针非空"短路。

### 2.8 改完第 1 个根因后的中间态（**这是任务书预期的验收点已达成**）

```
$ sh run3.sh off build/libbxroot-runtime.so napi.js
=== N-API 模块加载与 dlsym 探测 ===
require(addon): OK
  导出: requireBuiltin, isAllowedInternalId, getBindingInfo, default
  requireBuiltin(esm/loader): OK ✅        ← ★ 验收点达成 ★
rc=0
```

**但 `dsh web` 仍然起不来**——它换了个错法。继续往下查是必要的。

---

## 3. 根因二：`dladdr` 的 `dli_fbase` 恒 NULL

### 3.1 新的报错

插件链走到下一步后报：

```
requireBuiltin 抛错: node-addon-require-builtin unsupported:
    Unsupported/no-realm (realm vptr image does not match getter image)
```

### 3.2 定位：校验逻辑读的就是 `dli_fbase`

反汇编 `ValidatePlatformRuntimeImagePointers` @0x1d4f4，
它对两个地址各调一次 `dladdr`，然后比较**同一个字段**：

```asm
1d528:  bl  107d0 <dladdr@plt>      ; dladdr(地址1, &info1)
1d534:  ldr x0, [sp, #88]           ; info1.dli_fbase
1d5a4:  bl  107d0 <dladdr@plt>      ; dladdr(地址2, &info2)
1d5b0:  ldr x0, [sp, #56]           ; info2.dli_fbase
...
1d640:  ldr x1, [sp, #96]           ; fbase1
1d644:  ldr x0, [sp, #64]           ; fbase2
1d648:  cmp x1, x0
1d64c:  b.eq 1d694                  ; 相等 → Ok
        → 否则 "realm vptr image does not match getter image"
```

### 3.3 实测：bxroot 下 `dli_fbase` 就是 NULL

同一个 `.node`、同一个地址，两个运行时对照（`probeapi3` stage 17/18）：

```
######## 官方 runtime ########
  getter=0x9a2930 dladdr=1 fname=…/usr/local/bin/node fbase=0x400000
  v8gc  =0xc03360 dladdr=1 fname=…/usr/local/bin/node fbase=0x400000

######## bxroot runtime（改前）########
  getter=0x9a2930 dladdr=1 fname=…/usr/local/bin/node fbase=(nil)   ★
  v8gc  =0xc03360 dladdr=1 fname=…/usr/local/bin/node fbase=(nil)   ★
```

**判据**：`fname` 有值只是巧合（glibc 从 maps 猜的），
`dli_fbase` 恒为 NULL ⇒ 两个地址的 fbase 都是 NULL，
在插件的判据里「NULL == NULL」**并不成立**（它要求来自**同一个已加载镜像**，
NULL 被当作"不在任何镜像里"）。同一个根因（自研 loader + libc 的 dl* 不自洽）。

### 3.4 `dl_iterate_phdr` 的差异（同一根因的另一面）

```
######## bxroot ########
  [1] name=…/usr/local/bin/node addr=(nil) phnum=10
dl_iterate_phdr 返回 0, 回调命中 1 个对象        ← 只看到主程序

######## 官方 ########
  [1] name=…/usr/local/bin/node
  [3] name=…/liboff-runtime.so  addr=0x78d9088000
  [4] name=…/probe18.so         addr=0x78da437000
  [9] name=…/libc.so.6          addr=0x75df180000
dl_iterate_phdr 返回 0, 回调命中 11 个对象       ← 完整对象列表
```

glibc 的 `dl_iterate_phdr` 同样只看得到主程序 ⇒ 它的 `dladdr` **无数据可填 fbase**。

### 3.5 实现：照抄官方的做法（**不自己解析 ELF**）

官方 `dladdr`（@0x23080）自己没有遍历任何链表，而是：
准备一个 walk 结构 → 调 `ldso_service_dl_iterate_phdr(内部回调, &walk)` →
回调里按 PT_LOAD 区间命中就填 fbase/fname 并返回非 0 停止。
回调 ABI 由官方 `proroot_dladdr_walk_cb` @0x22d40 **逐条坐实**：

```asm
22d40:  ldr  x1, [x0, #16]     ; dlpi_phdr     （x0 = struct dl_phdr_info *）
22d4c:  ldrh w7, [x0, #24]     ; dlpi_phnum
22d7c:  ldr  x3, [x8]          ; dlpi_addr
22d8c:  add  x3, x3, x9        ; vstart = dlpi_addr + p_vaddr
22d90:  csel x6, x6, x3, ne    ; ★ x6 为 0 时记下 vstart（首个 PT_LOAD）
22d9c:  ccmp x0, x3, #0x0, cc  ; vstart <= addr < vstart+p_memsz ?
22dd4:  stp  x6, x1, [x2, #8]  ; w->fbase = x6 ; w->fname = x1
```

按同一形状实现（`src/runtime/preload.c`）：

```c
struct bxroot_dladdr_walk { const void *addr; void *fbase; const char *fname; int ptype; };

static int bxroot_dladdr_walk_cb(struct dl_phdr_info *info, size_t size, void *data) {
    struct bxroot_dladdr_walk *w = data;
    if (info == NULL || info->dlpi_phdr == NULL || info->dlpi_phnum == 0) return 0;
    unsigned long first_load = 0, a = (unsigned long)w->addr;
    for (unsigned i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        unsigned long vstart = (unsigned long)info->dlpi_addr + (unsigned long)ph->p_vaddr;
        unsigned long vend   = vstart + (unsigned long)ph->p_memsz;
        if (first_load == 0) first_load = vstart;      /* 对应 csel */
        if (a >= vstart && a < vend) {
            w->fbase = (void *)first_load;             /* ★ 不是 dlpi_addr */
            w->fname = info->dlpi_name ? info->dlpi_name : "";
            w->ptype = (int)ph->p_type;
            return w->ptype;
        }
    }
    return 0;
}
```

### 3.6 ★ 一处我写错又改对的细节：`dli_fbase` ≠ `dlpi_addr` ★

初版把 `fbase` 写成 `dlpi_addr`，实测**主程序仍然得到 NULL**：

```
[DLADDR] 服务返回 1 ptype=1 fbase=(nil) fname=…/usr/local/bin/node
```

原因：主程序的 `dlpi_addr == 0`（它按 p_vaddr 就地映射，不重定位）。
而官方的 `csel` 记的是**首个 PT_LOAD 的 `vstart`**，主程序即 `p_vaddr`（`0x400000`）。
改成 `first_load` 后：

```
  getter=0x9a2930 dladdr=1 fname=…/usr/local/bin/node fbase=0x400000   ← 与官方逐位一致
  v8gc  =0xc03360 dladdr=1 fname=…/usr/local/bin/node fbase=0x400000
```

**记录此处的价值**：这正是"看起来合理的实现（用 dlpi_addr）"与
"实测对齐官方"之间的差别 —— 若不照官方逐条读，会得到一个
「共享库对、主程序错」的半成品，而插件恰好查的是**主程序**里的 V8 符号。

### 3.7 ★ 红线合规说明 ★

本实现**没有**自研 ELF 重定位器 / 加载器（红线 CL-13），
**没有**让 `dlopen`/`dlsym` 偏离透传（红线 CL-14）：

| 关注点 | 做法 |
|---|---|
| 对象枚举、加载基址、段表 | **全部**来自 linker 服务 `ldso_service_dl_iterate_phdr` |
| `dlsym` 的真身解析 | **全部**来自 linker 服务 `ldso_service_dlsym*` |
| 本库自己做的事 | **只是区间比较与分派**（`vstart <= addr < vend`、按 handle 选分支） |
| `dlopen` | 仍是原有的纯路径翻译 + 转发给 libc |

`dladdr` 与官方 runtime 里的对应函数是**同一个形状**（甚至同一套 ABI 假设）。

---

## 4. 为什么没有一并实现 `dlerror` / `dl_iterate_phdr` / `dladdr1` / `dlinfo`

任务书建议"官方导出全套，照做更稳"。本轮**只导出 `dlsym` 与 `dladdr`**，理由如下（诚实说明）：

| 符号 | 本轮状态 | 理由 |
|---|---|---|
| `dlsym` | ✅ 已实现 | 客户失败点，实测闭合 |
| `dladdr` | ✅ 已实现 | 第二失败点，实测闭合 |
| `dlerror` | ❌ 未实现 | **TLS 错误码语义**。官方在自己的 `dlerror` 里直接读写 `tpidr_el0` 偏移处的 TLS（反汇编 @0x22fa0 可见 `mrs x1, tpidr_el0` + 固定偏移）。要复刻就得先坐实 `__libc_dlerror_result` 的布局；**做错比不做更糟** —— 客户会拿到垃圾字符串而不是"没有错误"。而 `dladdr`/`dlsym` 失败路径上客户主要看返回值，不看 dlerror 文本 |
| `dl_iterate_phdr` | ❌ 未实现（**但服务可以直接用**） | 客户若直接调 glibc 版，在 bxroot 下只能看到主程序（§3.4）。**目前没有观察到客户依赖它**；若将来需要，实现方式已探明（服务入口 + §3.5 的 ABI） |
| `dladdr1` / `dlinfo` | ❌ 未实现 | 未观察到客户使用；语义面更大（RTLD_DL_LINKMAP 等） |

**这不是"没做"，而是"按证据决定不做"**：`dsh web` 的失败链已闭合，
在没有失败证据的地方扩大符号接管面，只会扩大风险面（每个被接管的 `dl*`
都要重新证明"与 glibc 行为一致"，见 §2.5 那类等价性验证的成本）。

---

## 5. 端到端结果（全部实测）

### 5.1 ★ 验收标准 1：`requireBuiltin` ✅

```
$ sh run3.sh off build/libbxroot-runtime.so napi.js
=== N-API 模块加载与 dlsym 探测 ===
require(addon): OK
  导出: requireBuiltin, isAllowedInternalId, getBindingInfo, default
  requireBuiltin(esm/loader): OK ✅
rc=0
```

官方对照：

```
$ sh run3.sh off liboff-runtime.so napi.js
=== N-API 模块加载与 dlsym 探测 ===
require(addon): OK
  导出: requireBuiltin, isAllowedInternalId, getBindingInfo, default
  requireBuiltin(esm/loader): OK ✅
rc=0
```

**两边输出逐行一致。**

### 5.2 ★ 真正的目标：`dsh web` 完整启动并可服务 ✅

```
$ sh rundsh.sh build/libbxroot-runtime.so web --no-open --port 44992
node[1]: pthread_create: Invalid argument
dsh web: http://127.0.0.1:44992/?token=IA2oxQlToY0gVdgCMEwhfoxGZwTbFU_ISE73sEtM4Vg

--- curl 根路径 HTTP 状态 ---
http_code=303 size=0
--- 等待进程状态 ---
✅ 进程仍然存活（40 秒后）
```

**判据**：打印了 URL（说明 profile + 全部插件装载完成才可能打印）、
HTTP 有响应、进程稳定存活。
**且日志里 `Cannot find package` 计数为 0**（这正是原缺陷的报错文本）。

补充正向证据 —— 五个插件在配置树里都在，且与官方**数量一致**：

```
$ bxroot:  dsh web --dump-config   rc=0
  device-shell-guide   3      task-notifier   3      status-overlay   3
  web-mobile           3      app-integration 3
$ 官方:    dsh web --dump-config   rc=0
  device-shell-guide   3      task-notifier   3      status-overlay   3
  web-mobile           3      app-integration 3
```

### 5.3 加分项：`dsh web --help` ✅

```
$ sh rundsh.sh build/libbxroot-runtime.so web --help
Usage: dsh --profile web [options]
Serve the DeepSeek Harness browser UI.
...
rc=0
```

### 5.4 ★ 验收标准 3：不回归 ✅

**`cspawn4` 仍 `rc=0 ×4`**（bxroot）：

```
$ sh /root/l2sfix/run_cspawn4.sh libbxroot-runtime.so
=== 变体对照 ===
posix_spawn  /bin/true + environ           rc=0   OK
posix_spawn  host路径 + environ            rc=0   OK
posix_spawn  空环境                        rc=0   OK
posix_spawn  空argv[0]=NULL                rc=0   OK
```

（官方 runtime 对照同样 `rc=0 ×4`，两边一致。）

**`spawnSync("/bin/echo")` 仍 `status=0 out="ok\n"`**：

```
$ sh run3.sh off build/libbxroot-runtime.so spawnsync.js
=== spawnSync(/bin/echo) ===
status=0 out="ok\n" err=(无)
=== execSync(/bin/echo ok) ===
out="ok\n"
rc=0
```

### 5.5 ★ 验收标准 2：`sh test/RUN_ALL.sh` ✅

```
  ✅ 编译告警门禁       ✅ 零告警（检查了 11 个编译单元）
  ✅ l2s 运行时            RESULT: PASS
  ✅ l2s×fakeroot 协同     RESULT: PASS
  ✅ fakeroot 纯逻辑       RESULT: PASS
  ✅ 系统调用参数位置 RESULT: PASS
  ✅ rename/link 双路径    RESULT: PASS
  ✅ crash 崩溃处理器    RESULT: PASS
  ✅ D4 进程管理             断言门禁：通过
  ✅ 运行时构建             ✅ D4 进程管理符号全部导出（23/23）
  ✅ proot CLI 兼容         RESULT: PASS
  ⚠️  l2s 端到端契约      rc=1    （已知缺陷）
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/wait4 均已导出
------------------------------------------------------
  通过 11 / 失败 0 / 已知缺陷 1
  ✅ 全部通过
rc=0
```

**与任务书预期的"10/10"差异说明**：当前是 **11 通过 / 0 失败 / 1 已知缺陷**，
比任务书多一项（`proot CLI 兼容`，另一个 agent 新增），
且 `l2s 端到端契约` 被 `RUN_ALL.sh` **显式登记为已知缺陷**（`KNOWN_FAIL="l2s 端到端契约"`，
失败记 `KNOWN` 不计 `FAIL`）。**回退码 rc=0，全绿。**

`l2s 端到端契约` 这一项**确认与本轮改动无关**（A/B 实证）：

| 运行时 | `RUN_L2S_E2E.sh` 结果 |
|---|---|
| 改前版本（`preload.c.bak` 重建） | `RESULT: FAIL — l2s 的 stat 伪装未生效` |
| 改后版本（本轮修复） | `RESULT: FAIL — l2s 的 stat 伪装未生效`（**逐字相同**） |

**两侧输出完全一致 ⇒ 非本轮引入。** 该缺陷根因方向已由另一个 agent
记录在 `docs/l2s-stat伪装修复.md`（与 `src/runtime/preload.c` 的 stat 钩子接线相关，
**不是**我改的真身解析路径 —— §2.5 已证明 stat/lstat/fstatat/*xstat 等 133 个
名字的解析在改动前后逐个等价）。

### 5.6 零告警门禁 ✅

```
$ sh test/RUN_WARN_GATE.sh
✅ src/runtime/preload.c              0 条
...
✅ 零告警（检查了 11 个编译单元）
```

> 说明：运行期间 `uname` 处一度出现 2 条 `-Wstringop-overread`
> （`strnlen(字面量, 64)`，gcc 对"界限大于源对象"的已知误报）。
> 那是**另一个 agent** 同时改 `uname` 引入的（本轮的符号解析改动不涉及 `uname`）。
> 本轮用 `__attribute__((noinline))` 包一层 `bxroot_bounded_strlen()` 消除该误报
> —— 而非用 `-Wno-` 掩盖（门禁的注释明确禁止那种做法）。语义不变。

### 5.7 最终产物构建记录（含 ICE 重试）

最终一次干净重建**触发了容器的间歇性 gcc ICE**，按 `BUILD_RUNTIME.sh` 的设计逐级回退：

```
== 构建 libbxroot-runtime.so ==
   起始优化   : -O2
   gcc ICE（-O2 第 1..10 次），重试
   ⚠️  -O2 连续 10 次 ICE，回退下一级优化
   gcc ICE（-O1 第 1..8 次），重试
   ✅ 链接成功（-O1，第 9 次尝试）
   大小: 229776 字节
   导出符号（nm -D --defined-only）: 344
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
```

**这不是本轮引入的问题**：脚本头部的注释早已记录该现象
（"本容器 aarch64 gcc 13.3.0 有**间歇性 ICE**……同一条命令重试几次往往就过"）。
过程中**产物始终未被破坏**（脚本"构建到临时文件再 mv"的设计生效，
`build/*.tmp` 无残留），且 ICE 期间用旧产物跑验收 1 仍然通过 —— 这正是该设计要保证的。

### 5.8 导出符号 / 未定义符号核对 ✅

```
$ nm -D --defined-only build/libbxroot-runtime.so | grep -wE 'dlopen|dlsym|dladdr'
000000000000c750 T dladdr
000000000000c664 T dlopen
00000000000075d0 T dlsym

$ nm -D -u build/libbxroot-runtime.so | grep ldso
                 U ldso_service_dl_iterate_phdr
                 U ldso_service_dlsym
                 U ldso_service_dlsym_global
                 U ldso_service_dlsym_next_from
```

四个服务符号保持**未定义**（由 linker 装载时填 PLT）—— 这一点很关键：
若本库自己定义它们，就会**覆盖** linker 的实现，整套机制失效。

---

## 6. 改动清单

| 文件 | 改动 | 说明 |
|---|---|---|
| `src/runtime/preload.c` | 新增 `bxroot_has_ldso_service()` | 探测 linker 服务是否可用（首次求值后缓存） |
| `src/runtime/preload.c` | 新增 `bxroot_next_symbol()` | 符号解析统一入口（服务优先，libc 回退），`static`+`noinline` |
| `src/runtime/preload.c` | 新增 `dlsym()` | 自研分派：RTLD_NEXT / RTLD_DEFAULT / 具体句柄 |
| `src/runtime/preload.c` | 新增 `dladdr()` + `bxroot_dladdr_walk_cb()` | 用服务枚举对象填 `dli_fbase` |
| `src/runtime/preload.c` | **141 处** `dlsym(RTLD_NEXT,"x")` → `bxroot_next_symbol("x")` | 机械替换，§2.5 证明等价 |
| `src/runtime/preload.c` | `dlopen` 真身解析**保持** libc 路径 | 改走服务会自递归（§2.7 陷阱 B） |
| `src/runtime/preload.c` | `bxroot_bounded_strlen()` + `uname` 宏 | 消除 `uname` 处 2 条误报告警（§5.6） |
| `BUILD_RUNTIME.sh` / `Makefile` | **未改** | 无新增源文件 |

**未触碰**（按硬约束）：`src/proc/proc.c`、`src/proc/proc.h`、
`src/runtime/syscall_guard.c`、`src/runtime/fakeroot.c`、
`test/RUN_WARN_GATE.sh`、`BUILD_RUNTIME.sh`、`test/RUN_ALL.sh`、`src/launcher/launcher.c`。

---

## 7. 未验证 / 已知限制（诚实清单）

1. **`bxroot_has_ldso_service()` 在非 proroot 环境返回 0 时，
   本库的 `dlsym` 一律返回 NULL。**
   实测本容器（官方 linker + 本运行时）**始终**有服务，故不影响 DSHA 路径；
   但若有人把本库 `LD_PRELOAD` 进普通 glibc 进程（例如跑单测），
   该进程里的 `dlsym` 会失效。**这是本轮明确接受的取舍**：
   在"返回 NULL"与"递归炸栈（历史 core dump）"之间选前者。
   *未验证*：是否有测试路径真的这样用。 `RUN_WAIT_TESTS.sh` 用 dlopen 打开
   产物 + dlsym 取符号，实测 **PASS（14 cases / 52 checks，0 failed）**，
   说明至少这条常用路径不受影响。

2. **`dl_iterate_phdr` 未接管** —— 客户若直接调用它，在 bxroot 下仍只能
   看到主程序（§3.4 实测）。本轮未观察到客户依赖它。

3. **`dlerror` / `dladdr1` / `dlinfo` 未实现**（§4）。特别是 `dlerror`：
   目前客户拿到的是 glibc 版的错误字符串，而解析实际走 linker 服务，
   两者**可能不一致**。本轮的判断是"没观察到依赖"，**不是"已证明无影响"**。

4. **`dlopen` 仍走 libc** —— 这意味着被 `dlopen` 装载的对象其
   符号视图由 libc 维护，而解析由服务完成。实测两者在本容器的组合下
   工作正常（`.node` 能装载并解析 `napi_register_module_v1`），
   但这是**两条实现拼接**，未来 glibc 或 linker 任一侧变更都可能打破。
   *未验证*：`RTLD_GLOBAL` 的全局可见性语义是否与原生完全一致。

5. **`dsh web` 的完整交互未逐项验证** —— 只验证了「启动成功 + 打印 URL +
   HTTP 303 + 存活 40 秒 + 配置树含全部 5 个插件」。
   浏览器端交互、各插件运行时行为**未逐一测试**。

---

## 8. 附：本轮用到的探针（可复跑）

| 探针 | 作用 | 关键结论 |
|---|---|---|
| `probeapi2.node` | 真 N-API 模块内 `dlsym` 探测 | 证明 libc `dlsym` 视图为空（§2.2） |
| `probeapi3.node` | 分 stage 探测（0–18） | service 各入口语义、句柄查找、fbase 对照 |
| `probe12.c` | 133 名字 libc↔服务等价性 | 相等 133 / 不等 0（§2.5） |
| `probe14.c` | 复刻 shim 结构测递归 | 递归进入次数 0（§2.7 陷阱 A 对照） |
| `probe15.c` | 服务返回值的模块归属 | 解释 `next_from` 的位置相关性 |
| `probe16.c` | `service_global("dlsym")` 自引用 | ★是★（§2.7 陷阱 A） |
| `probe18.c` | `dl_iterate_phdr` 对象数 | bxroot 1 vs 官方 11（§3.4） |
| `crashtrace2.so` | SIGSEGV 回溯（`dladdr` 逐帧） | 定位 `dlopen` 自递归 |

复跑脚本：

```sh
# 单 preload
sh /root/dlsym/run3.sh off <runtime.so> <js>
# 多 preload（探针）
sh /root/dlsym/run3.sh off <runtime.so> <js> <probe.so>
# 真实 dsh
sh /root/dlsym/rundsh.sh <runtime.so> web --no-open --port 44992
# cspawn4
sh /root/l2sfix/run_cspawn4.sh libbxroot-runtime.so
```

---

## 9. 一句话总结

> `dsh web` 的插件加载失败**不是一个缺陷，而是两个**：
> ① `dlsym` 未导出 ② `dladdr` 的 `dli_fbase` 为 NULL。
> 两者同源 —— **proroot 用自研 loader，而 glibc 的 `dl*` 依赖 glibc 自己的 loader 状态**；
> 官方 runtime 之所以正常，是因为它**自己实现了 `dlsym`/`dladdr` 并走 linker 私有服务**。
> 本轮照同一协议补上这两个符号，**符号解析本身仍然全部交给 linker 服务，
> 没有自研任何 ELF 解析**（红线 CL-13/CL-14 未触碰）。
> 验收点达成，`dsh web` 完整启动并可服务，`RUN_ALL.sh` 11 通过 / 0 失败 / 1 已知缺陷（rc=0），
> 零告警，`cspawn4` 与 `spawnSync` 无回归。
