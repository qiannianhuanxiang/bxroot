# `dsh web` 五个内置插件 `Cannot find package` —— 根因调查报告

> 结论：**是 bxroot 的缺陷**，而且**不是** `readlink` / `stat` / `access` / `openat` 的路径翻译问题。
> 真正的原因是一个**符号解析**问题：bxroot 缺了「官方探针运行时补进 ldso 的 `dlsym` 垫片」。
>
> 报告人：调查代理（只做实验与取证，未修改任何受保护源文件）
> 日期：本机 Sep 16

---

## 0. 一句话结论

```
bxroot 未接管 dlsym/dlerror/dladdr/dl_iterate_phdr
        ↓
proroot-ldso 提供的 libc.so.6「影子副本」里根本没有 dlsym 实现，
且它对 RTLD_DEFAULT / RTLD_NEXT 返回 NULL
        ↓
进程内 dlsym(RTLD_DEFAULT, <任意符号>) 一律返回 NULL（连 malloc 都查不到）
        ↓
N-API 原生模块 node-addon-require-builtin 的 V8 探测全部失败
   （它靠 dlsym 找 Isolate::GetCurrent / GetCurrentContext /
     Context::GetNumberOfEmbedderDataFields /
     PrincipalRealm::builtin_module_require 这两个/四个成员）
        ↓
r.requireBuiltin 抛 Unsupported/no-context
        ↓
cordis-plugin-loader 的 ModuleLoader.fromInternal() 返回 undefined
   （源码：require("node-addon-require-builtin").requireBuiltin(...) 在 try{}catch{} 里）
        ↓
loader.internal === undefined
        ↓
@deepseek-ai/dsh-app-boot 的 HostResolvedRootInclude.import() 走 fallback 分支
   `super.import(specifier, ...)` → 裸 `import('dsh-xxx')`，
   baseUrl 退化成「cordis-plugin-loader/lib/index.js 自己」
        ↓
该路径祖先链上不存在 node_modules/dsh-xxx
        ↓
Cannot find package 'dsh-xxx' imported from .../cordis-plugin-loader/lib/index.js
```

**实验终点验证**：在 `/usr/local/lib/node_modules/` 下建 5 个**相对**符号链接指向
`../../../../root/dsha-*` 之后，bxroot 下 `dsh web` **完整启动成功**
（打印 `dsh web: http://127.0.0.1:44927/?token=...`）。这条因果链被闭合。

---

## 1. 实验环境与不可变基线的固化

本次调查期间**有其他代理正在并发修改与重建 bxroot 运行时**（`src/runtime/preload.c`、`build/libbxroot-runtime.so` 的时间戳在我调查过程中变过）。为了让所有对照实验可比，我把运行时**冻结成一份快照**，全部 bxroot 实验都用这一份：

```
$ mkdir -p /root/proroot-work/agents/rename-bxroot/work/probe-webplugin
$ cp -f .../build/libbxroot-runtime.so .../work/probe-webplugin/libbxroot-runtime.so.snap
$ sha256sum .../libbxroot-runtime.so.snap
e42551c5a7763a0a8522bb4888c9478c62f008e96503109c9bd7ec8f3cffb5a0  .../libbxroot-runtime.so.snap
```

本次运行时的落地方式（沿用 `test/RUN_E2E.sh` 的双视角约定：`mkdir` 用容器视角，`--preload` 用内核视角）：

| 项 | 值 |
|---|---|
| 官方库目录（内核视图） | `/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64` |
| rootfs | `/data/data/com.dsh.client/files/linux/ubuntu` |
| stage（内核视图） | `<rootfs>/root/proroot-work/agents/rename-bxroot/work/probe-webplugin/stage` |
| dsh 入口 | `/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js` |
| node | `/usr/local/bin/node`（v24.19.0） |

**关于真机 root 权限的如实说明**：本次调查**没有**需要真机 root 能力。
探测到本进程 `Uid: 10655 10655 10655 10655`、`CapEff: 0000000000000000`、`Seccomp: 2`，
即只有 fakeroot 伪装、没有任何 capability。所有实验都在容器内以普通进程完成，
`libproroot-bridge.so` / `libproroot-linker.so` 由 exec 直接交给内核加载（不经过 shell 的路径解析），
因此容器视角看不到 `/data/app/...` 并不影响实验。
`/root/dsh-bin/adb-shell` 返回 `EXECUTION_UNKNOWN`（设备桥 JSON 解析失败），**本次未使用设备 shell**。

---

## 2. 对照实验（最关键的一步）

### 2.1 先确认现象可复现

为不污染生产 profile，先把 `/root/.dsh/profiles/web` 复制一份为 `webprobe`：

```
$ cp -a /root/.dsh/profiles/web /root/.dsh/profiles/webprobe
```

**对照 A —— 官方 proroot：**

```
$ cd /root && DSH_HOME=/root/.dsh DSHA_STARTUP_PROFILE=webprobe DSHA_UI_LANGUAGE=zh \
    timeout 120 \
    "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
      --preload "$APP_LIB/libproroot-runtime.so" \
      "$ROOTFS/usr/local/bin/node" "$DSH_JS" --profile webprobe --port 44911 --no-open
dsh web: http://127.0.0.1:44911/?token=ebP2nn06iP4CIqifEufM4BC1_d3zLqK57QS67mQxsEM
rc=124        ← 124 = timeout 杀掉，说明一直在正常服务
```

**对照 B —— bxroot：**

```
$ cd /root && DSH_HOME=/root/.dsh DSHA_STARTUP_PROFILE=webprobe DSHA_UI_LANGUAGE=zh \
    timeout 180 \
    "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
      --preload "$STAGE_LOAD/libbxroot-runtime.so" \
      "$ROOTFS/usr/local/bin/node" "$DSH_JS" --profile webprobe --port 44912 --no-open
node[1]: pthread_create: Invalid argument
file:///usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js:1545
		throw new Error(`${binName}: ${stage}: ${detail}${stack}`, { cause });
		      ^

Error: dsh: plugin tree failed to load: failed to apply loader entry include (cordis:include): loader entries failed to apply
AggregateError: loader entries failed to apply
Error: failed to import loader entry device-shell-guide (dsh-device-shell-guide): Cannot find package 'dsh-device-shell-guide' imported from /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js
    ... （同样 5 条，task-notifier / dsh-status-overlay / dsh-web-mobile / dsh-app-integration）
  [cause]: Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'dsh-device-shell-guide' imported from /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js
              at Object.getPackageJSONURL (node:internal/modules/package_json_reader:301:9)
              at packageResolve (node:internal/modules/esm/resolve:768:81)
              ...
rc=1
```

> **对照实验结论（任务判断点 1）：**
> **官方 proroot 下这 5 个插件全部正常加载**（`/root/dsh-web.log` 里也有现成证据：
> `{"type":"loaded","plugin":"dsh-task-notifier",...}` 等 5 条 `loaded` 事件）。
> bxroot 下 5 个全部失败。**所以这是 bxroot 的差异，不是环境/配置本身的问题。**

### 2.2 先排除掉任务里点名的四个嫌疑（readlink / stat / access / openat）

任务书让我重点怀疑 `readlink` 系列。我写了 `work/probe-webplugin/linkq.c`
把四个 API 对着**同一个链接**在两种视图下逐一测：

```
$ "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 linkq \
    --preload "$APP_LIB/libproroot-runtime.so" "$ROOTFS/root/.dsh/profiles/web/linkq"
== Q1. readlink 返回的内容对不对？ ==
  readlink(/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide)
      -> "../../../../dsha-device-shell-guide"
  readlink(/proc/self/root/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide)
      -> "../../../../dsha-device-shell-guide"

== Q2. realpath / stat / access 解析对不对？ ==
  realpath(/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide)
      -> /root/dsha-device-shell-guide
  stat     -> ok (ino=5899463)
  access   -> ok
  lstat is symlink -> yes

== Q3. openat 的相对路径基准对不对？ ==
  open(dirfd=/root/.dsh/profiles/web/node_modules) = 6 ok
  openat(dirfd, "dsh-device-shell-guide/package.json") = 9 ok
      读到 550 字节，首行: { "name": "dsh-device-shell-guide", ...
  fstatat(dirfd, "dsh-device-shell-guide", NOFOLLOW) -> 符号链接 ok
  fstatat(dirfd, "dsh-device-shell-guide", 0)         -> 目录 ok
```

bxroot 下同一程序：

```
== Q1. readlink 返回的内容对不对？ ==
  readlink(/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide)
      -> "../../../../dsha-device-shell-guide"     ← ✅ 与官方逐字节一致
  readlink(/proc/self/root/root/.dsh/.../dsh-device-shell-guide)
      -> ERR 2(No such file or directory)          ← ⚠️ 见 §5 的旁支发现

== Q2. realpath / stat / access 解析对不对？ ==
  realpath(...) -> /data/data/com.dsh.client/files/linux/ubuntu/root/dsha-device-shell-guide
                                                    ← ⚠️ 内核视图（旁支发现）
  stat     -> ok (ino=5899463)                      ← ✅ inode 与官方一致
  access   -> ok                                    ← ✅
  lstat is symlink -> yes                           ← ✅

== Q3. openat 的相对路径基准对不对？ ==
  open(dirfd=...) = 9 ok
  openat(dirfd, "dsh-device-shell-guide/package.json") = 10 ok
      读到 550 字节，首行: { "name": "dsh-device-shell-guide", ...   ← ✅
  fstatat(dirfd, "dsh-device-shell-guide", NOFOLLOW) -> 符号链接 ok  ← ✅
  fstatat(dirfd, "dsh-device-shell-guide", 0)         -> 目录 ok      ← ✅
```

> **结论：`readlink` 返回内容、`stat`/`access` 解析、`openat` 相对基准三项在 bxroot 下全部正确。**
> 任务书第 2 点列出的三个具体怀疑方向**全部排除**。
> （`realpath` 返回内核视图路径是一个**真实的独立缺陷**，见 §5，但它**不是**本次故障的原因 —— §6 有决定性反证。）

---

## 3. 锁定真正的失败点：ESM 解析的 referrer

### 3.1 用解析钩子抓真实 parentURL（无侵入）

写了一个只记录、原样放行的 loader hook（`--import=reg.mjs` 注册 `resolve`）：

```js
// hooks.mjs
export async function resolve(specifier, context, nextResolve) {
  if (NAMES.test(specifier)) {
    process.stderr.write('[HOOK] resolve specifier=' + specifier +
      '  parentURL=' + (context.parentURL || '(none)') + '\n');
    ...
  }
  return nextResolve(specifier, context);
}
```

**官方 proroot 下：**

```
[HOOK] resolve specifier=dsh-device-shell-guide  parentURL=file:///root/.dsh/profiles/webprobe/
[HOOK]   -> OK {"url":"file:///root/dsha-device-shell-guide/lib/index.js","format":"module"}
[HOOK] resolve specifier=dsh-task-notifier  parentURL=file:///root/.dsh/profiles/webprobe/
[HOOK]   -> OK {"url":"file:///root/dsha-task-notifier/lib/index.js","format":"module"}
... （5 个全 OK）
dsh web: http://127.0.0.1:44921/?token=dgqOXMhimcny69HOodU1PIPzX9b8bbqEdXSFduNZY9Q
```

**bxroot 下（同一 hook、同一 profile 内容）：**

```
[HOOK] resolve specifier=dsh-device-shell-guide  parentURL=file:///usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js
[HOOK]   -> FAIL ERR_MODULE_NOT_FOUND :: Cannot find package 'dsh-device-shell-guide' imported from /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js
[HOOK] resolve specifier=dsh-task-notifier  parentURL=file:///usr/local/.../cordis-plugin-loader/lib/index.js
[HOOK]   -> FAIL ERR_MODULE_NOT_FOUND :: Cannot find package 'dsh-task-notifier' ...
... （5 个全 FAIL，且 `imported from` 与报错文字逐字一致）
```

> **决定性差异：官方解析基准是 `/root/.dsh/profiles/webprobe/`（profile 目录本身），
> bxroot 的解析基准是 `cordis-plugin-loader/lib/index.js`。**

### 3.2 为什么基准会变 —— 读 dsh 源码

`@deepseek-ai/dsh-app-boot/lib/index.js`（`mountRootInclude`，约 1322–1332 行）：

```js
ctx.loader.builtins.include = bareModuleBaseUrl === void 0 ? Include
  : class HostResolvedRootInclude extends Include {
      import(name, getOuterStack) {
        const specifier = isAbsolute(name) ? pathToFileURL(name).href : name;
        if (name.startsWith(".") || name.startsWith("cordis:")) return super.import(specifier, getOuterStack);
        const internal = this.ctx.loader.internal;
        if (internal === void 0) return super.import(specifier, getOuterStack);   // ★ fallback
        return internal.import(specifier, bareModuleBaseUrl, {});                  // ★ 正确路径
      }
    };
```

`cordis-plugin-loader/lib/index.js`（`ModuleLoader.fromInternal()`，第 4–38 行）：

```js
function requireInternal(id) {
    const require = createRequire(import.meta.url);
    if (process.execArgv.includes("--expose-internals")) try { return require(id); } catch {}
    try { return require("node-addon-require-builtin").requireBuiltin(id); } catch {}   // ★ 被吞掉
}
function fromInternal() {
    if (_cachedLoader) return _cachedLoader;
    const [major] = process.versions.node.split(".").map(Number);
    if (major < 22) return;
    const raw = requireInternal("internal/modules/esm/loader")?.getOrInitializeCascadedLoader();
    if (!raw) return;
    ...
}
```

**`requireInternal` 的失败被 `catch {}` 完全吞掉**，所以外部看不到任何线索 —— 这就是为什么这个 bug 难查。

> **这条 fallback 路径只在 Node ≥ 22 且 `loader.internal` 取不到时才会走到。**
> 官方 proroot 下永远走不到；bxroot 下**必然**走到。这解释了"为什么偏偏是这 5 个插件"：
> 只有用户插件是**裸包名**（相对名 `./x` 走 `name.startsWith(".")` 分支，不受影响）。

---

## 4. 根因：`dlsym(RTLD_DEFAULT, …)` 在 bxroot 下全部返回 NULL

### 4.1 直接验证 `Node` 侧

在 profile 目录里跑一个只加载 `node-addon-require-builtin` 的脚本：

**官方 proroot：**

```
### NATIVE TAG=OFFICIAL node=v24.19.0
=== 2. 加载 require-builtin 并取 bindingInfo ===
   ✔ require node-addon-require-builtin = ["requireBuiltin","isAllowedInternalId","getBindingInfo","default"]
   ✔ getBindingInfo() = {"mode":"napi","product":"require-builtin","backend":"napi","abi":"napi-v9",
       "bindingPath":"/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/node-addon-require-builtin-linux-arm64-gnu/prebuilt/linux-arm64-gnu-napi-v9.node",
       "bindingSource":"optional-package", ...}
=== 3. isAllowedInternalId / requireBuiltin ===
   ✔ isAllowedInternalId(internal/modules/esm/loader) = true
   ✔ requireBuiltin(internal/modules/esm/loader) = {"keys":["createModuleLoader","getOrInitializeCascadedLoader","isCascadedLoaderInitialized","register"],"ctor":"Object"}
   ✔ requireBuiltin(internal/modules/esm/resolve) = {"keys":["defaultResolve","packageResolve","packageExportsResolve", ...]}
=== 4. requireBuiltin 的 loader 形状 ===
   ✔ getOrInitializeCascadedLoader() = {"got":true,"version":"v2","resolveSync":"function"}
```

**bxroot：**

```
### NATIVE TAG=BXROOT node=v24.19.0
=== 2. 加载 require-builtin 并取 bindingInfo ===
   ✔ require node-addon-require-builtin = ["requireBuiltin","isAllowedInternalId","getBindingInfo","default"]
   ✔ getBindingInfo() = {"mode":"napi", ... "bindingPath":"/usr/local/lib/..." }   ← .node 本身加载成功！
=== 3. isAllowedInternalId / requireBuiltin ===
   ✔ isAllowedInternalId(internal/modules/esm/loader) = true
   ✘ requireBuiltin(internal/modules/esm/loader) -> Unsupported/no-context
        :: node-addon-require-builtin unsupported: Unsupported/no-context
           (required V8 current-context symbols were not found)
   ✘ requireBuiltin(internal/modules/esm/resolve) -> Unsupported/no-context  ...
   ✘ requireBuiltin(fs)                            -> Unsupported/no-context  ...
=== 4.   ✘ getOrInitializeCascadedLoader() -> Unsupported/no-context ...
```

注意：`.node` 文件**加载成功**（说明 `dlopen` 与路径翻译都没问题），
失败的是 `.node` **内部通过 `dlsym` 做的 V8 符号探测**。

### 4.2 把 Node 摘掉，用纯 C 验证这是**运行时层**的问题

`work/probe-webplugin/dlonly2.c` 只做两件事：打印各 `dl*` 函数指针来自哪个 .so，
再查几个符号。**同一个二进制**，只换 `--preload`：

```
########## A. 无 --preload ##########
== 被测函数指针（本程序 PLT 解析到的实现）==
  dlsym                        0x77ea8a2590  <- libc.so.6
  dlopen                       0x77ea8a2490  <- libc.so.6
  ...
== RTLD_DEFAULT 查找 ==
  dlsym(DEFAULT,"malloc")  = (nil)
  dlsym(DEFAULT,"dlsym")   = (nil)
  dlsym(NEXT,"malloc")     = 0x77ea5ff7f0

########## B. --preload 官方 runtime ##########
  dlsym                        0x7a31eaae90  <- .../lib/arm64/libproroot-runtime.so   ← ★ 官方 runtime 接管了 dlsym
  dlopen                       0x7a31eab160  <- .../lib/arm64/libproroot-runtime.so
  dlerror                      0x7a31eaafa0  <- .../lib/arm64/libproroot-runtime.so
  dladdr                       0x7a31eab080  <- .../lib/arm64/libproroot-runtime.so
  dl_iterate_phdr              0x7a31eaafec  <- .../lib/arm64/libproroot-runtime.so
  readlink                     0x7a31ea91f0  <- .../lib/arm64/libproroot-runtime.so
== RTLD_DEFAULT 查找 ==
  dlsym(DEFAULT,"malloc")  = 0x7a31d60490        ← ★ 正常
  dlsym(DEFAULT,"dlsym")   = 0x7a328074a8        ← ★ 正常
  dlsym(NEXT,"malloc")     = 0x7a31d60490        ← ★ 正常

########## C. --preload bxroot runtime ##########
  dlsym                        0x76594c3590  <- libc.so.6       ← ★ bxroot 没接管（与"无 preload"完全一致）
  dlerror                      0x76594c2bf0  <- libc.so.6
  dladdr                       0x76594c2b10  <- libc.so.6
  dl_iterate_phdr              0x765957e990  <- libc.so.6
  dlopen                       0x765a8881f4  <- .../stage/libbxroot-runtime.so   ← 只有 dlopen 被接管
  readlink                     0x765a883c80  <- .../stage/libbxroot-runtime.so
== RTLD_DEFAULT 查找 ==
  dlsym(DEFAULT,"malloc")  = (nil)                ← ❌ 连 malloc 都查不到
  dlsym(DEFAULT,"dlsym")   = (nil)                ← ❌
  dlsym(NEXT,"malloc")     = (nil)                ← ❌
```

**关键**：官方 runtime 的 `dlsym` 是这样的（`work/runtime.so` 反汇编 `dlsym@@Base`）：

```asm
0000000000022e90 <dlsym@@Base>:
   ...
   22ea4:  cmn  x0, #0x1                 ; handle == RTLD_NEXT ?
   22ea8:  b.eq 22f8c
   22f14:  bl   ldso_service_dlsym@plt    ; ← 转给自研加载器
   22f8c:  bl   ldso_service_dlsym_next_from@plt
```

它**依赖 `libproroot-linker.so` 的自研加载器服务**：

```
$ nm -D --undefined-only work/runtime.so | grep ldso_service
                 U ldso_service_dl_iterate_phdr
                 U ldso_service_dlsym
                 U ldso_service_dlsym_global
                 U ldso_service_dlsym_next_from
                 U ldso_service_find_object_by_addr
                 U ldso_service_find_object_by_handle
```

**为什么裸 libc 的 `dlsym` 会失败？**
proroot-ldso 是把 guest 的 `libc.so.6` 加载成一份“影子”副本、自己实现动态链接的。
`RTLD_DEFAULT` 在 glibc 里要遍历主程序的动态链接表，而这份表在影子副本下是空的。
旁证（在**本容器 shell 里**用 python ctypes 复现）：

```
$ python3 -c "import ctypes; ... libdl.dlsym(ctypes.c_void_p(0), b'malloc')"
AttributeError: ldso_runtime dlsym: symbol 'dlsym' not found
```

连 `dlsym` 这个符号本身都找不到 —— 说明影子副本里根本没有可用的 `dlsym` 实现，
**只能靠 proroot 自己的 `ldso_service_*` 补上**。

### 4.3 看一下两者导出的 dl 家族符号

```
=== bxroot runtime 导出的 dl 家族 ===
000000000000c2f4 T dlopen            ← 只有这一个

=== 官方 runtime 导出的 dl 家族 ===
0000000000022fec T dl_iterate_phdr
0000000000023080 T dladdr
00000000000235a0 T dladdr1
0000000000022fa0 T dlerror
0000000000023704 T dlinfo
0000000000023160 T dlopen
0000000000022e90 T dlsym
```

这就是缺口。而 `preload.c` 里有一段**明确解释为什么当初决定不导出 `dlsym`** 的注释
（见 §7，它的技术判断在当时是对的，但漏掉了「官方 runtime 用 `dlsym` 垫片补 ldso 空缺」这一层）。

---

## 5. 旁支发现：bxroot 的 `realpath` 返回内核视图路径（真实缺陷，非本次故障原因）

`fs.realpathSync.native`（走 libuv/`realpath()`）在 bxroot 下返回内核视图：

```
--- /root/.dsh/profiles/web/node_modules/dsh-device-shell-guide
   realpathSync(js)      = /root/dsha-device-shell-guide                                （官方）
   realpathSync.native   = /data/data/com.dsh.client/files/linux/ubuntu/root/dsha-device-shell-guide   （bxroot）
```

同样，`/proc/self/root/<guest 绝对路径>` 这种带前缀的路径 bxroot 下直接 ENOENT：

```
$ linkprobe "/proc/self/root/root/.dsh/profiles/web/node_modules"
   realpath  -> /root/.dsh/profiles/web/node_modules        （官方 ok）
$ ./linkprobe "/proc/self/root/root/.dsh/profiles/web/node_modules"   （bxroot）
   readlink  ERR 22(Invalid argument)
   realpath  -> (NULL)
```

`/data/data/com.dsh.client/files/linux/ubuntu/...` 是形如 `/usr/local/lib/node_modules` 的最长前缀，
这强烈指向 **bxroot 的 rootfs 前缀剥离是按“最长前缀匹配”实现的**，
而 `/proc/<pid>/root` 的 readlink 结果是 `/`，所以任何 `/proc/<pid>/root/...` 都命中不了前缀。

**报告人自己的方法论提醒（必读）**：
我起初把这两条当成根因线索（`realpath` 泄漏内核视图 → ESM 可能因此解析失败）。
**§6 的实验证明这个方向是错的** —— 反例是 `/usr/local/lib/node_modules`（**不在** rootfs 前缀内）
下的链接同样解析失败。所以请后人**不要**再沿着 `realpath` 这条线找本次故障的原因；
它值得单独修，但与 `Cannot find package` 无关。

---

## 6. 决定性反证 + 因果链闭合

### 6.1 反证：Node 的 ESM 候选表里压根没有这些包

用 `work/probe-webplugin/walk.mjs` 精确复刻 Node 的 `PACKAGE_RESOLVE` 上溯，
从真实 referrer 出发逐级列候选：

```
### WALK TAG=BXROOT
### referrer = /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js
=== dsh-device-shell-guide
     /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/node_modules/dsh-device-shell-guide  -> ENOENT
     /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/node_modules/dsh-device-shell-guide      -> ENOENT
     /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/node_modules/dsh-device-shell-guide                            -> ENOENT
     /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/node_modules/dsh-device-shell-guide                                        -> ENOENT
     /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/dsh-device-shell-guide                                                    -> ENOENT
     /usr/local/lib/node_modules/@deepseek-ai/node_modules/dsh-device-shell-guide                                                        -> ENOENT
     /usr/local/lib/node_modules/node_modules/dsh-device-shell-guide                                                                     -> ENOENT
     /usr/local/lib/node_modules/dsh-device-shell-guide                                                                                 -> ENOENT
     /usr/local/node_modules/dsh-device-shell-guide                                                                                     -> ENOENT
     /usr/node_modules/dsh-device-shell-guide                                                                                           -> ENOENT
     /node_modules/dsh-device-shell-guide                                                                                               -> ENOENT
   >>> 命中: 否
```

**这 11 个候选里没有任何一个落在 rootfs 前缀内**，
所以「`realpath` 泄漏内核视图」**在数学上不可能**是这 5 个包解析失败的原因。
真正的包在 `/root/.dsh/profiles/web/node_modules/` —— 只有以 **profile 目录**为基准才能找到它。

### 6.2 闭合实验：把包放到 fallback 能搜到的地方

在第 9 个候选（`/usr/local/lib/node_modules/`）放**相对**符号链接：

```
$ for n in dsh-device-shell-guide dsh-task-notifier dsh-status-overlay dsh-web-mobile dsh-app-integration; do
    ln -sfn "../../../../root/dsha-${n#dsh-}" "/usr/local/lib/node_modules/$n"
  done
$ ls -la /usr/local/lib/node_modules/ | grep dsh-
lrwxrwxrwx.  1 root root    37 ... dsh-app-integration -> ../../../../root/dsha-app-integration
lrwxrwxrwx.  1 root root    40 ... dsh-device-shell-guide -> ../../../../root/dsha-device-shell-guide
lrwxrwxrwx.  1 root root    36 ... dsh-status-overlay -> ../../../../root/dsha-status-overlay
lrwxrwxrwx.  1 root root    35 ... dsh-task-notifier -> ../../../../root/dsha-task-notifier
lrwxrwxrwx.  1 root root    32 ... dsh-web-mobile -> ../../../../root/dsha-web-mobile
```

再跑 bxroot（**其余一切不变**，仍然只有 bxroot 被 preload）：

```
$ DSH_HOME=/root/.dsh DSHA_STARTUP_PROFILE=webprobe2 ... \
    timeout -s KILL 110 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
      --preload "$STAGE_LOAD/libbxroot-runtime.so" \
      "$ROOTFS/usr/local/bin/node" "$DSH_JS" --profile webprobe2 --port 44927 --no-open
node[1]: pthread_create: Invalid argument
[HOOK] resolve specifier=dsh-device-shell-guide  parentURL=file:///usr/local/.../cordis-plugin-loader/lib/index.js
[HOOK]   -> OK {"url":"file:///root/dsha-device-shell-guide/lib/index.js","format":"module"}
[HOOK] resolve specifier=dsh-task-notifier       parentURL=... -> OK {"url":"file:///root/dsha-task-notifier/lib/index.js", ...}
[HOOK] resolve specifier=dsh-status-overlay      parentURL=... -> OK {"url":"file:///root/dsha-status-overlay/lib/index.js", ...}
[HOOK] resolve specifier=dsh-web-mobile          parentURL=... -> OK {"url":"file:///root/dsha-web-mobile/lib/index.js", ...}
[HOOK] resolve specifier=dsh-app-integration     parentURL=... -> OK {"url":"file:///root/dsha-app-integration/index.js", ...}
dsh web: http://127.0.0.1:44927/?token=BqLajf4YEjOLPnTwbCCsiZ-BfAVYq2q6HBwKhdJEw8Q
rc=137    ← 110 秒到点被 KILL，说明一直在正常服务
```

> **bxroot 下 `dsh web` 完整启动成功。**
> 同时满足：(a) 官方 proroot 下无需这些链接也成功；(b) 加了链接后 bxroot 成功。
> 因果链闭合，根因确认。
>
> （踩过的坑：第一次我写的是**绝对**链接 `-> /root/dsha-app-integration`，
> 结果仍然失败 —— 因为绝对符号链接的内核目标被解析成 `<rootfs>/root/...`，
> 而 `/usr/local/lib/node_modules` 在 rootfs 之外。换成相对链接立刻成功。
> 这本身也是一条值得记录的 bxroot 语义差异。）

---

## 7. 修复建议

### 7.1 主修复（必须）：补齐 `dlsym` 系列垫片

**文件**：`src/runtime/preload.c`
**位置**：`dlopen` 定义之后、那段「`dl*` 家族：刻意不再导出」的注释块处。

> ⚠️ **行号不稳定**：`preload.c` 正被其他代理并发编辑。我调查期间同一段代码的行号从
> `2810 / 2826 / 2874` 漂移到 `2945 / 2961 / 3013`。**请按注释文字定位**，不要按行号改。

```
$ grep -n "^void \*dlopen" src/runtime/preload.c
2945:void *dlopen(const char *filename, int flags) {
$ grep -n "dl\* 家族：\*\*刻意不再导出\*\*" src/runtime/preload.c
2961: * dl* 家族：**刻意不再导出**（曾经的实现是错的，见下）。
$ grep -n "^/\* Hook: nocancel 变体" src/runtime/preload.c
3013:/* Hook: nocancel 变体 —— 高频（不可取消的内部路径）                    */
```

**diff 思路**：

现有注释论证「这四个函数没有路径语义 ⇒ 不必接管」，**这个前提在官方运行时下也不成立** ——
官方运行时导出它们，但**不是**为了翻译路径，而是为了**接住 ldso 的空缺**
（`ldso_service_dlsym` / `ldso_service_dlsym_global` / `ldso_service_dlsym_next_from`）。

关键点：**不能简单地把 `dlsym` 转发给 libc 的 `dlsym`**。因为 proroot-ldso 的
libc 影子副本里 `dlsym` 本身不可用（§4.2 的 python ctypes 已证明）。
所以正确做法是走**绕过 libc 的路径** —— bxroot 已有的处理手法（见 `syscall_guard.c`
用裸 `svc` 绕开 libc 的 `syscall`）。可行方案优先级：

1. **首选：直接调用加载器的服务函数。**
   `libproroot-linker.so` 里有 `ldso_runtime_dlopen` / `ldso_runtime_dlsym` /
   `ldso_runtime_dlsym_addr_of`（已实测存在于 `work/linker.so`）。
   但**官方 runtime 用的 `ldso_service_*` 这个符号名在我能读到的所有 linker 副本里都不存在**
   （`nm -D --defined-only` 对全部 20+ 份 `libproroot-linker.so` 副本都是 0 命中），
   怀疑是加载器在运行时把符号注入/改名的。**这一步必须先核实真机
   `libproroot-linker.so` 的动态符号表**（见 §8「还需什么信息」）——
   若 `ldso_service_dlsym` 确实存在，bxroot 直接调它即可，这是最干净的修法。

2. **次选：自己实现 RTLD_DEFAULT / RTLD_NEXT 的遍历。**
   bxroot 用的是 **glibc 原生 ld.so**（与官方自研加载器不同），
   所以理论上 libc 的 `dlsym` 应该是好的。需要在 **bxroot 自己的运行环境**下实测确认；
   若确认可用，则 `dlsym` 只需：
   - `handle == RTLD_NEXT` → 转发 libc 原生 `dlsym`
   - `handle == NULL || handle == RTLD_DEFAULT` → 先查主程序（`dlopen(NULL)` 语义），
     再查 `LD_PRELOAD` 列表
   - 其余 handle → 原样转发

   **红线提醒**：绝对不要**再次**写成 `dlsym(RTLD_NEXT, "dlsym")` 的懒加载包装器 ——
   那正是文件里已经记录过的无限递归崩溃（详见现有注释）。

3. `dlerror` / `dladdr` / `dl_iterate_phdr` / `dladdr1` / `dlinfo` **建议一并导出**，
   与官方符号表对齐。这几个风险低（纯查询），且 `dl_iterate_phdr` 缺失同样会影响
   其他原生模块的探测。**注意 `dladdr` 也要做路径翻译** —— bxroot 下它返回内核视图
   （见 §5），与 `readlink` 的视图不一致。

**验收标准（可复现）**：
修复后，用 §4.1 的 `native.mjs`（在 profile 目录里跑）应看到
`requireBuiltin(internal/modules/esm/loader)` 返回 loader 对象、
`getOrInitializeCascadedLoader()` 报 `version: "v2"`，
然后 bxroot 下 `dsh web` 应能打印 `dsh web: http://127.0.0.1:...`。

### 7.2 回归防线（建议）：把这条链路加进自检

`test/RUN_E2E.sh --selftest` 目前只测路径翻译/fakeroot/子进程/l2s，
**没有覆盖 `dlsym` 与 `requireBuiltin`**。建议加两条：

```js
// 加进 RUN_E2E.sh 的 selftest.js
t("dlsym(RTLD_DEFAULT,\"malloc\") 非空", () => {
  // 用 process.binding / 或直接加载一个 .node 确认
  const b = require("node-addon-require-builtin");
  const info = b.getBindingInfo();          // 能拿到说明 .node 加载 OK
  const loader = b.requireBuiltin("internal/modules/esm/loader");  // ★ 这一句就是本 bug 的探针
  return JSON.stringify(Object.keys(loader));
});
```

**单行判定探针**：`require("node-addon-require-builtin").requireBuiltin("internal/modules/esm/loader")`
在官方 proroot 下成功、在 bxroot（未修）下抛 `Unsupported/no-context`。
这一句应该进 CI。

### 7.3 临时规避（仅用于在修复前继续联调，**不建议进交付**）

在 `/usr/local/lib/node_modules/`（或 `/root/node_modules/`）为这 5 个包建
**相对**符号链接指向 `dsha-*`。已在 §6.2 实测有效。
但这是一条**让 fallback 路径“碰巧能work”**的补丁，
一旦 `dlsym` 修好、`loader.internal` 恢复，这条路径就重新回到 profile 基准，
届时这些链接会变成**永远不会被读到的死链接**，且会把解析优先级打乱（profile 层本应优先）。
**修完主缺陷后必须删除。**

### 7.4 独立缺陷（建议单独开单，与本 bug 无关）

`realpath()` / `dladdr` 返回**内核视图**路径（§5）。
对 `/usr/local/lib/node_modules` 这类 rootfs 前缀**之外**的路径同样复现，
所以**压测不是“路径翻译”问题，而是“根因对 `realpath` 的翻译是**返回内核视图**而非 guest 视图。

**文件**：`src/runtime/preload.c` 的 `realpath` 钩子（`realpath` / `realpath` 的 nocancel 变体）。
**判据**：`fs.realpathSync.native("/root/.dsh/profiles/web/node_modules/dsh-app-integration")`
应返回 `/root/dsha-app-integration`（与官方一致），当前返回
`/data/data/com.dsh.client/files/linux/ubuntu/root/dsha-app-integration`。

---

## 8. 结论汇总

| 项 | 结论 |
|---|---|
| **是 bxroot 缺陷还是环境问题？** | **bxroot 缺陷。** 官方 proroot 下 5 个插件全部 `loaded`（`/root/dsh-web.log` 第 6–15、20–31 行有现成记录），bxroot 下 5 个全部 `Cannot find package` |
| **任务点名的 `readlink` 是不是元凶？** | **不是。** `readlink` 返回内容、`stat`/`access`/`openat` 相对基准四项在 bxroot 下**逐字节正确**，与该 bug 无关 |
| **符号链接指向哪里？目标存在吗？** | 指向 `../../../../dsha-{app-integration,device-shell-guide,status-overlay,task-notifier,web-mobile}`，即 `/root/dsha-*`。**目标存在且可访问**（`stat` ok、`access` ok） |
| **真正的根因** | bxroot **未接管 `dlsym`/`dlerror`/`dladdr`/`dl_iterate_phdr`**，而 proroot-ldso 的 libc 影子副本不提供可用的 `dlsym`（`RTLD_DEFAULT`/`RTLD_NEXT` 一律 NULL）。官方运行时用 `ldso_service_dlsym*` 垫片补上了这个空缺 |
| **故障传导链** | 缺 `dlsym` → N-API 模块 `node-addon-require-builtin` 的 V8 探测失败（`Unsupported/no-context`） → `loader.internal === undefined` → `HostResolvedRootInclude.import()` 走 `super.import()` fallback → 解析基准从 **profile 目录**退化成 **cordis-plugin-loader/lib/index.js** → 该目录祖先链上不存在 `node_modules/dsh-xxx` → `Cannot find package` |
| **为什么只有这 5 个插件？** | 只有用户插件是**裸包名**。相对名（`./x`）走 `name.startsWith(".")` 分支，不受 `loader.internal` 影响；`cordis:` 内置更不受影响 |
| **为什么 `dsh --version` / `--help` 正常？** | 这些路径不加载插件树（`loadLayeredEnv` 早退），走不到 ESM bare-specifier 解析 |
| **修复后的验收探针** | `require("node-addon-require-builtin").requireBuiltin("internal/modules/esm/loader")` 必须成功 |
| **还需什么信息** | 见下 |

### 还需什么信息（诚实边界）

1. **真机 `libproroot-linker.so` 的动态符号表。**
   官方运行时 `U ldso_service_dlsym` 等 6 个符号**必然**由加载器提供，
   但我能读到的 20+ 份 `libproroot-linker.so` 副本（`/root/proroot-work/build/`、
   `/root/dsha-*/proroot-backup/`、`work/linker.so` 等）**动态符号表里都是 0 命中**。
   我怀疑加载器在运行时注入或改名了这些符号。**要给出精确到 `ldso_service_*` 调用形式的修复代码，
   必须先拿到真机那份 linker 的符号表**（例如在真机 root 下
   `nm -D /data/app/.../lib/arm64/libproroot-linker.so | grep ldso_service`）。
   拿不到时，我给的修复方向只能停在“补齐 `dlsym` 语义”这一层（§7.1 方案 1 vs 方案 2 需要它来定）。
2. 未实测：把 `dlsym` 补齐后，是否还有**第二层**阻塞（例如其他 N-API 模块）。
   §6.2 的规避实验已经让 `dsh web` 完整启动，所以至少启动路径上没有第二层阻塞。

### 清理声明

本次调查建立的所有临时物**已全部删除**，未触碰任何受保护源文件：

- 删除 `/usr/local/lib/node_modules/dsh-{device-shell-guide,task-notifier,status-overlay,web-mobile,app-integration}`（§6.2 的规避链接）
- 删除 `/root/.dsh/profiles/webprobe`、`/root/.dsh/profiles/webprobe2`（临时 profile 副本）
- 删除放进 `/root/.dsh/profiles/web/` 的所有探针文件
- **未修改** `src/proc/proc.c`、`src/runtime/fakeroot.c`、`src/runtime/syscall_guard.c`、`src/runtime/preload.c`
- 复核：`/root/.dsh/profiles/` 只剩 `node_modules` 与 `web`；原 profile `web` 的 5 个链接完好；
  官方 `dsh web`（PID 22552）仍健康（`HTTP 401`，是未带 token 的正常响应）

### 复现用脚本与探针

全部在 `work/probe-webplugin/`（本次新建）：

| 文件 | 用途 |
|---|---|
| `probe.js` / `esm2.mjs` / `esm3.mjs` / `esm4.mjs` / `esm5.mjs` | Node 侧模块解析与内部 loader 探针 |
| `native.mjs` | **主探针**：`node-addon-require-builtin` 与 `requireBuiltin` |
| `dlprobe.c` / `dlprobe.node` | N-API 形态的 `dlsym` 探针 |
| `dlonly.c` / `dlonly2.c` | **纯 C 的最小复现**（把 Node 摘掉，直接看 `dlsym(RTLD_DEFAULT,…)`） |
| `linkq.c` / `linkq2.c` | `readlink`/`stat`/`access`/`openat` 四问对照 |
| `walk.mjs` | 复刻 Node ESM `PACKAGE_RESOLVE` 候选表 |
| `hook/hooks.mjs`、`hook/reg.mjs` | 无侵入的 loader `resolve` 钩子（抓真实 parentURL） |
| `libbxroot-runtime.so.snap` | **固化的运行时快照**（sha256 `e42551c5…b5a0`），保证实验可重放 |
