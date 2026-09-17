# 缺口 D：NSS 用户库查询失败（`getent` / `pwd.getpwnam`）

> 这是子代理在降权族调查中**顺带发现**的独立缺口（报告 §8.2 登记为"缺口 D"）。
> 我在这里把它从"一句话登记"细化到**可执行的根因定位**，供后续任务直接接手。
>
> **状态：未修**（本轮两个子代理在做缺口 B/C 与 shebang，未涉及此项）。

---

## 一、现象（两侧对照实测）

```
########## 官方 libproroot-runtime.so ##########   ########## bxroot ##########
$ head -1 /etc/passwd                              $ head -1 /etc/passwd
root:x:0:0:root:/root:/bin/bash                    root:x:0:0:root:/root:/bin/bash   ← 相同

$ getent passwd root                               $ getent passwd root
root:x:0:0:root:/root:/bin/bash                    （空）
rc=0                                               rc=2                               ← ★

$ python3 -c "import pwd; pwd.getpwnam('root')"    $ python3 -c "import pwd; pwd.getpwnam('root')"
pwd.struct_passwd(pw_name='root', ...)             KeyError: "getpwnam(): name not found: 'root'"   ← ★

$ id                                               $ id
uid=0(root) gid=0(root) groups=0(root)             uid=0(root) gid=0 groups=0        ← 组名解析不了
```

## 二、关键排除：**不是文件读取的问题**

`head -1 /etc/passwd` 两边都成功 → `/etc/passwd` 的**路径翻译与读取都正常**。

也不是"用户库里没有 root"：官方同一份 rootfs 能查到。

**所以问题在 NSS 的"模块加载"环节。**

## 三、已排除的假设（避免接手者重走）

我逐一实测，**推翻了自己最初的"`dlopen` 搜索路径"假设**：

### ✗ 假设 1：`dlopen("libnss_files.so.2")` 失败 → **错，它成功**

```
########## bxroot ##########
dlopen(libnss_files.so.2                             ) = OK
dlopen(/lib/aarch64-linux-gnu/libnss_files.so.2      ) = OK
dlopen(libnss_dns.so.2                               ) = OK
```
两侧**完全一致**。`dlopen` 不是问题。

### ✗ 假设 2：`LD_LIBRARY_PATH` 缺容器目录 → **错，设了也一样**

```
### bxroot + LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu ###
getpwnam(root) = (NULL)      ← 仍然失败
```

### ✗ 假设 3：fakeroot 干扰 → **错，关掉 fakeroot 也一样**

```
### bxroot 不启用 fakeroot ###          ### 官方不启用 fakeroot ###
getpwnam(root) = (NULL)                 getpwnam(root) = root
```

### ✗ 假设 4：`/etc/passwd` 读不到 → **错，`fopen` 正常**

分层探针（`/root/vfy/nss2.c`）结果：

```
########## 官方 ##########                        ########## bxroot ##########
A) fopen(/etc/passwd) = OK                        A) fopen(/etc/passwd) = OK
   fgetpwent -> root                                 fgetpwent -> root      ← 相同！
B) _nss_files_getpwnam_r rc=1 res=(NULL)          B) _nss_files_getpwnam_r rc=0 res=(NULL)
C) getpwnam -> root                               C) getpwnam -> (NULL)     ← 差异在这
```

**关键读数**：
- **A 层（纯文件解析）两侧都正常** → `/etc/passwd` 的内容与读取都没问题
- **B 层**（直接调 NSS 模块函数）：返回值**不同**（官方 `rc=1` = NOTFOUND，
  bxroot `rc=0` = SUCCESS 但 `res=NULL`）—— 这个差异很可疑但含义不明
- **C 层**（`getpwnam`，走 glibc 的 `nsswitch` 分派 + 内部加载）：官方成功，
  **bxroot 返回 NULL**

## 四、当前的精确定位（诚实版）

**已确定的**：
- 问题**不在** `dlopen`、不在搜索路径、不在 fakeroot、不在文件读取
- 问题在 **glibc 内部**那条 `getpwnam → nsswitch 分派 → 内部加载 NSS 模块`
  的链路上
- `getpwent()` **遍历**也返回 0 条（不是"查不到 root"，而是**整个 NSS
  后端都没接上**）
- 两侧 `dlopen` 加载的是**同一个** `libnss_files.so.2`（同路径、同文件）

**尚未确定的**（我没有继续深挖的原因见下）：
- glibc 内部那条链具体死在哪一步。可疑点是 **glibc 内部加载 NSS 模块时
  用的不是公开 `dlopen`**，而是它私有的 `__libc_dlopen_mode` /
  `_dl_open` 路径 —— 那条路**绕过 LD_PRELOAD 的 `dlopen` 钩子**，
  于是模块被加载到**宿主视角**的路径上（或加载了**宿主**的同名模块）。
  宿主与容器的 `/etc/passwd` 内容**恰好相同**（实测），所以如果加载的是
  宿主模块 + 宿主 `/etc/passwd`，结果**应该也是对的** —— 但它返回 0 条，
  所以这个解释**也不完全成立**，需要进一步证据。

> **诚实标注**：我**没有**定位到最终根因。上面 A/B/C 三层数据是可靠的，
> 但"哪一步断了"仍需接手者用更细的手段（`LD_DEBUG=libs` 看 glibc 内部
> 实际加载了什么、`strace -f` 看它 open 了哪个文件）确定。

## 五、建议的下一步（供接手者）

1. **`LD_DEBUG=libs`**（bxroot 侧设 `BXROOT_` 无关，直接设 `LD_DEBUG=libs`）
   观察 glibc 加载 NSS 模块时**实际打开的文件路径** —— 这是最直接的证据。
   注意：`LD_DEBUG` 输出量大，用 `2>&1 | grep -iE "nss|passwd"` 过滤。
2. **`strace -f -e trace=openat,open`** 过滤 `nss`/`passwd`。
3. 若确认 glibc 走了私有加载路径（绕过 `dlopen` 钩子），那就需要
   **在 `__libc_dlopen_mode` / `_dl_open` 层面**做处理 —— 但注意
   `docs/dlsym垫片与插件加载修复.md` 记录了本项目在 `dlsym` 上
   **148 处错误改动被全部回滚**的教训：**这个方向高危，动手前必须有
   独立测试覆盖，且先确认假设。**

> **先测后改**：目前连"哪一步断了"都还没有硬证据。
> 直接动手改 `dlopen`/`ld.so` 层是本项目历史上最容易出错的方向。

## 六、影响面

- `getent`、`id`（组名解析）、python 的 `pwd`/`grp` 模块、
  `passwd -S`（缺口 D 的最初触发者）等一切走 NSS 的工具
- DSHA 主链路（node）不直接依赖，**但 dsh 的 write 工具或插件若用 NSS 会受影响**
- 与缺口 C（降权族）**无关但会叠加**：`passwd -S root` 同时受两者影响，
  子代理已实测"补了 setter 也没用"（零 SIGSYS 命中）—— 因为它的阻塞点是 D

