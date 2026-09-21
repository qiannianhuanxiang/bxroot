# 已知限制：直接调用 `ld.so` 段错误（外层加载器限制，**非 bxroot 缺陷**）

> **状态：不修（不属于本项目）。** 三方对照证明这是**外层 proroot 加载器**
> 的限制：不加载任何 runtime 时正常，加载**官方 proroot runtime 同样
> 段错误** —— 与 bxroot 无关。

## 一、现象

```sh
$ bxroot-run -- /lib/ld-linux-aarch64.so.1 --version
Segmentation fault            # rc=139
```

## 二、三方对照（决定性）

| 环境 | `ld.so --version` |
|---|---|
| **不加载任何 runtime** | ✅ 正常打印版本 |
| **官方 proroot runtime** | ❌ **rc=139 段错误** |
| bxroot runtime | ❌ rc=139 段错误 |

官方与 bxroot **表现完全相同**，所以根因在**两者共用的那层**（外层
proroot 的自研加载器 + bridge/linker），不在任一 runtime 内。

**机理**：`ld.so` 本身就是动态链接器，而外层加载器的工作方式正是
"自己 mmap 客户程序然后跳进去" —— 把一个链接器当成普通客户程序加载，
再叠加它自己对 `_rtld_global` / `_dl_*` 的处理，冲突是结构性的。

## 三、影响：`ldd` 不可用

`ldd` 是一个 `#!` 脚本，内部调用 `ld.so` 来列出依赖，所以继承同一问题：

```sh
$ bxroot-run -- /usr/bin/ldd /bin/true
	not a dynamic executable        # ← 形状像"成功"，其实是错的
$ ldd /bin/true                     # 宿主
	libc.so.6 => /usr/lib/.../libc.so.6 (0x...)
	/lib/ld-linux-aarch64.so.1 => .../ld-linux-aarch64.so.1 (0x...)
```

★ **"成功形状的错答案"比报错更危险** —— 调用方看到
`not a dynamic executable` 会以为"这个程序是静态的"，从而走错分支。
如果哪个构建系统用 `ldd` 判断链接方式，会得到相反结论。

**替代方案**（都能正确工作）：
- `readelf -d <file>` 看 `NEEDED`
- `objdump -p <file> | grep NEEDED`
- `LD_TRACE_LOADED_OBJECTS=1` 由外层加载器静默忽略，**不可用**

## 四、为什么记为"已知限制"而不是缺陷

1. **不是 bxroot 引入的** —— 官方 runtime 表现相同（见上表）；
2. **无法在 bxroot 层修复** —— `ld.so` 的执行发生在**运行时被加载之前**
   （它是启动路径的一部分），bxroot 的钩子那时还不存在；
3. 与 `docs/已知限制与架构能力边界.md` 里 `df`/`make` 那几条同一性质：
   边界由**外层容器**划定，本项目的合理做法是**如实记录 + 给出替代**。

## 五、发现者说明

本条由最终验收子代理报为"bxroot bug（E2）"。**该归因经复核后推翻** ——
只在 bxroot 上测会自然怀疑 bxroot，补上官方 runtime 的对照才看清是
外层限制。这也是本项目反复出现的教训：
**没有对照的"失败"和没有对照的"成功"一样不可信**
（参见 `docs/两处控制实验缺陷更正.md`）。
