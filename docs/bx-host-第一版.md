# bx-host 第一版：显式进入 Android bionic world

`bx-host` 是 bxroot 原生调用的第一版入口。它不改变现有 guest 的 `execve` 热路径，而是在 guest 中提供一个显式命令：

```sh
bx-host /system/bin/getprop ro.product.model
bx-host toybox uname -a
bx-host /system/bin/sh -c 'getprop ro.product.model'
```

它是无 libc 的静态 AArch64 程序，所有 ELF 检查和 `execve` 都使用 raw `svc`。这样它能由 bxroot 的 static-exec 路径装载，也不会再次进入 bxroot 自己的 exec hook。

## 判断规则

- 目标必须是 AArch64 ELF。
- 动态 ELF 的 `PT_INTERP` 必须精确等于 `/system/bin/linker64` 或 `/apex/com.android.runtime/bin/linker64`。
- 没有 `PT_INTERP` 的静态 ELF 只有在 `/system`、`/system_ext`、`/product`、`/vendor`、`/odm` 或 `/apex` 下才接受。
- 不读取 guest 的 `PATH`，名字搜索固定使用：

```text
/system/bin:/system/xbin:/vendor/bin
```

这样不会把 `/usr/bin` 里的 glibc 程序误送给 Android linker。

## 环境

宿主程序得到 Android 最小环境：

```text
PATH=/system/bin:/system/xbin:/vendor/bin
ANDROID_ROOT=/system
ANDROID_DATA=/data
ANDROID_RUNTIME_ROOT=/apex/com.android.runtime
ANDROID_ART_ROOT=/apex/com.android.art
ANDROID_I18N_ROOT=/apex/com.android.i18n
ANDROID_TZDATA_ROOT=/apex/com.android.tzdata
HOME=/data/local/tmp
TMPDIR=/data/local/tmp
```

共享环境策略会保留 `TERM`、`LANG`、`LC_*`、`FOO` 等普通应用变量；guest 的 `LD_*`、`BXROOT_*`、`PROROOT_*`、`PROOT_*`、`PWD` 和 `OLDPWD` 不会传入宿主。`PATH`、`HOME`、`TMPDIR` 和上述 Android runtime 变量由入口重建。原始 `argv[0]`、stdio、PTY、信号和退出状态由内核直接继承。

第一版独立工具仍使用最多 128 槽的环境数组，并固定 `HOME/TMPDIR=/data/local/tmp`，不保证该目录对普通 App 可写。第二版自动分流使用动态环境数组，并提供可配置、实际可写的 host HOME/TMPDIR；不能把这两项第二版行为等同于独立 `bx-host`。

## 已验证

Termux 的 bxroot v4 guest 中已验证：

- `/system/bin/getprop ro.product.model` → `V2352A`，rc=0；
- `/system/bin/toybox uname -a` → Android kernel 信息，rc=0；
- `/system/bin/sh -c 'getprop ro.product.model'` → `V2352A`，rc=0；
- 宿主环境中存在 Android `PATH`、`ANDROID_ROOT`、`HOME`、`TMPDIR`，没有 guest 的 `LD_*`；
- `/usr/bin/true` 被拒绝并返回 rc=126，而不会误交给 bionic linker。

`/system/bin/ls /system/bin` 在当前普通 app 身份下被 Android 文件权限拒绝；这是宿主权限结果，不是 bx-host loader 失败。

## 当前边界

第一版是显式入口，不会自动把 guest 中所有 `/system/bin/*` 的普通 `execve` 改成宿主执行。Termux 命令和 Android 服务仍需要后续的 Termux RPC / host broker / `/app/*` 后端。该程序也不会提高 UID 或 SELinux 权限。
