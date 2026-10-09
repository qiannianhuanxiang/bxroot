# bxroot 原生调用第三版规划：双向执行与会话交接

状态：第三版核心实现已提交为 `8e45e49`，后续补充 proc fd 句柄解析修复和严格真机回归。本页保留原规划；当前接口、启用方式与边界以 [第三版说明](bx-host-第三版.md) 为准。Android 原生 PIE 和同 UID 回入已验证；DSHA APK 集成仍未验收。

## 1. 目标与范围

第三版优先完成同一 Android App 身份下的 `guest → host → guest` 调用链。第二版已经能让 Ubuntu/glibc 中的 agent 启动 Android/bionic 程序；现在缺少的是宿主程序返回原 guest 的入口，以及跨环境交换文件时明确、可复用的路径语义。

一个可验收的目标场景是：guest Node 启动 `/system/bin/sh`，宿主 shell 调用回入口启动 guest Node，后者再执行 `getprop`，全过程使用原会话的 rootfs、bind、工作目录和运行时配置，正常返回输出及退出状态。

核心目标：

1. 增加显式 host→guest 回入口，复用原会话，而非新建配置不同的嵌套容器。
2. 保存跨 libc 边界所需的会话上下文，不把 guest 的 `LD_*` 注入 bionic 程序。
3. 给 cwd、路径转换和环境继承制定可测试的契约。
4. 对独立 `bx-host` 和自动 host 分流统一必要的环境与会话语义。
5. 在 Termux 与 DSHA 各自真实启动链中验证，分别报告结果。

第三版核心不包含任意 bionic 程序自动拦截后代 exec、不包含跨 App UID 代执行、不包含在同一进程混载 glibc/bionic。Termux companion、通用 Binder 代理及设备能力适配单独划分阶段。

## 2. 已确认的第二版基线

- 自动分流默认关闭，仅 `BXROOT_AUTO_HOST=1` 开启；guest 同名程序优先。
- ELF、搜索候选和 shebang interpreter 都遵守 rootfs/bind，使用真实 backing path。
- 第二版 Android 25/25、分类/环境 77、分流集成 175、17 单元零告警通过。
- 第二版 Android 验证来自 Termux App 沙箱，不能等同于 DSHA 集成验证。
- 全量 `RUN_ALL --quick` 曾在 l2s 等用例失败，尚未做同环境基线归因。
- 匿名/已删除 bionic fd、相对 spawn 配合 chdir actions，以及初始无 PATH 的 bridge 直加载仍有边界。
- 独立 `bx-host` 当前仍有 128 槽环境上限和固定 `/data/local/tmp` HOME/TMPDIR；自动模式后端已改为动态数组和可配置目录。
- `PROROOT_CFG_FD` 名称虽然含 FD，兼容实现实际读取的是配置文件路径；不能把它直接用作第三版的 fd 会话协议。

## 3. 会话上下文

建议增加独立、版本化的只读会话数据，供 guest runtime 和 native 回入口共同读取。先使用继承 fd，避免为同 UID 的调用链引入常驻 HTTP/RPC 服务。

协议至少包含 magic、版本、总长度、字段长度与特性位，携带：

- 生效后的 rootfs、bind 及只读标记，而不只复制原始环境字符串；
- fakeroot 身份配置、l2s 配置及应继承的 runtime 行为开关；
- bridge/linker/runtime/stub/ULX 的实际可访问 backing path，必要时记录其 fd 生命周期；
- 分开的 guest PATH、host PATH、guest HOME/TMPDIR、host HOME/TMPDIR；
- 会话默认 guest cwd 与用于反向解析的路径信息。

cwd 在返回时取调用者的当前目录，不能仅使用启动时保存的 cwd。会话可以保存默认值或提示，不能用旧值覆盖 host 的后续 chdir。

fd 读取使用 `pread`，不依赖共享 offset；并发 fork、不同 guest 会话和不同宿主子进程不能相互覆盖。根据当前 Android 能力选择 memfd 或既有合法的只读 fd 来源，不为此更改最低内核声明。

计划增加 `BXROOT_SESSION_FD` 和 `BXROOT_ENTER` 两个窄接口。host 环境构造仅在回入口启用时保留这两个明确字段，其余 guest loader/internal 变量继续清理。这是待实现的新接口，不是当前已支持的配置。

fd 号动态分配，不占用 0/1/2，不约定某个固定高位数值。继承 fd 的关闭、dup2 冲突、closefrom/CLOEXEC actions 均须明确处理。如果用户程序主动关闭全部额外 fd，会话可能不可用；入口应返回具体原因，不能沿父 PID 猜测和重建会话。

会话描述配置，不保证所有 guest 进程内可变账本已经跨原生 exec 持久化。fakeroot inode 账本、l2s 状态和进程账本必须逐项审计：已具备持久/共享来源的复用，只有进程内副本的部分不能声称已经保留。配置身份与实际内核 UID 分开验证。

## 4. 回入口与执行链

拟提供 guest 侧命令别名 `bx-enter`，Android 打包采用可位于 nativeLibraryDir 的静态 AArch64 原生入口，例如 `libbxroot-enter.so`，保持 16KB ELF LOAD 对齐，不依赖 guest glibc。

宿主通过 `BXROOT_ENTER` 中的实际路径调用，不能假定 `/usr/bin/bx-enter` 在宿主存在，也不能假定把可执行文件复制进 App data 目录就能执行。

拟定调用形式（仅为接口设计）：

```sh
# guest 中启动原生 shell，原生 shell 显式回到原 guest
/system/bin/sh -c '"$BXROOT_ENTER" -- /usr/bin/printf "back-to-guest\\n"'

# 显式指定返回后的 guest cwd
"$BXROOT_ENTER" --cwd /root/project -- /usr/local/bin/node app.js

# 调用者清掉环境后，可明确提供仍然有效的会话 fd
/path/to/libbxroot-enter.so --session-fd N -- /usr/bin/true
```

回入口复用已验证的 `bridge → linker --argv0 --preload → guest ELF` 链，复原生效配置和 guest loader 环境，不重新走一轮容易覆盖 cwd 的普通 launcher 参数解析。

入口直接 exec 替换自身，避免增加常驻中间进程；stdio、pipe、PTY、进程组和退出状态由原调用链继承。guest runtime 再次启动 host 时继续携带同一会话。

第一阶段优先支持明确的 guest 绝对可执行路径；之后补 guest PATH 搜索与脚本。名称搜索按会话中的 guest PATH 处理，host PATH 不污染回入口的 guest 搜索。argv 采用结构化数组，不拼接 shell 命令字符串。

原生进程不会自动加载 guest exec hooks。`/system/bin/sh -c '/usr/bin/node ...'` 仍不能凭空执行 guest 程序，必须使用回入口；透明拦截所有原生后代需要额外 bionic 注入或另一套监管机制，超出本版核心。

## 5. cwd 与参数路径

默认返回 cwd：读取 host 调用者实际 cwd，经 bind/rootfs 反向映射，并用正向映射校验。能够唯一确定 guest 目录时保留；同一 host 目录对应多个 guest bind、目录已删除或映射失效时，给出明确错误并支持 `--cwd`，不默默回到 `/root`。

拟在同一入口中提供显式转换选项：

```sh
bx-enter --to-host /tmp/report.json
bx-enter --to-guest /actual/backing/path/report.json
```

其中 `bx-enter` 是安装层提供的别名；宿主也可以调用实际入口路径。转换复用生效的映射规则，支持 bind、符号链接、相对 cwd 及尚不存在的输出文件。反向映射歧义应返回状态，而不是随意挑一个 bind。

普通 argv 保持原样，不能把所有形似绝对路径的参数都改写：URL、正则、JSON 和命令文本均可能包含 `/`。文件交接使用显式转换、绑定目录或打开的 fd。例如 guest `/tmp/report.json` 传给 native 工具前，转换成它能看到的 backing path；无需改变其他参数。

## 6. 环境与现有入口收敛

- host 继续使用独立 Android loader 环境；guest 回入口重建 guest loader 环境。
- 普通变量继承调用现场，例如 FOO、TERM、LANG；不保存和恢复整份旧环境来覆盖 host 更新。
- guest/host PATH、HOME、TMPDIR 分开维护，支持显式覆盖；回入口在加载前补齐缺失 PATH。
- `env -i` 清掉会话定位字段后，要求明确指定有效 fd；不承诺无上下文的透明恢复。
- 重复 `guest→host→guest` 时环境与 PATH 不累计增长，内存和 fd 不持续泄漏。
- 独立 `bx-host` 消除无声环境截断，与自动分流共享 host HOME/TMPDIR 和回入口传播契约；必要时采用共享 freestanding 两遍计数/分配，不强迫静态入口依赖 glibc。

## 7. 第二版边缘 exec 的优先级

匿名/已删除 bionic fd 与带 chdir 的相对 spawn 是 P1，放在回入口与路径契约通过之后。

fd exec 必须直接读取同一个 fd 分类并执行，处理 `AT_EMPTY_PATH`、dirfd、符号链接 flags 和 `FD_CLOEXEC`；不能借 `/proc/self/fd` 的显示名臆造真实路径。匿名脚本与 ELF 的内核语义分别验证，遇到 Android 拒绝按实际 errno 返回。

相对 spawn 不能在父 cwd 分类。若引入子进程 dispatcher，须在 actions 完成后的真实 cwd 分类，且保留 `posix_spawn` 同步返回目标 exec errno 的契约。普通 helper 启动成功后目标 exec 失败，不能伪装成 spawn 成功再 exit 127。若握手、actions/fd 交互无法完整验证，本版继续明确保留该边界，不作为 P0 的阻塞项。

## 8. Android 能力适配边界

bxroot 保持通用项目，遵守现有 DSHA 适配约定。运行时不硬编码 DSHA 的端口、凭据、设备端点或 Termux UID。

完成核心之后，DSHA 可以在其自身适配层给 agent 提供结构化设备命令/MCP 接口，对接现有 `/app/*` 能力。其验收包括设备信息、应用启动、读屏/操作后验证及原生权限结果，但该适配的代码与测试属于 DSHA；不把读屏、传感器和系统服务功能计为 bxroot ELF 分流本身提供的能力。

Termux API 命令通常需要 Termux 身份及相应组件。若用户需要在 DSHA 中调用这些能力，另做 Termux companion：结构化 argv、stdio/退出码/取消、明确身份与调用方向。它不等同于同 UID 的 raw exec，也不作为第三版核心必需依赖。

## 9. 实施阶段与交付

| 阶段 | 主要工作 | 完成判据 |
|---|---|---|
| A：固定基线 | 第二版提交；同一环境对比基线和第二版的全量失败 | 列出新回归、原有失败与环境问题，不伪称全绿 |
| B：最小回入口 | 版本化会话、原生入口、绝对 guest ELF 回入 | guest→host→guest 成功，配置与 argv0 正确 |
| C：实用混合调用 | cwd、路径转换、guest 名称搜索/脚本、环境与 bx-host 收敛 | Node/shell/管道/PTY 和重复调用通过 |
| D：边缘 exec | fd exec、相对 spawn/chdir 逐项验证 | 支持项保持 libc errno/actions 契约，未支持项明确报告 |
| E：集成验证 | Termux 真机及 DSHA 实际启动链分别验证 | 两种启动链独立有日志和产物哈希 |
| F：可选设备适配 | DSHA 自身设备命令接口；按需求再做 Termux companion | 设备操作从 agent 到实际结果可追踪，不写入 bxroot 核心 |

第三版核心按 B→C→E 收敛；D 的每项能力单独纳入，F 为集成扩展。建议分开提交会话协议、回入口、路径/env、测试文档，便于定位和回滚。

bxroot 交付为源码、通用运行时 zip（增加原生回入口）、校验值、接口说明和验证日志。DSHA 的 APK 打包和 GitHub Release 是独立交付，不由本规划自动执行。

## 10. 当前实现验证记录

第三版核心实现已在 Termux Android 16 / vivo V2352A / kernel 6.1 的真实 bridge/linker 链路中验证。运行时通过匿名 memfd 加载，未向设备目录写入第三版产物。

- 原生会话 fd：`F_GETFL=O_RDONLY`、`F_GET_SEALS=15`、写入返回 `EBADF`，guest fakeroot UID=0 与真实 App UID=10399 分开可见。
- Android linker 手工启动参数：检测 `AT_BASE` 存在且为 0，并只对精确 linker argv0 去掉一层 argv；正常 PT_INTERP 的非零 `AT_BASE` 不剥离。
- 真机混合回归：初始 bash 变量、host shell→guest、Node→Android `getprop`→guest Node、环境修改、guest/host cwd、显式路径转换、只读 bind、PTY 尺寸/输入、Ctrl-C、pipe EOF、clean env 显式 fd 均通过。
- 最终真机核心矩阵 **21/21 PASS**，额外脚本对照 **7/7 PASS**，同一第三版 runtime 的第二版兼容矩阵 **25/25 PASS**。匿名脚本曾因 runtime 把 proc fd 句柄解析成 `memfd:... (deleted)` 显示名而失败；不是 fd owner 生命周期问题。该路径缺陷已修复，匿名绑定脚本和持久 guest ldd 脚本都恢复严格 PASS，旧 SKIP 结果不作为验收证据。
- 容器回归：告警门禁 21 个编译单元零告警；会话路径 369 PASS、2 个外层 proc fd 语义 SKIP；native-session 18 cases/1454 checks PASS；静态及 freestanding PIE 回入口各 107 checks PASS；第二版 77/175 聚焦回归保持通过。
- 全量 `RUN_ALL --quick` 仍没有重新宣称全绿；l2s 失败已由同环境基线确认是外层 proot 的夹具污染，不是第二版新增回归。

第三版当前仍是实验分支，未部署 DSHA APK，也未发布 Release。

## 11. 核心验收矩阵

1. guest Node → Android sh → guest Node → getprop，输出完整、argv0 正确、退出码准确。
2. 原会话 rootfs、bind、只读标记、身份配置、l2s 配置一致；不存在重复路径前缀或错误的嵌套 rootfs。
3. rootfs 内 cwd、bind cwd、host chdir 后回入、映射歧义及已删除 cwd 均按契约处理。
4. 通过转换后的路径，native 工具可读取 guest 文件；可向 guest 预期的输出路径写入。空间、Unicode、符号链接及嵌套 bind 覆盖。
5. 普通环境保留且现场修改可见；LD_* 在两种 libc 间不串用；缺失 PATH、空 PATH 和 env -i 行为可解释。
6. stdout/stderr、pipe EOF、交互输入、PTY 窗口大小、Ctrl-C、正常 wait 与信号退出正常；核心回入口不增加代理进程。
7. 并发会话不串配置；重复回入不泄漏 fd、不无限延长 PATH；调用者关闭会话 fd 时准确报错。
8. 第二版 25/25 Android、77/175 聚焦回归和 17 单元零告警保持通过；新增测试按新语义断言实际执行结果。
9. Termux 与 DSHA 两种真实启动链分别核验 runtime 生效，不把一方通过当作另一方通过。
10. 全量失败有同环境基线比较；发布说明明确每项 PASS/FAIL/SKIP，不用聚焦回归替代全量结论。
