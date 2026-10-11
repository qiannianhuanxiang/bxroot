# statx NULL 输出错误：独立 raw 基线与 guard 对照

本轮修复的是测试前提，未修改 `src/runtime/syscall_guard.c`。

## 源码与环境证据

`syscall_guard.c` 的 `raw_syscall6()` 发出 AArch64 `svc`，将内核约定的负值转换为 `-1/errno`。statx 结果补丁只在 `ret == 0 && number == 291 && a4 != 0` 时执行；没有提前把 NULL 输出转成 EFAULT 的分支。因此本项不是用户态 NULL 解引用或错误优先级被 guard 改写。

当前父进程实际运行 `libproot.so --link2symlink ... -0 --rootfs=...`。inline svc 绕过本项目的 `syscall()` 符号，但仍由外层 ptracer 处理，不能把结果标为未经模拟的 Linux 内核真值。

独立探针仅调用 statx(291)，没有枚举其他 syscall。有效路径为 `/proc/self/status`：

| 参数 | raw 结果 | guard 结果 |
|---|---:|---|
| flags=0，mask=0x7ff，有效输出 | 0 | 0 |
| flags=0，mask=0x7ff，NULL 输出 | -22 | -1 / EINVAL |
| flags=0x80000000，有效输出 | 0 | 0 |
| flags=0x80000000，NULL 输出 | -22 | -1 / EINVAL |
| mask=0x80000000，有效输出 | 0 | 0 |
| mask=0x80000000，NULL 输出 | -22 | -1 / EINVAL |
| 缺失路径，NULL 输出 | -2 | -1 / ENOENT |

外层对有效输出忽略部分非法 flags/mask，对 NULL 输出返回 EINVAL。旧测试固定要求 EFAULT，不能在这一环境中成立。为凑该断言而给 guard 添加早期 EFAULT 会错误覆盖已有 EINVAL、ENOENT 及可能的其他前置错误。

## 修改与判据

`test/test_id_syscall_guard.c` 新增限定的 raw statx helper，以及 7 个同参数对照。guard 接收 guest 路径，raw helper 接收该路径已知的翻译目标；逐项严格要求返回值和 errno 等于原始基线，不允许 `EFAULT || EINVAL` 二选一。正常基线必须成功且输出 mode 有效；NULL 基线必须失败；缺失路径必须保持 ENOENT。非法参数对照防止 NULL 优先短路覆盖原始错误。每个 case 还严格验证只翻译 a1、不把输出地址送入路径翻译桩。

有效输出下外层忽略非法参数时，对照只证明 guard 没改变外层结果，不能证明原生 Linux 的 flags/mask 校验。脱离外层 PRoot 的平台上同一矩阵会严格跟随该平台 raw 结果；原生 EFAULT 仍须精确返回 EFAULT。

## 实际验证

- `sh test/RUN_ID_SYSCALL.sh`：83 项检查，0 失败，RESULT: PASS。
- 同一测试与 guard 以 `-std=c11 -O1 -Wall -Wextra -Werror` 严格编译通过。
- 限定文件 diff 格式检查通过。
- 未修改 sysvshm、总运行器或 runtime 行为，未提交。

测试日志：`/root/work/bxroot-id-statx-final.log`。独立基线探针位于 `/root/work/bxroot-statx-baseline.c`，只发 syscall 291。
