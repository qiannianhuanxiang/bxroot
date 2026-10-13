# bxroot v0.2.4

源码与运行库发行，不含 DSHA APK、DSHA 源码或设备数据。运行库行为与 v0.2.3 相同（默认 profile，SHM gate 关闭）。

## 变化

- launcher `-V` 与发行版本一致（v0.2.3 附件里仍是 `0.1.4`）。
- README 重构，开发笔记迁出到 `docs/DEVELOPMENT-NOTES.md`。
- 更正 README 中的过时数字，上游 issue 回归标注为快照。
- 新增三后端基准脚本 `test/host/bench_backends.py`（含成功断言与自检）。

## 验证

| 项 | 结果 |
|---|---|
| 编译告警门禁 | 22 单元零告警 |
| `RUN_CLI_COMPAT` | 41 / 41 |
| `RUN_UPSTREAM_CLI` | 35 / 35 |
| 基准 | 首轮只有 `find /usr` 一项可信（proot 与 bxroot 条目数均为 8413）；其余作废，不作性能结论 |

## 边界

同 v0.2.3：bxroot 不是安全沙箱；默认构建拒绝新建 SysV SHM；官方 proroot 混合并发不协调。
