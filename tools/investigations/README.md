# 调查脚本归档

这里归档的是**文档中作为证据引用**的一次性调查脚本。它们原本散在
开发期临时目录 `work/`（该目录被 `.gitignore` 排除，因为多数内容
是编译产物与快照），导致文档里 `work/xxx.py` 之类的引用在远端
**无法复现**。

归档标准：只收被 `docs/` 明确引用、且是纯文本（.py/.c/.sh/.mjs）的
脚本。二进制产物与一次性快照不收。

| 归档路径 | 原位置 | 引用文档 |
|---|---|---|
| `parity/cat.py`, `parity/one.sh` | `work/parity/` | `docs/parity-补齐报告.md` |
| `probe-webplugin/linkq.c`, `dlonly2.c`, `walk.mjs` | `work/probe-webplugin/` | `docs/web插件加载失败调查.md` 等 |

注意：这些脚本里的路径多为开发期绝对路径（如容器内 rootfs），
直接跑需按当前环境调整。
