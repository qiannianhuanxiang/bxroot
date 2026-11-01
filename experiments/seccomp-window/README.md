# seccomp-window 实验

验证"按指令地址窗口 TRAP + 加载时改写 svc"方案。

- `probe.c`：窗口内 svc 经 seccomp 陷阱 vs 改写成跳转的耗时与正确性对照。
- `child.c`：fork+exec 子进程辅助程序。

构建：`gcc -O2 -o probe probe.c`。结论见 docs 或提交说明；原生进程继承过滤器的行为尚未在真机验证。
