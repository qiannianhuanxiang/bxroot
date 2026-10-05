/*
 * static_exec.h —— 进程内装载并执行无 PT_INTERP 的静态 ELF
 *
 * 设计与边界见 static_exec.c 文件头。
 */
#ifndef BXROOT_STATIC_EXEC_H
#define BXROOT_STATIC_EXEC_H

/*
 * host 为**已翻译的宿主路径**；argv/envp 原样成为新程序的 argv/envp。
 * 成功不返回；失败返回 -1 且进程状态未被改动（errno 已置），调用方应回退
 * 到 stub-loader。多线程进程、ET_EXEC 地址冲突、站点超出预留均属失败。
 */
int px_static_exec(const char *host, char *const argv[], char *const envp[]);

#endif /* BXROOT_STATIC_EXEC_H */
