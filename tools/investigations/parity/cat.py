import collections
syms = open("onlyoff_f.txt").read().split()
def cat(s):
    if s.startswith(("proroot_drm","drm","gbm","libseat","proroot_seat")): return "A. DRM/GBM/seat 图形栈（宿主 App 专用）"
    if s.startswith("proroot_"): return "B. proroot_* 内部符号（官方私有）"
    if s.startswith("fake_id0"): return "C. fake_id0_*（官方 fakeroot 内部 API）"
    if s.startswith("link2symlink"): return "D. link2symlink_*（官方 l2s 内部 API）"
    if s.startswith("audit"): return "E. libaudit 符号（审计）"
    if s in ("dlsym","dlerror","dladdr","dladdr1","dlinfo","dl_iterate_phdr"): return "F. dl* 符号（★ 禁止导出，会无限递归）"
    if s.startswith("__"): return "G. __* glibc 内部别名（官方为 4 字节跳转桩）"
    if s in ("translate_path","detranslate_path","g_canon_buf"): return "H. 官方内部翻译器符号"
    return "I. 其他 libc/图形符号"
g = collections.defaultdict(list)
for s in syms: g[cat(s)].append(s)
tot=0
for k in sorted(g):
    print(f"\n{k}  —— {len(g[k])} 个"); tot+=len(g[k])
    print("   " + " ".join(sorted(g[k])))
print(f"\n合计 {tot} 个")
