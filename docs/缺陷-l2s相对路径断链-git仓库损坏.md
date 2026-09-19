# 缺陷调查：l2s 中间层相对路径断链（git 仓库损坏的根因）

> **状态**：已最小复现、已定位代码层次。**真实缺陷**（用户可见：
> `git commit` fatal "not a valid object"、仓库损坏）。
> 修复未实施，方案见文末。

---

## 一、现象（真实世界）

容器内 `git init && git add && git commit`：

- `git add` 成功（对象落盘）
- `git commit` fatal: `<sha> is not a valid object`
- `git fsck`：`bad sha1 file: .git/objects/45/.l2s.tmp_obj_*`、
  `unable to mmap .git/objects/45/b983...: No such file or directory`
- 仓库目录里残留 `.l2s.*` 中间层文件与**断链的符号链接**

## 二、最小复现（与 git 无关，纯 l2s）

**复现条件：`link()` 的参数用【相对路径】且 cwd 与链接目标目录不同。**

```sh
mkdir -p /tmp/l2rel2/.git/objects/df
cd /tmp/l2rel2                      # cwd = 仓库根（父目录）
# 探针在容器内执行：link(".git/objects/df/src.dat", ".git/objects/df/dst.dat")
$ bxroot --link2symlink /tmp/l2sl .git/objects/df/src.dat .git/objects/df/dst.dat
```

落盘结果（宿主视角 `$ROOTFS/tmp/l2rel2/.git/objects/df/`）：

```
dst.dat -> .git/objects/df/.l2s.src.dat0001              ← 断链的 symlink
.l2s.src.dat0001 -> .git/objects/df/.l2s.src.dat0001.0002 ← 同样断链
.l2s.src.dat0001.0002                                    ← 真实数据在这
.l2s.src.dat0001.0002.cnt                                ← 引用计数
```

`cat /tmp/l2rel2/.git/objects/df/dst.dat` → ENOENT（用户可见失败）。

**对照（同探针，cwd = 文件所在目录，相对名 `src.dat dst.dat`）**：
`dst.dat -> .l2s.src.dat0001` —— 链接可用 ✅。

**对照（绝对路径 link）**：target 是绝对路径，可用 ✅。

## 三、根因

`link()` 钩子对**相对路径不做翻译**（设计如此，`translate_path` 只翻
绝对路径），把相对形态直接传给 `l2s_rt_link`：

1. `l2s_make_paths_ex(orig=相对路径)` → `mid` / `final` 也是**相对形态**
2. 落盘：`symlink(mid, oldpath)`、`symlink(final, mid)` ——
   这些相对 symlink 在**创建时的 cwd** 下是正确的
3. 但链接是**持久的文件系统对象**：一旦从别的目录/别的进程读它
   （git 读取 objects），相对 target 按**链接所在目录**解析 → 多出
   一截路径 → 断链

也就是说：l2s 中间层的**磁盘形态依赖了创建进程的 cwd**，而符号链接
的解析基准是**链接自身的位置**，两者不一致时断链。

## 四、为什么 git 一定踩中

git 的 loose object 写入流程（`object-file.c`）在**仓库根**运行时用
**相对路径** `.git/objects/<xx>/tmp_obj_*`、`link()` 到
`.git/objects/<xx>/<sha>`。而读取方（后续任何 git 进程）从其它 cwd
或用绝对路径访问 —— 断链立刻暴露。

## 五、修复方向（未实施）

**方案（推荐）**：`l2s_rt_link`（以及 rename/同族的其它入口）在入口处
把**相对路径转成绝对**（基于当前 cwd，`getcwd` + 拼接；路径超长按
EINVAL 处理），再走 `l2s_make_paths_ex`。这样：

- mid/final 恒为绝对形态 → symlink target 是绝对 → 与 cwd 无关
- 对绝对路径输入零影响（原样通过）
- 改动集中在 l2s-runtime.c 的少数入口，不动 l2s.c 纯逻辑
  （纯逻辑测试传相对路径的用例需要同步审视）

**备选**：`symlink()` 钩子统一把 target 绝对化 —— 影响面更大
（用户的相对 symlink 会被改语义），**不采用**。

验证：最小复现两形态对照 + `git init/add/commit/log/fsck` 全流程 +
`RUN_L2S_ENTRYPOINTS` / `RUN_TESTS`（l2s 纯逻辑）回归。
