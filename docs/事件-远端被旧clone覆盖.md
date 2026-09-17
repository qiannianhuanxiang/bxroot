# 事件记录：远端仓库被旧 clone 强制覆盖（已恢复）

> **状态**：已恢复，无数据损失。**根因已定位并切断**。
> **时间**：2026-09-17 20:52（发现于一次正常推送后核对 hash）

---

## 一、现象

`git push --force origin main` 报成功，但推送出的 hash 与我本地 HEAD
**不一致**：

```
To https://github.com/qiannianhuanxiang/bxroot.git
 + 48217db...cf9c7db main -> main (forced update)

本地 HEAD:  b4f5ebb feat(cli): 补 -l 别名；新增上游选项表与路径形态两项回归
远端 HEAD:  cf9c7db docs: 官方 seccomp 补丁分析     ← 完全不同的谱系
```

★ **这里是本事件最关键的一点**：`git push` 报成功，且输出里确实有
`forced update`。如果只看"推送成功"就收工，这条就永远发现不了。
**核对 hash** 是唯一能暴露它的动作。

---

## 二、根因

容器里存在**多个指向同一远端的 clone**，其中三个停留在 09-16 的旧状态：

| clone | HEAD 时间 | 是否含我的后续工作 |
|---|---|---|
| `/tmp/bxroot-final`   | 09-16 14:54 | ❌ 不含 |
| `/tmp/bxroot-final2`  | 09-16 14:55 | ❌ 不含 |
| `/tmp/bxroot-verify`  | 09-16 14:51 | ❌ 不含 |
| `/tmp/bxroot-git`     | 09-17 20:52 | ✅ 当前工作副本 |

这三次 `push --force` 里的 `update by push` 记录与旧 clone 的时间线吻合。
`--force` 的语义是"**用我这条谱系无条件替换远端**"，所以旧 clone 一推就
把远端整体换回 09-16 的状态。

### 为什么危害比"回退一天"更大

远端那 50 个文件**全部是我方文件的旧版本**（实测 `comm -13` 结果为 0，
即远端无任何独有文件），所以不是"两套内容需要合并"——是**单方面覆盖**。

具体丢了什么：

| 项 | 旧快照 | 我的谱系 |
|---|---|---|
| 文件总数 | 50 | **123** |
| `test/` 下 | 9 | **30** |
| `src/runtime/` 下 | 18 | **21** |
| `docs/` | 6 | **43** |
| `src/preload.c` | 还在旧路径 | 已归位到 `src/runtime/` |

即：v0.1.0 发行之后的所有工作（回归套件、43 份文档、dpkg/NSS/utimensat
修复、本次的 `-l` 与两项新回归）全部不在远端。

---

## 三、处置

### 3.1 先固化双方，再动手

★ 恢复动作本身有风险（又一次 `--force`）。所以**先备份，后恢复**：

```sh
git branch -f rescue-mine   b4f5ebb     # 我的谱系
git branch -f rescue-remote origin/main # 被推上去的旧谱系
git bundle create /root/bxroot-rescue/all-refs.bundle --all
git archive rescue-mine   -o /root/bxroot-rescue/mine.tar
git archive rescue-remote -o /root/bxroot-rescue/remote.tar
git reflog --date=iso > /root/bxroot-rescue/local-reflog.txt
```

### 3.2 判定哪条谱系该留

判据不是"谁新"，而是**内容包含关系**：

```sh
comm -13 <(git ls-tree -r --name-only rescue-mine | sort) \
         <(git ls-tree -r --name-only rescue-remote | sort) | wc -l
# → 0    远端无任何独有文件，我的谱系是完整超集
```

这条判据很重要：若结果非 0，就必须先看那些独有文件是什么，**不能**
直接 force —— 可能双方各有产出。

### 3.3 恢复

```sh
git push --force origin rescue-mine:main
git fetch origin main && git log --oneline -1 origin/main   # 核对 hash
```

实测恢复后：远端 123 个文件，`test/RUN_PATH_FORMS.sh`、
`test/RUN_UPSTREAM_CLI.sh`、`docs/已知限制与架构能力边界.md` 均在。

### 3.4 切断误推途径

```sh
# 三个旧 clone 的 remote 换成无效地址 —— 让"误推"从可能变成不可能
for d in /tmp/bxroot-final /tmp/bxroot-final2 /tmp/bxroot-verify; do
    git -C "$d" remote set-url origin "https://invalid.local/DISABLED-$(basename $d).git"
done
```

★ 用**改 remote 地址**而不是删 clone：删掉会丢掉历史现场，改地址既保留
可查性，又让 push 必然失败（失败是响亮的，静默覆盖才是危险的）。

### 3.5 顺带修掉的凭证隐患

旧 clone 的 remote URL 把 token **内嵌在明文**里
（`https://qiannianhuanxiang:ghp_xxx@github.com/...`）。这类 URL 会：

- 出现在 `git remote -v`、`.git/config`、`git log` 的输出里
- 被任何把这些输出贴进报告/日志的动作带出去

改为标准做法：

```sh
git remote set-url origin https://github.com/qiannianhuanxiang/bxroot.git
git config credential.helper store
printf 'https://user:TOKEN@github.com\n' > /root/.git-credentials
chmod 600 /root/.git-credentials
```

---

## 四、教训（可复用的部分）

### 4.1 `push` 成功 ≠ 推的是我的东西

**核对 `git rev-parse HEAD` 与 `git ls-remote origin main` 是否相等**，
这是唯一可靠的确认。本项目现在把它作为推送后必做动作。

### 4.2 多个 clone 指向同一远端 + `--force` = 定时炸弹

`--force` 本身不是问题（本项目历史需要重写），**问题是它没有
"远端是不是被我覆盖了别人"的检查**。防御办法：

- 只保留**一个**推送用的 clone，其余 clone 停用 remote
- 或推送前 `git fetch` 并检查 `git merge-base --is-ancestor origin/main HEAD`
  （自己是否包含远端当前状态）

第二条更通用，值得固化成习惯：

```sh
# 推送前：远端当前 HEAD 是不是我的祖先？
git fetch origin main
git merge-base --is-ancestor origin/main HEAD \
  || echo "⚠️ 远端有我没有的提交 —— 先看清楚再推"
```

### 4.3 崩溃/失败会说话，成功不会

本缺陷的信号只有"hash 不一样"这一个。相比之下，子代理误用 `pkill`、
误删共享目录这类问题都会立刻报错。**静默的破坏需要主动核对才能发现**，
所以核对动作不能省。

---

## 五、遗留

- `/tmp/bxroot-release` 的 HEAD 是 **09-17 19:20**（比另外三个新，
  但仍不含 20:52 的提交）。它的 remote 是干净 URL，**暂未停用** ——
  因为它可能仍被用于发版流程。若后续确认无用，应一并停用。
- 三个旧 clone 仍在磁盘上（只是推不动了）。若要彻底清理，需先确认
  它们没有其它用途（例如存放着未提交的现场文件）。
