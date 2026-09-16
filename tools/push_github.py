#!/usr/bin/env python3
"""
把 bxroot 项目推送到 GitHub（走 Contents API，因为 git 端点不可达）。

背景：本环境的 github.com:443 不通（TCP 超时），但 api.github.com 可达。
所以不能用 git push，只能用 Contents API 逐个文件写。代价是没有真正的
git 历史 —— 每个文件一次提交。这对首次上传是可接受的。

用法：
    python3 tools/push_github.py --dry-run     # 只看要传什么
    python3 tools/push_github.py               # 实际推送
"""
import base64
import fnmatch
import json
import os
import sys
import time
import urllib.error
import urllib.request

REPO = "qiannianhuanxiang/bxroot"
TOKEN = os.environ.get("GITHUB_TOKEN", "")

# 不传的东西：
#   build/   编译产物（应由 CI 或使用者自己生成）
#   work/    子代理的临时分析目录
#   .git/    版本控制元数据
SKIP_DIRS = {"build", "work", ".git", "__pycache__"}
#   二进制与中间产物
SKIP_PATTERNS = ["*.so", "*.o", "*.a", "*.tmp", "*.bak", "*.log",
                 "*.pyc", "*.tar", "*.tar.gz", "*.bin"]
#   单文件上限（Contents API 对超过 1MB 的文件需要 blob API，这里先避开）
MAX_SIZE = 900 * 1024


def collect(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if any(fnmatch.fnmatch(fn, p) for p in SKIP_PATTERNS):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > MAX_SIZE:
                print(f"  跳过（过大 {size} 字节）: {rel}")
                continue
            files.append((rel, size))
    return sorted(files)


def api(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "bxroot-push")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode()
            return r.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"message": body[:200]}
    except Exception as e:
        return 0, {"message": str(e)}


def get_sha(repo, path):
    """取已存在文件的 sha（更新时必须带，否则 422）。"""
    st, body = api("GET", f"https://api.github.com/repos/{repo}/contents/{path}")
    if st == 200 and isinstance(body, dict):
        return body.get("sha")
    return None


def put_file(repo, path, content_bytes, message):
    sha = get_sha(repo, path)
    payload = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode(),
    }
    if sha:
        payload["sha"] = sha
    st, body = api("PUT", f"https://api.github.com/repos/{repo}/contents/{path}", payload)
    if st in (200, 201):
        return True, body.get("commit", {}).get("sha", "")[:10]
    return False, f"{st} {body.get('message', '')[:120]}"


def main():
    global REPO
    dry = "--dry-run" in sys.argv
    if "--repo" in sys.argv:
        REPO = sys.argv[sys.argv.index("--repo") + 1]
    if not TOKEN and not dry:
        print("错误：需要环境变量 GITHUB_TOKEN")
        return 1

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = collect(root)
    total = sum(s for _, s in files)
    print(f"仓库: {REPO}")
    print(f"文件: {len(files)} 个，合计 {total} 字节\n")

    if dry:
        for rel, size in files:
            print(f"  {size:>8}  {rel}")
        return 0

    ok = fail = 0
    for i, (rel, size) in enumerate(files, 1):
        with open(os.path.join(root, rel), "rb") as f:
            blob = f.read()
        success, info = put_file(REPO, rel, blob, f"add: {rel}")
        if success:
            ok += 1
            print(f"  [{i}/{len(files)}] ✅ {rel}  ({info})")
        else:
            fail += 1
            print(f"  [{i}/{len(files)}] ❌ {rel}  {info}")
        time.sleep(0.15)      # 轻微限速，避开 secondary rate limit

    print(f"\n完成：成功 {ok}，失败 {fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
