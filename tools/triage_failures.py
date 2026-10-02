#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
triage_failures.py —— 回归失败自动归类小工具（内部用）

跑完 test/RUN_ALL.sh 后，把失败项喂给 LLM 做初步归类（路径层 / 身份层 /
livepatch / 进程管理…），省得每次手动翻几十条 RESULT。纯开发期辅助，
不进构建、不影响运行时。

用法:
    sh test/RUN_ALL.sh 2>&1 | python3 tools/triage_failures.py
"""

import os
import sys
import json
import urllib.request

# --- LLM 端点（OpenAI 兼容）----------------------------------------------
# 端点与 key 一律从环境变量读取，不入库（审计：原先硬编码 key 与临时隧道地址）。
# 回归日志会发往该端点 —— 只配置你信任的服务。
OPENAI_BASE_URL = os.environ.get("TRIAGE_LLM_BASE_URL", "")
OPENAI_API_KEY = os.environ.get("TRIAGE_LLM_API_KEY", "")
MODEL = os.environ.get("TRIAGE_LLM_MODEL", "")


def ask_llm(prompt):
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "你是 bxroot 项目的回归失败归类助手。"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OPENAI_BASE_URL}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def main():
    text = sys.stdin.read()
    fails = [ln for ln in text.splitlines() if "❌" in ln or "FAIL" in ln]
    if not fails:
        print("没有失败项，跳过归类。")
        return
    if not (OPENAI_BASE_URL and OPENAI_API_KEY and MODEL):
        print("[triage] 未设置 TRIAGE_LLM_BASE_URL / TRIAGE_LLM_API_KEY / "
              "TRIAGE_LLM_MODEL，跳过 LLM 归类。失败项：")
        print("\n".join(fails))
        return
    prompt = "把下面这些 bxroot 回归失败按子系统归类，并给出最可能的根因方向：\n\n" + "\n".join(fails)
    try:
        print(ask_llm(prompt))
    except Exception as e:
        print(f"[triage] LLM 调用失败（{e}），请手动查看失败项：")
        print("\n".join(fails))


if __name__ == "__main__":
    main()
