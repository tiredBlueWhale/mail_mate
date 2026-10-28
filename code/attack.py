#!/usr/bin/env python
"""攻击方 CLI 工具 —— 技术实现见 attack_upload.py。
Attacker CLI utility — the techniques now live in attack_upload.py.

本文件只保留命令行自测入口：读对阵集、运行上传版 attack(env)、保存注入内容。
This file only keeps the command-line self-test entry: read the match set, run the uploaded
attack(env), and save the injected payloads.

用法 / Usage:
    python attack.py                 # 读对阵集，注入全部邮件并保存注入内容
    python attack.py                 # Read the match set, inject all emails and save payloads
"""

from __future__ import annotations

import argparse
import json
import os

from dataset import load_matches
from attack_upload import attack

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="部门身份冒充注入攻击 CLI（技术见 attack_upload.py）",
        # description="Identity impersonation injection attack CLI (techniques in attack_upload.py)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--matches", type=int, default=20, help="对阵场数")
    # parser.add_argument("--matches", type=int, default=20, help="Number of matches")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    # parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", default="data/attack_payloads.json",
                        help="输出文件：{match_id: 注入内容}")
                        # help="Output file: {match_id: injected content}")
    args = parser.parse_args()

    from dataset import MailMateEnv

    out = {}
    for m in load_matches(args.matches, args.seed):
        env = MailMateEnv(attacker_email=m["attacker_email"])
        attack(env)   # uploaded attack entry point (attack_upload.py)
        ok = env.injection_success
        out[m["match_id"]] = {
            "attacker_email": m["attacker_email"],
            "injected": env.injected,
            "injection_success": ok,
        }
        print(f"[attack] {m['match_id']}: 注入成功={ok}, 注入邮件={sorted(env.injected)}")
        # print(f"[attack] {m['match_id']}: injection_success={ok}, injected_emails={sorted(env.injected)}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    max_bytes = max((len(p.encode("utf-8")) for rec in out.values()
                     for p in rec["injected"].values()), default=0)
    print(f"[attack] 上传版攻击已注入 {len(out)} 场对阵 -> {args.output}")
    # print(f"[attack] Uploaded attack has injected {len(out)} matches -> {args.output}")
    print(f"[attack] 单条载荷最大字节数: {max_bytes}")
    # print(f"[attack] Maximum bytes of a single payload: {max_bytes}")
