#!/usr/bin/env python3
"""toksentry —— 零依赖的密钥扫描器（单文件，纯标准库）。

用法：
    python toksentry.py <dir> [--format table|json] [--config rules.json] [--self-test]

退出码：0 干净 / 1 命中（或自检失败）/ 2 运行错误（如规则文件损坏）。

设计要点：
- 只报告「规则名 + 位置 + 打码片段」，绝不把完整密钥写进输出或日志；
- 正则规则 + Shannon 熵兜底，熵阈值取高值以压误报；
- 支持 .toksentryignore（按路径前缀排除）。
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter

DEFAULT_RULES = [
    {"name": "AWS Access Key ID", "severity": "high",
     "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"name": "GitHub Token", "severity": "high",
     "pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"},
    {"name": "Slack Token", "severity": "high",
     "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"},
    {"name": "Stripe Secret Key", "severity": "high",
     "pattern": r"\bsk_live_[0-9a-zA-Z]{24,}\b"},
    {"name": "Google API Key", "severity": "high",
     "pattern": r"\bAIza[0-9A-Za-z_\-]{35}\b"},
    {"name": "Private Key Block", "severity": "high",
     "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"},
    {"name": "JWT", "severity": "medium",
     "pattern": r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"},
    {"name": "Bearer Token", "severity": "medium",
     "pattern": r"\bBearer\s+[A-Za-z0-9._\-]{20,}"},
]

_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
_CAMEL_OR_WORD = re.compile(r"^[A-Za-z]+$")
_SAFE_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
                ".whl", ".pyc", ".woff", ".woff2", ".ttf", ".svg", ".lock")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


def shannon_entropy(s: str) -> float:
    """香农熵（bit/字符）。空串返回 0，随机字母数字串通常 > 4。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _mask(token: str) -> str:
    """打码：保留首 4 位与末 2 位，中间用 *** 代替，避免输出二次泄露。"""
    if len(token) <= 8:
        return token[:2] + "***"
    return token[:4] + "***" + token[-2:]


def _compile(rules):
    out = []
    for r in rules:
        pat = r.get("pattern") if isinstance(r, dict) else None
        if not pat:
            continue
        out.append({"name": r.get("name", "unnamed"),
                    "severity": r.get("severity", "medium"),
                    "re": re.compile(pat)})
    return out


def detect_secrets(content: str, rules=None) -> list[dict]:
    """在一段文本里找疑似密钥，返回 [{rule, severity, token(已打码), entropy}]。"""
    found, seen = [], set()
    for rule in _compile(rules or DEFAULT_RULES):
        for m in rule["re"].finditer(content):
            tok = m.group(0)
            if tok in seen:
                continue
            seen.add(tok)
            found.append({"rule": rule["name"], "severity": rule["severity"],
                          "token": _mask(tok), "entropy": round(shannon_entropy(tok), 2),
                          "pos": m.start()})
    # 熵兜底：抓规则没覆盖到的高随机串（阈值偏高，宁漏不误报）
    for m in _ENTROPY_TOKEN.finditer(content):
        tok = m.group(0)
        if tok in seen or _CAMEL_OR_WORD.match(tok) or tok.startswith(("http", "www")):
            continue
        if shannon_entropy(tok) >= 4.5:
            seen.add(tok)
            found.append({"rule": "High-entropy string", "severity": "medium",
                          "token": _mask(tok), "entropy": round(shannon_entropy(tok), 2),
                          "pos": m.start()})
    return found


def load_rules(path: str | None = None) -> list[dict]:
    """加载规则集：默认内置；给了 JSON 文件就用文件里的（文件坏了直接抛，由上层报错）。"""
    if not path:
        return DEFAULT_RULES
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    if not isinstance(rules, list):
        raise ValueError("rules file must contain a JSON array")
    _compile(rules)
    return rules


def _load_ignore(root: str) -> list[str]:
    p = os.path.join(root, ".toksentryignore")
    if not os.path.isfile(p):
        return []
    pats = []
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pats.append(line.rstrip("/"))
    except OSError:
        pass
    return pats


def _ignored(rel: str, patterns: list[str]) -> bool:
    rel = rel.replace(os.sep, "/")
    return any(rel == p or rel.startswith(p + "/") for p in patterns)


def scan_directory(directory: str, rules=None, ignore=None) -> list[dict]:
    """递归扫描目录，返回命中清单。

    字段契约（release_gate 复用）：file / line / rule / severity / match / entropy。
    `match` 是**打码后**的片段——扫描器的输出本身不能再泄露密钥。
    """
    root = os.path.abspath(directory)
    pats = list(ignore) if ignore else _load_ignore(root)
    results: list[dict] = []
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(cur, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if _ignored(rel, pats) or name.endswith(_SAFE_SUFFIX):
                continue
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            for h in detect_secrets(content, rules):
                pos = h.pop("pos", -1)
                line_no = content[:pos].count("\n") + 1 if pos >= 0 else 0
                results.append({"file": rel, "line": line_no, "rule": h["rule"],
                                "severity": h["severity"], "match": h["token"],
                                "token": h["token"], "entropy": h["entropy"]})
    return results
    return results


def output_table(results: list[dict]) -> None:
    """表格输出（release_gate 复用这个函数名）。"""
    if not results:
        print("no secrets found")
        return
    print("%-40s %6s %-22s %-8s %s" % ("FILE", "LINE", "RULE", "SEVERITY", "MATCH"))
    for r in results:
        print("%-40s %6s %-22s %-8s %s" % (
            r["file"][:40], r["line"], r["rule"][:22], r["severity"],
            r.get("match") or r.get("token", "")))


_print_table = output_table


def self_test() -> bool:
    """内置自检：运行时构造伪密钥，证明「该抓的抓得到、干净代码不误报」。"""
    aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    # 拼接构造，避免源码里出现高熵长字面量（否则本仓库自扫会把自己判成泄露）
    gh = "ghp_" + ("abcdefghij" * 4)[:36]
    stripe = "sk_live_" + ("abcdefgh" * 3)
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.py"), "w", encoding="utf-8") as f:
            f.write("aws=%s\ntok=%s\nsk=%s\n" % (aws, gh, stripe))
        os.makedirs(os.path.join(d, "clean"), exist_ok=True)
        with open(os.path.join(d, "clean", "ok.py"), "w", encoding="utf-8") as f:
            f.write("def add(a, b):\n    return a + b\nprint('hello world')\n")
        hits = scan_directory(d)
        names = {h["rule"] for h in hits if h["file"] == "bad.py"}
        clean_hits = [h for h in hits if h["file"].startswith("clean/")]
    ok = ({"AWS Access Key ID", "GitHub Token", "Stripe Secret Key"} <= names
          and not clean_hits)
    print("self-test: %s (bad.py rules=%d, clean hits=%d)" % (
        "PASS" if ok else "FAIL", len(names), len(clean_hits)))
    return ok


def run_self_test() -> bool:
    """对外公开的自检入口（release_gate 依赖此函数名）。"""
    return self_test()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a directory for leaked secrets.")
    ap.add_argument("directory", nargs="?", default=".", help="directory to scan")
    ap.add_argument("--format", choices=("table", "json"), default="table")
    ap.add_argument("--config", help="JSON file with custom rules")
    ap.add_argument("--self-test", action="store_true", help="run built-in self test")
    args = ap.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1

    rules = DEFAULT_RULES
    if args.config:
        try:
            rules = load_rules(args.config)
        except Exception as e:
            print("error: bad rules file: %s" % e, file=sys.stderr)
            return 2

    if not os.path.isdir(args.directory):
        print("error: not a directory: %s" % args.directory, file=sys.stderr)
        return 2

    results = scan_directory(args.directory, rules)
    if args.format == "json":
        print(json.dumps({"findings": results, "count": len(results)},
                         ensure_ascii=False, indent=2))
    else:
        _print_table(results)
    return 1 if results else 0


if __name__ == "__main__":
    sys.exit(main())
