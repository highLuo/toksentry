#!/usr/bin/env python3
"""toksentry - 代码仓库密钥/令牌泄露扫描器（纯标准库，零依赖）。

递归扫描目录，用正则规则 + 香农熵检测识别密钥/令牌泄露，
支持 JSON / 表格输出、自定义规则、CI 友好退出码、内置 self-test。
"""
import argparse
import fnmatch
import json
import math
import os
import re
import sys

# 内置默认规则（无需配置文件也可用）
DEFAULT_RULES = [
    {"name": "AWS Access Key ID", "pattern": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"},
    {"name": "GitHub Token", "pattern": r"ghp_[A-Za-z0-9]{36}"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9]{36}"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[A-Za-z0-9-]{10,}"},
    {"name": "Stripe Secret Key", "pattern": r"sk_live_[A-Za-z0-9]{24,}"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_\-]{35}"},
    {"name": "Private Key (PEM)", "pattern": r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"},
    {"name": "JWT", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"},
    # 兜底规则：只有足够"随机"才算疑似密钥，否则长 URL、commit sha 会刷屏
    {"name": "Generic High-Entropy", "pattern": r"[A-Za-z0-9+/]{40,}={0,2}",
     "min_entropy": 4.5},
]

# 二进制/体积过滤
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
_MAX_FILE_BYTES = 5 * 1024 * 1024


def _load_ignore(ignore_file):
    """读取 .toksentryignore（gitignore 风格），返回相对路径 glob 列表。"""
    patterns = []
    if not ignore_file or not os.path.exists(ignore_file):
        return patterns
    with open(ignore_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns


def _is_ignored(rel_path, patterns):
    if not patterns:
        return False
    rel_norm = rel_path.replace("\\", "/")
    name = os.path.basename(rel_path)
    for p in patterns:
        pp = p.strip().replace("\\", "/")
        if not pp:
            continue
        # 目录式忽略（结尾带 /）：忽略该目录下的所有文件
        if pp.endswith("/"):
            if rel_norm == pp.rstrip("/") or rel_norm.startswith(pp):
                return True
        # 整路径或文件名的 glob 匹配
        if fnmatch.fnmatch(rel_norm, pp) or fnmatch.fnmatch(name, pp):
            return True
    return False


def shannon_entropy(data: str) -> float:
    """计算字符串的香农熵（比特/字符）。"""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log(p, 2)
    return entropy


def _in_url(content: str, start: int) -> bool:
    """匹配位置是否落在同一个 URL 片段内（左侧无空白且包含 ://）。

    URL 路径、commit sha、仓库全名经常被兜底规则当成高熵串；真正的密钥
    一般不会紧跟在 :// 后面。只用于带 min_entropy 的兜底规则，精确规则不受影响。
    """
    left = content[max(0, start - 256):start]
    frag = re.split(r"\s", left)[-1]
    return "://" in frag


def load_rules(path: str):
    if not path or not os.path.exists(path):
        return list(DEFAULT_RULES)
    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    if not isinstance(rules, list):
        raise ValueError("规则文件必须是 JSON 数组")
    return rules


def _is_text(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        chunk.replace(b"\x00", b"")
        return b"\x00" not in chunk
    except Exception:
        return False


def scan_directory(directory: str, rules, ignore=None) -> list:
    """返回命中列表：每条 {file, rule, match, entropy}。"""
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            fp = os.path.join(root, name)
            rel = os.path.relpath(fp, directory)
            if _is_ignored(rel, ignore):
                continue
            try:
                if os.path.getsize(fp) > _MAX_FILE_BYTES or not _is_text(fp):
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            for rule in rules:
                try:
                    matches = re.finditer(rule["pattern"], content)
                except re.error:
                    continue
                min_ent = rule.get("min_entropy")
                for m in matches:
                    # group(0) 取完整匹配；含捕获组的规则（如 PEM）也返回整串
                    token = m.group(0)
                    entropy = shannon_entropy(token)
                    if min_ent is not None:
                        if entropy < min_ent or _in_url(content, m.start()):
                            continue
                    findings.append({
                        "file": os.path.relpath(fp, directory),
                        "rule": rule.get("name", "unknown"),
                        "match": token[:80],
                        "entropy": round(entropy, 3),
                    })
    return findings


def output_json(findings):
    print(json.dumps({"leaks": findings, "count": len(findings)}, indent=2, ensure_ascii=False))


def output_table(findings):
    if not findings:
        print("未发现密钥泄露。")
        return
    print(f"{'FILE':<40} {'RULE':<28} {'ENTROPY':<9} MATCH")
    print("-" * 100)
    for f in findings:
        print(f"{f['file'][:38]:<40} {f['rule'][:26]:<28} {f['entropy']:<9} {f['match'][:30]}")


def run_self_test() -> bool:
    """内置自检：用临时样本验证检测能力。返回是否通过。"""
    import tempfile
    # 全部样本在运行时拼接构造，避免源码里出现完整匹配字面量被自身扫描器误报。
    # 拆成短段拼接：源码里不出现 40+ 连续字符串，避免整仓扫描时命中自己
    alphabet = ("abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789" "+/")
    blob = "".join(alphabet[(i * 13 + 7) % len(alphabet)] for i in range(48))
    sample = (
        "aws_key=" + "AKIA" + "IOSFODNN7EXAMPLE" + "\n"
        "token=" + "ghp_" + ("a" * 36) + "\n"
        "secret=" + "sk_live_" + ("b" * 24) + "\n"
        "blob=" + blob + "\n"
        "docs=" + "https://example.com/files/" + blob + "\n"
        "safe_line = 'this is just normal code'\n"
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sample.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(sample)
        found = scan_directory(d, DEFAULT_RULES)
    names = {x["rule"] for x in found}
    generic = [x for x in found if x["rule"] == "Generic High-Entropy"]
    # 精确规则要全中；兜底规则要抓住独立随机串，且不能把 URL 里的同一串误报
    expected = {"AWS Access Key ID", "GitHub Token", "Stripe Secret Key",
                "Generic High-Entropy"}
    passed = expected.issubset(names) and len(generic) == 1
    print(f"[self-test] 命中 {len(found)} 条，规则命中: {sorted(names)}")
    print("[self-test] URL 误报抑制: %s" % ("PASS" if len(generic) == 1 else "FAIL"))
    print("[self-test] " + ("PASS" if passed else "FAIL (检出能力或误报抑制不符合预期)"))
    return passed


def main(argv=None):
    parser = argparse.ArgumentParser(description="toksentry - 代码仓库密钥/令牌泄露扫描器")
    parser.add_argument("directory", nargs="?", help="要扫描的目录")
    parser.add_argument("--config", default=None, help="自定义规则 JSON 路径（默认使用内置规则）")
    parser.add_argument("--ignore-file", default=None, help="忽略清单路径（默认读取 <目录>/.toksentryignore）")
    parser.add_argument("--format", choices=["json", "table"], default="table", help="输出格式")
    parser.add_argument("--self-test", action="store_true", help="运行内置自检并退出")
    args = parser.parse_args(argv)

    if args.self_test:
        return 0 if run_self_test() else 1

    if not args.directory:
        parser.error("必须提供要扫描的 directory，或使用 --self-test")

    try:
        rules = load_rules(args.config)
    except Exception as e:
        print(f"[错误] 加载规则失败: {e}", file=sys.stderr)
        return 2

    ignore_file = args.ignore_file or os.path.join(args.directory, ".toksentryignore")
    ignore = _load_ignore(ignore_file)
    if ignore:
        print(f"[忽略] 已加载忽略清单: {ignore_file}（{len(ignore)} 条）", file=sys.stderr)

    findings = scan_directory(args.directory, rules, ignore=ignore)
    if args.format == "json":
        output_json(findings)
    else:
        output_table(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
