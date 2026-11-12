#!/usr/bin/env python3
"""toksentry 基本单元测试：验证能检出样本密钥、且干净代码不误报。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toksentry import scan_directory, DEFAULT_RULES, shannon_entropy


class TestBasic(unittest.TestCase):
    def _write(self, d, name, content):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return p

    def test_detects_known_secrets(self):
        # Build fixtures at runtime. A literal that looks like a live
        # credential trips GitHub push protection and downstream scanners,
        # even though it is only a test value.
        aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        gh = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"[:36]
        stripe = "sk_live_" + "abcdefghijklmnopqrstuvwx"
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bad.py", "aws=%s\ntok=%s\nsk=%s\n" % (aws, gh, stripe))
            found = scan_directory(d, DEFAULT_RULES)
            names = {x["rule"] for x in found}
            self.assertIn("AWS Access Key ID", names)
            self.assertIn("GitHub Token", names)
            self.assertIn("Stripe Secret Key", names)

    def test_clean_code_no_false_positive(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "clean.py", (
                "def add(a, b):\n"
                "    return a + b\n"
                "print('hello world')\n"
            ))
            found = scan_directory(d, DEFAULT_RULES)
            self.assertEqual(len(found), 0)

    def test_entropy(self):
        self.assertAlmostEqual(shannon_entropy(""), 0.0)
        self.assertGreater(shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789"), 4.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
