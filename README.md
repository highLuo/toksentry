# toksentry

[![Secret Scan](https://github.com/highLuo/toksentry/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/highLuo/toksentry/actions/workflows/secret-scan.yml)

A small secret scanner for code repositories.

I kept accidentally committing API keys, so I wrote this to catch them before they
leave my machine. It's a single Python file with **no third-party dependencies** —
just the standard library — so you can drop it into a CI job or run it locally
without installing anything.

What it looks for:
- AWS keys, GitHub / GitHub OAuth tokens, Slack tokens, Stripe keys, Google API keys
- Private keys (PEM / RSA / EC / OpenSSH / PGP)
- JWTs, and other high-entropy strings that usually mean a leaked secret

It combines regex rules with a Shannon-entropy check to keep false positives down.

## Install / run

```bash
pip install .
# or just run it as a script, no install needed
python toksentry.py <directory>
```

## Usage

```bash
# scan the current directory, human-readable table output
python toksentry.py .

# JSON output, easier to pipe into other tooling or a CI step
python toksentry.py ./src --format json

# bring your own rules
python toksentry.py . --config my_rules.json

# built-in self test, needs no external data
python toksentry.py --self-test
```

## Exit codes

| code | meaning |
|------|---------|
| 0    | nothing found (or self-test passed) |
| 1    | a secret was found (or self-test failed) |
| 2    | runtime error, e.g. a broken rules file |

Because it returns a non-zero code on a hit, it works as a CI gate — wire it into a
pre-commit hook or a pipeline step and it'll fail the build when something slips in.

## CI (GitHub Actions)

The workflow at `.github/workflows/secret-scan.yml` is live. On every push and
pull request it runs the self-test, then scans the whole repo; a single hit
fails the build. The badge above is this repo's real status, not a mockup.

To use it elsewhere, copy that one file — there is nothing to install. The
generic high-entropy rule has a noise filter (entropy threshold plus URL
suppression), so long links, repo paths and commit hashes don't trip it. That
matters in practice: the first version of this scanner flagged its own README.

Want the same gate locally before you commit? Drop it in a pre-commit hook:

```bash
# .git/hooks/pre-commit
python toksentry.py . --format json || {
  echo "Aborting commit: possible secret detected"; exit 1; }
```

## Ignoring known files

Some files legitimately contain fake tokens — test fixtures, docs, examples. Drop a
`.toksentryignore` (gitignore style) in the scanned directory to skip them. Both `/`
and `\` separators work, and a trailing slash marks a whole directory:

```text
# .toksentryignore
tests/
docs/examples.md
```

## Custom rules

`--config` takes a JSON array of rules:

```json
[{"name": "My Token", "pattern": "mytoken_[A-Za-z0-9]{20}"}]
```

If you don't pass `--config`, the built-in rule set is used.

## Sponsors

If this caught a leak in your CI before it shipped, consider supporting the project
through GitHub Sponsors. Contributions go toward broader default rules, fewer false
positives, and keeping the tool dependency-free. Sponsors get priority on issues and
access to private rule templates.

See [SPONSORS.md](https://github.com/highLuo/toksentry/blob/main/SPONSORS.md)
for the full tier list (Backer / Supporter / Team / Enterprise) and what each includes.
