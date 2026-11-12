# Sponsor these tools

## Why sponsor

These are small, practical command-line tools I built because I kept running into
the same two problems before every release: a secret gets committed by accident,
or a piece of marketing copy drifts into "guaranteed returns" territory without
anyone noticing. Both are easy to prevent and annoying to clean up after.

`toksentry` and `fin-compliance` are zero-dependency, standard-library-only
Python. They run offline, drop into any CI job or pre-commit hook, and don't
phone home. If your team ships software — especially anything finance-adjacent —
they probably save you a incident or two a year.

Sponsorship pays for the time spent keeping the rule sets current (new token
formats show up constantly) and for building the combined `release-gate` wrapper.
It is also the most direct way to say "yes, this is worth maintaining."

## Tiers

| Tier | Amount | What you get |
|------|--------|--------------|
| **Backer** | $5 / month | Name in the README supporters list. My thanks, and a steady reason to keep the rules fresh. |
| **Supporter** | $20 / month | Everything above, plus priority on bug reports and rule requests — your false positives and missed patterns get looked at first. |
| **Team** | $99 / month | Everything above for your whole team, plus a short yearly note on what changed in the rule sets and how it affects you. Good fit for a small security/compliance group. |
| **Enterprise** | custom | Everything above, plus private rule sets tuned to your internal policies, and a review of your CI wiring if you want one. Talk to me about scope and pricing. |

The tiers map to GitHub Sponsors amounts, so you can set them up in one click
from the repository's Sponsors tab. Enterprise is "custom" because every
company's compliance surface is different — reach out and we'll scope it.

## What sponsorship does not buy

No influence over what the scanners detect. A rule goes in because it reflects a
real, documented requirement (a framework control, a regulator's guidance, a
token format in the wild), not because a sponsor asked. The tools stay MIT and
self-contained.

---

## 中文对照（给用户参考，不直接放 GitHub）

**为什么要赞助**
这两个小工具解决的是每次发布前最容易踩的两个坑：密钥被不小心提交、营销文案不知不觉写成"保本保收益"。
`toksentry` 和 `fin-compliance` 都是零依赖、纯标准库的 Python，可离线运行，能直接塞进 CI 或 pre-commit，不会外联。
如果你的团队要发版——尤其是涉及金融内容的——它们一年大概能帮你少出一两起事故。

**档位**
- 支持者 Backer：$5/月，列入 README 致谢名单。
- 赞助者 Supporter：$20/月，优先处理你报的误报/漏报和规则请求。
- 团队 Team：$99/月，团队共用，年终附一份规则变更说明；适合小的安全/合规组。
- 企业 Enterprise：按需定制，含私有规则集 + CI 接入复盘；具体范围与价格另谈。

**赞助不买什么**：不影响扫描器的检测逻辑。规则只基于真实存在的依据（框架条款、监管指引、实际出现的令牌格式）加入，工具保持 MIT、自包含。
