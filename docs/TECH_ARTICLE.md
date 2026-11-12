# 发布前加一道双闸：两个零依赖 Python 脚本，管住密钥泄露和金融文案合规

每次发版前，团队最容易翻车的其实就两类事：

1. 有人把密钥、令牌、私钥顺手提交进了仓库。等 CI 跑完、镜像打好的时候，密钥已经进了 git 历史，清都清不干净。
2. 运营或产品写的推文、海报、投教文案里，不知不觉出现了「保本保收益」「老师带单」这类话术。金融行业的合规红线摆在那，一旦发出去就是事故。

这两类问题都很容易预防，难的是**每次都记得查**。与其靠人肉 review，不如让流水线在发布前自己拦一道。

下面这套工具就是干这个的：两个纯标准库、零依赖的 Python 脚本，一个查密钥，一个查金融文案合规，再用一个 `release-gate` 把它们串成一条命令。三个仓库的 GitHub Actions 都已启用并保持绿灯。

---

## 一、toksentry：别让密钥混进仓库

`toksentry` 干一件事——递归扫你的目录，把像密钥的东西揪出来。它用两套手段：

- **正则规则**：AWS Key、GitHub Token、Stripe Key、Google API Key、各种私钥 PEM、JWT 这些，都有固定形态，直接匹配。
- **香农熵**：拿不准的字符串（比如一段 40 位以上的随机字符），算一下信息熵；低于 4.5 的直接放过，落在 URL 片段里的长串也会跳过，避免把 README 里的赞助链接、commit sha 当成密钥。

用法简单到不需要配置：

```bash
# 扫整个仓库，命中就非零退出，直接卡 CI
python toksentry.py .

# 输出 JSON，方便接别的处理
python toksentry.py . --format json

# 跑内置自检（不扫任何文件，确认扫描器自己没坏）
python toksentry.py --self-test
```

自检会同时放一段独立随机串和一段嵌在 URL 里的同一串，要求只命中前者——这样以后改规则，误报抑制有没有退化一眼能看出来。测试 fixtures 在运行时拼接构造，源码里不留完整令牌字面量（否则会被服务端的密钥检测当成真凭证）。仓库里如果有测试样例、示例代码不想被扫，写个 `.toksentryignore`（gitignore 语法）排除掉就行。

---

## 二、fin-compliance：金融文案别踩红线

金融行业的营销话术有明文红线。监管层反复强调：不能承诺收益、不能暗示荐股、不能夸大、引流要留痕、AI 生成内容要显著标识。

`fin-compliance` 就是针对这些做的文本模式标注。它扫 `.md` / `.txt` / `.html` / `.py` 这类文本文件，按规则标出：

| 类别 | 严重级别 | 典型触发 |
|------|----------|----------|
| 收益承诺 | high | 保本保收益、无风险、稳赚 |
| 荐股暗示 | high / medium | 必涨、主力建仓、老师带单 |
| 夸大宣传 | medium | 最牛、第一、100% |
| 引流话术 | medium | 加微信、扫码进群、免费领 |
| AI 生成未标识 | low | 全文没有出现 AI 标识（监管建议显著标注） |

用法和 toksentry 对称：

```bash
# 扫内容目录，high 及以上即失败
python fin_compliance.py ./docs --fail-on high

# 只出报告、不拦截
python fin_compliance.py ./docs --fail-on none

# 内置自检
python fin_compliance.py --self-test
```

规则放在 `rules.json` 里，按监管口径增删即可，不用改代码。同样支持 `.fincomplianceignore` 排除目录。注意别把讲解规则的文档一起扫进去——文档里引用违规例句属于说明，不是待发布文案。

---

## 三、release-gate：一条命令跑双闸

两个工具各管一摊，但发布前你肯定想一次查全。`release-gate` 就是把它们组合起来：

```bash
# 同一个仓库，代码和内容都在里面
python release_gate.py /path/to/repo

# 代码和内容分开放
python release_gate.py --code-dir ./src --content-dir ./docs

# 合规问题 medium 及以上才拦（默认 high）
python release_gate.py /path/to/repo --fail-on medium

# 自检
python release_gate.py --self-test
```

输出长这样（节选）：

```
① 密钥/令牌泄露扫描 (toksentry)
未发现密钥泄露。

② 金融内容合规标注扫描 (fin-compliance)
  samples/violation.md:4 | high   | 收益承诺 | 年化 15%，保本保收益...
  samples/violation.md:3 | high   | 荐股     | 这只票主力马上建仓，必涨！

结论:
  密钥泄露 : PASS (0 处)
  内容合规 : FAIL (7 处，阈值 high)
  总判定   : BLOCK 发布
```

任何一闸不过，退出码就是 `1`，CI 直接红。全过才 `0`。

---

## 四、为什么非得是「零依赖、可离线」

这套工具刻意只用 Python 标准库，不引入任何第三方包。原因很实际：

- **能直接塞进 CI**。别人的 CI 镜像你动不了，少一个依赖就少一个装不上、版本冲突的坑。复制一个 `.py` 就能跑。
- **能进内网 / 信创环境**。金融、政企客户的打包机经常不允许联网装包，甚至跑的是国产操作系统。纯标准库 + 离线，刚好对口。
- **不外接任何服务**。扫描在本地完成，代码和文案不会传到某个 SaaS 上，合规上更说得过去。

这也是它和那些「云原生密钥扫描平台」的差别：平台按月收费、要联网、规则黑盒；这套东西你拿走就能用，规则你看得懂、改得了。代价也清楚——规则要自己跟着新令牌格式和监管口径维护，没有集中报表和 dashboard。它解决的是「发布前拦一道」，不是「全公司密钥治理」。

---

## 五、怎么接进你的流水线

GitHub Actions 里就是几行（在 `release_gate` 仓库根目录执行）：

```yaml
- name: 发布前双闸
  run: python release_gate.py --code-dir . --content-dir ./docs --fail-on high
```

`release_gate.py` 默认在同级目录找两个子扫描器；CI 里单独 checkout 时它们不存在，所以正式 workflow 会先把 `toksentry`、`fin-compliance` 拉到父目录，也可以用 `--toksentry` / `--fin-compliance` 显式指定路径。三个仓库的 `.github/workflows/*.yml` 都是可直接参考的现成例子。

GitLab CI、Jenkins、甚至 pre-commit hook 同理。建议的卡点位置：

- **pre-commit**：提交前本地先拦一遍，最快反馈；
- **PR 检查**：合并前再拦一遍，防止本地跳过的；
- **发布流水线**：打镜像 / 出包前最后一道，兜底。

密钥这一道建议「零容忍」（只要有就拦）；合规那一道可以按阶段放宽——内部评审阶段用 `high` 拦硬伤，对外发布前再上 `medium` 收紧话术。

---

## 收尾

三个项目都是 MIT、零依赖，仓库里自带自检和已启用的 GitHub Actions（状态徽章均为绿灯），clone 下来就能跑：

- https://github.com/highLuo/toksentry
- https://github.com/highLuo/fin-compliance
- https://github.com/highLuo/release_gate

如果这套东西帮你拦下过一次事故，欢迎在 GitHub 上点个 Sponsor——规则集要跟着新令牌格式和监管口径持续更新，赞助是它一直有人维护最直接的动力。

（注：这两个工具做的是文本模式风险标注，不构成法律意见，也不荐股、不碰任何账号与交易。正式合规以最新法规和持牌法务意见为准。）
