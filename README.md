# 网安 + AI 前沿每日简报

一个每天自动抓取、整理并输出结构化简报的智能体流水线，方向覆盖 **arXiv `cs.CR`（安全）与 AI 安全交叉**，外加 **CVE 在野利用、新增高危漏洞、行业动态**。

- 产物样例：`site/2026-11-25.html`（同目录有 `.md` 版本，可直接贴进 Word）
- 数据留档：`data/2026-11-25.json`

---

## 一、为什么这样分层

简报类项目最大的坑是「LLM 一本正经地编造标题、作者和链接」。本项目把这件事从架构上切断：

```
 采集层（脚本，无 LLM）        判断层（智能体 / LLM）        排版层
┌──────────────────────┐   ┌───────────────────────┐   ┌──────────────┐
│ arXiv API   cs.CR    │   │ 一句话结论 tldr        │   │ HTML（报纸风）│
│ CISA KEV    在野利用  │──▶│ 为什么值得看 why       │──▶│ Markdown     │
│ NVD API     高危 CVE  │   │ 今日速览 / 趋势观察    │   │ 首页归档      │
│ RSS         行业动态  │   │ 信息密度自评           │   │ Pages        │
└──────────────────────┘   └───────────────────────┘   └──────────────┘
        data/DATE.json          data/DATE.summaries.json      site/
```

**铁律：标题、作者、CVE 编号、CVSS 评分、链接一律来自官方接口，LLM 只写摘要与判断。**
判断层即使空着，简报也能渲染（用摘要原文兜底），只是质量下降——这让流水线不会因为 API 挂了就断。

---

## 二、跑起来

```bash
# 1. 只抓数据（约 30 秒，全程无 LLM、不需要 key）
python brief.py fetch --date 2026-11-25

# 2. 写判断层（三种方式，任选）
python brief.py summarize --date 2026-11-25      # A. 有 API key 时自动写
#   B. 交给智能体：手工/让 agent 写 data/DATE.summaries.json
#   C. 跳过：渲染时用摘要原文兜底

# 3. 出页面
python brief.py render --date 2026-11-25

# 一条龙
python brief.py all --date 2026-11-25
```

环境变量（都可选）：

| 变量 | 作用 | 默认 |
|---|---|---|
| `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` | 判断层调用凭据 | 不设则跳过判断层 |
| `BRIEF_API_BASE` | OpenAI 兼容接口地址 | `https://api.deepseek.com` |
| `BRIEF_MODEL` | 模型名 | `deepseek-chat` |

依赖：**仅 Python 3.9+ 标准库**，零第三方包。

---

## 三、三种部署方式

### 方式 1：GitHub Actions（推荐，最容易交作业）

1. 把本目录推到自己的 GitHub 仓库；
2. 仓库 `Settings → Pages → Source` 选 `GitHub Actions`；
3. 需要判断层就在 `Settings → Secrets and variables → Actions` 加 `DEEPSEEK_API_KEY`；
4. `.github/workflows/daily.yml` 每天 UTC 00:00（北京 08:00）自动跑，产物发布到 `https://<用户名>.github.io/<仓库名>/`。

这样三样提交物天然齐全：Actions 运行记录（截图）、Pages 链接（产物链接）、每天的 HTML 与 `data/*.json`（简报样例与可复现数据）。

### 方式 2：智能体定时任务（最贴题）

在 DeepSeek Harness 里建一个每日定时任务，提示词让它依次执行 `fetch` → 读 `data/DATE.json` → 写 `summaries.json` → `render`。此时「判断」由智能体本人完成，不依赖外部 API key。

### 方式 3：本机 cron / 计划任务

```bash
0 8 * * * cd /path/to/security-brief && python3 brief.py all
```

---

## 四、配置（`config.json`）

| 字段 | 说明 |
|---|---|
| `arxiv.cr_max_results` | cs.CR 抓取上限（默认 80） |
| `arxiv.ai_max_results` | cs.AI/CL/LG 抓取上限，仅保留命中安全关键词的（默认 80） |
| `arxiv.top_n` | 最终入选篇数（默认 8） |
| `arxiv.security_keywords` | 交叉方向关键词表 |
| `kev.days` | 在野利用清单回溯天数 |
| `nvd.hours` / `nvd.severity` | 新增漏洞时间窗与严重级别 |
| `rss[]` | 资讯源列表，`limit` 控制每源条数 |

换方向只改这里：把 `cs.CR` 换成你的学科分类、把关键词换掉即可。

---

## 五、已验证与已知限制

**已验证（2026-11-25 实测）**
- 四个信息源全部可用：arXiv、CISA KEV、NVD、The Hacker News / 安全客 / Krebs RSS
- 安全客的 RSS 不提供 `<link>`，URL 在 `<guid>` 里，代码已适配
- 同一厂商的批量公告（如某产品同日 4 个同类 CVE）描述一字不差，已按描述前缀归并并标注条数

**已排除的源**
- BleepingComputer RSS：403
- FreeBuf RSS：返回阿里云 WAF 页面
- GitHub Advisory Atom：406（需鉴权头）

**限制**
1. **只覆盖预印本**：arXiv 未经同行评审，USENIX Security / CCS / S&P 等顶会正式论文不在其中；
2. **不做资产比对**：能回答「世界上出了什么事」，不能回答「我的机器中没中」——后者要接 OSV-Scanner / Dependabot；
3. **关键词筛选是启发式的**：只负责把上百篇压到十几篇，真正的取舍在判断层；
4. **NVD 无 key 时有限流**：每分钟 5 次，本流水线每天只查一次，不受影响；
5. **判断层的质量取决于模型**，且无法自动验证——所以简报里保留了 `selfcheck` 自评字段，供人快速判断可信度。

---

## 六、目录

```
security-brief/
├── brief.py                    # 全部逻辑：fetch / summarize / render
├── config.json                 # 信息源与筛选配置
├── data/
│   ├── 2026-11-25.json         # 原始数据（事实层）
│   └── 2026-11-25.summaries.json  # 判断层
├── site/
│   ├── index.html              # 归档首页
│   ├── 2026-11-25.html         # 当日简报
│   └── 2026-11-25.md
└── .github/workflows/daily.yml # 每日自动运行 + Pages 发布
```
