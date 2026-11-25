# 网安与 AI 前沿每日简报

一个每天自动抓取、整理并输出结构化简报的流水线。学术侧覆盖 arXiv `cs.CR`（安全）、计算机科学七个子方向（`cs.DC / SE / DB / NI / OS / PL / HC`）与 AI 安全交叉；工程侧覆盖 CISA 在野利用清单、NVD 新增高危漏洞与安全资讯。

- 产物样例：`site/2026-11-25.html`（同目录有 `.md` 版本）
- 数据留档：`data/2026-11-25.json`

---

## 一、架构与分工

简报类项目的主要风险是：语言模型在生成文字时，会顺带编造标题、作者和链接。本项目在架构上把"取数"和"判断"分开，使这类错误无法进入产物。

```
 采集层（脚本，无 LLM）        判断层（智能体 / LLM）        排版层
┌───────────────────┐   ┌─────────────────────┐   ┌────────────────┐
│ arXiv   cs.CR     │   │ 一句话结论 tldr     │   │ HTML（报纸风） │
│ arXiv   CS 七方向 │   │ 为什么值得看 why    │   │ Markdown       │
│ CISA KEV 在野利用 │──▶│ 今日速览 / 趋势观察 │──▶│ 归档首页       │
│ NVD     高危 CVE  │   │ 信息密度自评        │   │ GitHub Pages   │
│ RSS     行业动态  │   │                     │   │                │
└───────────────────┘   └─────────────────────┘   └────────────────┘
        data/DATE.json          data/DATE.summaries.json      site/
```

约束：标题、作者、CVE 编号、CVSS 评分、链接一律取自官方接口，语言模型只负责撰写摘要与判断，不生成任何事实字段。

判断层留空时，简报仍可渲染（回退为论文摘要原文），只是内容质量下降。因此数据源或模型接口临时不可用时，流水线不会中断。

---

## 二、使用方法

```bash
# 1. 抓取数据（约 30 秒，不调用 LLM，不需要密钥）
python brief.py fetch --date 2026-11-25

# 2. 生成判断层（三种方式任选）
python brief.py summarize --date 2026-11-25      # A. 配置了 API 密钥时自动生成
#   B. 由智能体撰写 data/DATE.summaries.json
#   C. 跳过，渲染时回退为摘要原文

# 3. 渲染页面
python brief.py render --date 2026-11-25

# 依次执行以上三步
python brief.py all --date 2026-11-25
```

环境变量均为可选：

| 变量 | 作用 | 默认 |
|---|---|---|
| `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` | 判断层调用凭据 | 未设置则跳过判断层 |
| `BRIEF_API_BASE` | OpenAI 兼容接口地址 | `https://api.deepseek.com` |
| `BRIEF_MODEL` | 模型名 | `deepseek-chat` |

依赖：Python 3.9+ 标准库，无第三方包。

---

## 三、部署方式

### 方式 1：GitHub Actions

1. 将本目录推送到自己的 GitHub 仓库；
2. 仓库 `Settings → Pages → Source` 选择 `GitHub Actions`（首次也可由 workflow 中的 `configure-pages` 自动启用）；
3. 如需判断层，在 `Settings → Secrets and variables → Actions` 中添加 `DEEPSEEK_API_KEY`；
4. `.github/workflows/daily.yml` 每天 UTC 00:00（北京时间 08:00）触发，产物发布到 `https://<用户名>.github.io/<仓库名>/`。

运行记录、Pages 地址与每日的 HTML / JSON 均由仓库自身留存，可逐次回溯。

> 说明：GitHub 会在仓库连续 60 天无提交活动后暂停定时工作流。本流水线每天回写 `data/` 与 `site/`，正常运行时不会触发该限制。

### 方式 2：智能体定时任务

在 DeepSeek Harness 中创建每日定时任务，提示词依次执行 `fetch` → 读取 `data/DATE.json` → 撰写 `summaries.json` → `render`。此时判断层由智能体本人完成，不依赖外部 API 密钥。

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
| `arxiv.top_n` | 网络安全方向最终入选篇数（默认 8） |
| `arxiv.security_keywords` | 交叉方向关键词表 |
| `cs.categories` | 计算机科学子方向列表（默认 DC/SE/DB/NI/OS/PL/HC） |
| `cs.per_category_take` | 每个子方向保留的篇数（默认 1，用于保证覆盖面） |
| `cs.top_n` | 计算机科学方向最终入选篇数（默认 7） |
| `kev.days` / `kev.max` | 在野利用清单回溯天数与条数上限 |
| `nvd.hours` / `nvd.severity` | 新增漏洞时间窗与严重级别 |
| `rss[]` | 资讯源列表，`limit` 控制每源条数 |

更换研究方向只需修改本文件：替换 arXiv 分类与关键词即可，代码无需改动。

---

## 五、可用性实测与已知限制

**实测可用（2026-11-25）**

- arXiv API、CISA KEV、NVD、The Hacker News / 安全客 / Krebs RSS 均正常；
- 安全客的 RSS 不提供 `<link>` 节点，URL 位于 `<guid>`，代码已适配；
- 同一厂商的批量公告（如某产品同日 4 个同类 CVE）描述完全一致，已按描述前缀归并并标注条数。

**已排除的信息源**

- BleepingComputer RSS：HTTP 403
- FreeBuf RSS：返回阿里云 WAF 页面
- GitHub Advisory Atom：HTTP 406（需要鉴权头）

**限制**

1. **仅覆盖预印本**：arXiv 未经同行评审，USENIX Security / CCS / S&P 等会议正式论文不在其中；
2. **不做资产比对**：能说明外部世界发生了什么，不能判断本机是否受影响，后者需接入 OSV-Scanner 或 Dependabot；
3. **关键词筛选为启发式**：只用于把上百篇压缩到十余篇，最终取舍由判断层完成；
4. **NVD 未配置密钥时限流**：每分钟 5 次，本流水线每天查询一次，不受影响；
5. **判断层质量依赖模型且无法自动验证**：简报因此保留 `selfcheck` 自评字段，供读者判断可信度。

---

## 六、目录结构

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
