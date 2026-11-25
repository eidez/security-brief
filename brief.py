#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网安 + AI 前沿信息每日简报流水线
================================

三个子命令，职责分离：

    python brief.py fetch      抓取并落盘 data/YYYY-MM-DD.json（纯数据，不含任何判断）
    python brief.py render     读取 JSON + 可选的 summaries.json，生成 site/ 下的 HTML 与 Markdown
    python brief.py all        fetch + render

设计原则（这是本项目的核心）：
    1. 抓取层只负责"把事实搬下来"，标题、作者、链接、CVSS 全部来自官方 API，**不允许 LLM 生成**；
    2. 判断层（摘要、为什么重要、趋势）由智能体或 LLM 写，落到 summaries.json，与数据解耦；
    3. 任何一层都可以单独替换，层级之间只通过 JSON 交接。
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SITE = ROOT / "site"
UA = {"User-Agent": "Mozilla/5.0 (compatible; sec-ai-brief/1.0; +academic project)"}

ATOM = "{http://www.w3.org/2005/Atom}"


# --------------------------------------------------------------------------
# 基础设施
# --------------------------------------------------------------------------
def get(url: str, timeout: int = 30, retries: int = 3) -> bytes:
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"GET failed: {url} -> {last}")


def text_of(node, path: str, default: str = "") -> str:
    el = node.find(path)
    if el is None or el.text is None:
        return default
    return re.sub(r"\s+", " ", el.text).strip()


def load_config() -> dict:
    return json.loads((ROOT / "config.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# 1. 学术前沿：arXiv
# --------------------------------------------------------------------------
def arxiv_query(search_query: str, max_results: int) -> list[dict]:
    q = urllib.parse.quote(search_query)
    url = (
        "http://export.arxiv.org/api/query?"
        f"search_query={q}&start=0&max_results={max_results}"
        "&sortBy=submittedDate&sortOrder=descending"
    )
    raw = get(url, timeout=60)
    root = ET.fromstring(raw)
    out = []
    for entry in root.findall(ATOM + "entry"):
        link = ""
        for l in entry.findall(ATOM + "link"):
            if l.get("rel") == "alternate":
                link = l.get("href", "")
                break
        if not link:
            continue
        out.append(
            {
                "id": text_of(entry, ATOM + "id").rsplit("/", 1)[-1],
                "title": text_of(entry, ATOM + "title"),
                "abstract": text_of(entry, ATOM + "summary"),
                "published": text_of(entry, ATOM + "published")[:10],
                "authors": [
                    text_of(a, ATOM + "name") for a in entry.findall(ATOM + "author")
                ][:6],
                "categories": [
                    c.get("term", "") for c in entry.findall(ATOM + "category")
                ],
                "url": link,
                "source": "arXiv",
            }
        )
    return out


def score_paper(p: dict, keywords: list[str]) -> int:
    """关键词打分。标题权重 3，摘要权重 1；cs.CR 额外加分。

    注意：这是**启发式筛选**，不是语义判断。它的作用只是把候选从上百篇压到十几篇，
    真正的"该不该读"由智能体在 summaries 阶段判断。
    """
    title = p["title"].lower()
    abstract = p["abstract"].lower()
    score = 0
    for kw in keywords:
        k = kw.lower()
        if k in title:
            score += 3
        if k in abstract:
            score += 1
    if "cs.CR" in p.get("categories", []):
        score += 4
    return score


def fetch_arxiv(cfg: dict) -> list[dict]:
    acfg = cfg["arxiv"]
    kws = acfg["security_keywords"]
    pool: dict[str, dict] = {}

    # 查询一：安全主战场，全量取
    for p in arxiv_query("cat:cs.CR", acfg["cr_max_results"]):
        pool[p["id"]] = p

    # 查询二：AI 侧的交叉内容，靠关键词筛
    for p in arxiv_query("cat:cs.AI OR cat:cs.CL OR cat:cs.LG", acfg["ai_max_results"]):
        if p["id"] in pool:
            continue
        if any(k.lower() in (p["title"] + " " + p["abstract"]).lower() for k in kws):
            pool[p["id"]] = p

    for p in pool.values():
        p["score"] = score_paper(p, kws)

    ranked = sorted(pool.values(), key=lambda x: (-x["score"], x["published"]), reverse=False)
    return ranked[: acfg["top_n"]]


# --------------------------------------------------------------------------
# 2. 在野利用：CISA KEV
# --------------------------------------------------------------------------
def fetch_kev(cfg: dict) -> list[dict]:
    days = cfg["kev"]["days"]
    since = dt.date.today() - dt.timedelta(days=days)
    data = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    items = []
    for v in data.get("vulnerabilities", []):
        try:
            added = dt.date.fromisoformat(v["dateAdded"])
        except Exception:  # noqa: BLE001
            continue
        if added < since:
            continue
        items.append(
            {
                "cve": v.get("cveID", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "added": v.get("dateAdded", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "desc": v.get("shortDescription", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID','')}",
                "source": "CISA KEV",
            }
        )
    items.sort(key=lambda x: x["added"], reverse=True)
    return items[: cfg["kev"]["max"]]


# --------------------------------------------------------------------------
# 3. 新增高危：NVD
# --------------------------------------------------------------------------
def fetch_nvd(cfg: dict) -> list[dict]:
    ncfg = cfg["nvd"]
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=ncfg["hours"])
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={urllib.parse.quote(start.strftime(fmt))}"
        f"&pubEndDate={urllib.parse.quote(end.strftime(fmt))}"
        f"&cvssV3Severity={ncfg['severity']}"
        f"&resultsPerPage={ncfg['max']}"
    )
    try:
        data = json.loads(get(url, timeout=60))
    except Exception as e:  # noqa: BLE001
        print(f"  ! NVD 抓取失败（不致命）：{e}", file=sys.stderr)
        return []

    items = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score = ""
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore", "")
                break
        items.append(
            {
                "cve": c.get("id", ""),
                "score": score,
                "published": c.get("published", "")[:10],
                "desc": re.sub(r"\s+", " ", desc)[:400],
                "url": f"https://nvd.nist.gov/vuln/detail/{c.get('id','')}",
                "source": "NVD",
            }
        )
    # 同一厂商的批量公告（如某产品同日 4 个同类 CVE）描述往往一字不差，
    # 简报里应归并成一条并标注条数，而不是刷四行。
    order, count = [], {}
    for it in items:
        key = it["desc"][:100].lower()
        if key not in count:
            count[key] = 0
            order.append(it)
        count[key] += 1
    for it in order:
        it["similar"] = count[it["desc"][:100].lower()]
    return order


# --------------------------------------------------------------------------
# 4. 行业动态：RSS
# --------------------------------------------------------------------------
def fetch_rss(cfg: dict) -> list[dict]:
    out, seen = [], set()
    for feed in cfg["rss"]:
        try:
            raw = get(feed["url"], timeout=25)
            root = ET.fromstring(raw)
        except Exception as e:  # noqa: BLE001
            print(f"  ! 跳过 {feed['name']}：{e}", file=sys.stderr)
            continue
        entries = root.findall(".//item") or root.findall(".//" + ATOM + "entry")
        for e in entries[: feed.get("limit", 5)]:
            title = text_of(e, "title") or text_of(e, ATOM + "title")
            link = text_of(e, "link")
            if not link:
                for l in e.findall(ATOM + "link"):
                    if l.get("rel") in (None, "alternate"):
                        link = l.get("href", "")
                        break
            if not link:
                # 部分中文源（如安全客）不提供 <link>，URL 放在 <guid> 里
                guid = text_of(e, "guid")
                if guid.startswith("http"):
                    link = guid
            if not title or not link:
                continue
            key = re.sub(r"\W+", "", title.lower())[:40]
            if key in seen:
                continue
            seen.add(key)
            raw_date = text_of(e, "pubDate") or text_of(e, ATOM + "updated") or text_of(e, ATOM + "published")
            out.append(
                {
                    "title": title,
                    "url": link,
                    "date": raw_date[:25],
                    "feed": feed["name"],
                    "lang": feed.get("lang", "en"),
                    "source": "RSS",
                }
            )
    return out


# --------------------------------------------------------------------------
# fetch 主流程
# --------------------------------------------------------------------------
def cmd_fetch(date: str) -> None:
    cfg = load_config()
    DATA.mkdir(exist_ok=True)
    print(f"[1/4] arXiv（{'/'.join(cfg['arxiv']['categories'])}）…")
    papers = fetch_arxiv(cfg)
    print(f"      {len(papers)} 篇入选")
    print("[2/4] CISA KEV 在野利用清单…")
    kev = fetch_kev(cfg)
    print(f"      {len(kev)} 条")
    print("[3/4] NVD 新增高危 CVE…")
    nvd = fetch_nvd(cfg)
    print(f"      {len(nvd)} 条")
    print("[4/4] RSS 安全资讯…")
    news = fetch_rss(cfg)
    print(f"      {len(news)} 条")

    payload = {
        "date": date,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "papers": papers,
        "kev": kev,
        "nvd": nvd,
        "news": news,
    }
    out = DATA / f"{date}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n已写入 {out}")
    print(f"下一步：补写 {DATA / (date + '.summaries.json')}，然后 python brief.py render --date {date}")


# --------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------
CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1f;--muted:#6b6b70;--line:#e2ded5;--accent:#8a1c1c;--card:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font-family:"Georgia","Songti SC","SimSun",serif;line-height:1.75}
.wrap{max-width:860px;margin:0 auto;padding:56px 28px 96px}
.masthead{border-bottom:3px double var(--line);padding-bottom:18px;margin-bottom:28px}
.kicker{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;font-size:12px;
        letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:34px;margin:10px 0 8px;line-height:1.25}
.meta{font-family:system-ui,sans-serif;font-size:13px;color:var(--muted)}
h2{font-size:19px;margin:44px 0 6px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h2 .num{color:var(--accent);margin-right:8px;font-family:system-ui,sans-serif}
.lead{font-size:15px;color:#333;margin:6px 0 18px}
.item{margin:0 0 22px;padding:0 0 18px;border-bottom:1px dotted var(--line)}
.item:last-child{border-bottom:none}
.item h3{font-size:16.5px;margin:0 0 4px;line-height:1.5;font-weight:700}
.item h3 a{color:var(--fg);text-decoration:none;border-bottom:1px solid var(--accent)}
.byline{font-family:system-ui,sans-serif;font-size:12px;color:var(--muted);margin:0 0 8px}
.tldr{font-size:14.5px;margin:6px 0}
.why{font-size:14px;color:#3a3a3c;background:var(--card);border-left:3px solid var(--accent);
     padding:9px 13px;margin:8px 0}
.why b{font-weight:700}
.tag{display:inline-block;font-family:system-ui,sans-serif;font-size:11px;letter-spacing:.04em;
     background:#f0ece3;color:#5a5348;border-radius:3px;padding:1px 7px;margin-right:6px}
.cve{font-family:ui-monospace,Consolas,monospace;font-size:13px;white-space:nowrap}
td.date{white-space:nowrap;font-family:system-ui,sans-serif;font-size:12.5px;color:#555}
table{width:100%;border-collapse:collapse;font-family:system-ui,sans-serif;font-size:13px;margin:10px 0 18px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:12px;letter-spacing:.05em}
.score{font-family:system-ui,sans-serif;font-size:13px;background:var(--card);
       border:1px solid var(--line);padding:12px 16px;margin:18px 0;color:#444}
ul.trends{margin:8px 0 0 0;padding-left:20px}
ul.trends li{margin-bottom:8px;font-size:14.5px}
footer{margin-top:56px;padding-top:16px;border-top:1px solid var(--line);
       font-family:system-ui,sans-serif;font-size:12px;color:var(--muted)}
a{color:var(--accent)}
"""


def esc(s) -> str:
    return html.escape("" if s is None else str(s))


def render_html(payload: dict, summ: dict, archive: list[str]) -> str:
    d = payload["date"]
    papers, kev, nvd, news = payload["papers"], payload["kev"], payload["nvd"], payload["news"]
    ps = summ.get("papers", {})

    parts = [f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>网安与 AI 前沿简报 · {d}</title><style>{CSS}</style></head><body><div class="wrap">
<div class="masthead">
  <div class="kicker">Security &amp; AI Frontier Daily</div>
  <h1>网安与 AI 前沿简报</h1>
  <div class="meta">{d} ｜ 网络空间安全 · AI 安全交叉 ｜ 生成于 {esc(payload['generated_at'][:16].replace('T',' '))}</div>
</div>"""]

    # 概览
    overview = summ.get("overview") or []
    if overview:
        parts.append('<h2><span class="num">01</span>今日速览</h2>')
        parts.append('<ul class="trends">' + "".join(f"<li>{esc(x)}</li>" for x in overview) + "</ul>")

    # 学术前沿
    parts.append('<h2><span class="num">02</span>学术前沿</h2>')
    parts.append('<p class="lead">arXiv <code>cs.CR</code> 与 AI 安全交叉方向，按关键词相关度排序后人工/智能体复筛。</p>')
    for p in papers:
        s = ps.get(p["id"], {})
        tldr = s.get("tldr") or (p["abstract"][:160] + "…")
        why = s.get("why") or ""
        tags = "".join(f'<span class="tag">{esc(c)}</span>' for c in p.get("categories", [])[:3])
        authors = ", ".join(p.get("authors", [])[:3])
        if len(p.get("authors", [])) > 3:
            authors += " 等"
        parts.append(f"""<div class="item">
  <h3><a href="{esc(p['url'])}">{esc(p['title'])}</a></h3>
  <p class="byline">{tags}{esc(authors)} ｜ {esc(p['published'])} ｜ arXiv:{esc(p['id'])}</p>
  <p class="tldr">{esc(tldr)}</p>
  {f'<div class="why"><b>为什么值得看：</b>{esc(why)}</div>' if why else ''}
</div>""")

    # 在野利用
    if kev:
        parts.append('<h2><span class="num">03</span>在野利用（CISA KEV）</h2>')
        parts.append('<p class="lead">已被确认在真实攻击中使用过的漏洞。这是"今晚就动手"优先级最高的信号。</p>')
        parts.append("<table><tr><th>CVE</th><th>厂商 / 产品</th><th>名称</th><th>入库</th><th>勒索利用</th></tr>")
        for k in kev:
            parts.append(
                f'<tr><td class="cve"><a href="{esc(k["url"])}">{esc(k["cve"])}</a></td>'
                f'<td>{esc(k["vendor"])} / {esc(k["product"])}</td><td>{esc(k["name"])}</td>'
                f'<td class="date">{esc(k["added"])}</td><td>{esc(k["ransomware"])}</td></tr>'
            )
        parts.append("</table>")

    # 高危新增
    if nvd:
        parts.append('<h2><span class="num">04</span>新增高危漏洞（NVD）</h2>')
        parts.append('<p class="lead">过去 24 小时内公开的 Critical 级漏洞。</p>')
        parts.append("<table><tr><th>CVE</th><th>CVSS</th><th>摘要</th></tr>")
        for v in nvd:
            desc = v["desc"]
            short = desc[:180].rsplit(" ", 1)[0] + ("…" if len(desc) > 180 else "")
            extra = (
                f' <b style="white-space:nowrap">（同日同类 {v["similar"]} 条）</b>'
                if v.get("similar", 1) > 1
                else ""
            )
            parts.append(
                f'<tr><td class="cve"><a href="{esc(v["url"])}">{esc(v["cve"])}</a></td>'
                f'<td>{esc(str(v["score"]))}</td><td>{esc(short)}{extra}</td></tr>'
            )
        parts.append("</table>")

    # 行业动态
    if news:
        parts.append('<h2><span class="num">05</span>行业动态</h2>')
        parts.append("<table><tr><th>标题</th><th>来源</th></tr>")
        for n in news:
            parts.append(
                f'<tr><td><a href="{esc(n["url"])}">{esc(n["title"])}</a></td>'
                f'<td>{esc(n["feed"])}</td></tr>'
            )
        parts.append("</table>")

    # 趋势
    trends = summ.get("trends") or []
    if trends:
        parts.append('<h2><span class="num">06</span>趋势观察</h2>')
        parts.append('<p class="lead">跨条目的二次提炼：今天这一批放在一起说明了什么。</p>')
        parts.append('<ul class="trends">' + "".join(f"<li>{esc(t)}</li>" for t in trends) + "</ul>")

    # 自评
    sc = summ.get("selfcheck")
    if sc:
        parts.append(f'<div class="score"><b>信息密度自评：{esc(sc.get("score",""))}/10</b> —— {esc(sc.get("reason",""))}</div>')

    # 页脚
    arch = "".join(f'<a href="{esc(a)}">{esc(a.replace(".html",""))}</a> · ' for a in archive[-6:])
    parts.append(f"""<footer>
<p>本简报由「抓取脚本 + 智能体」生成：标题、作者、CVE 编号、CVSS 评分全部来自 arXiv / NIST / CISA 官方接口，
LLM 仅负责撰写摘要与判断，不生成事实字段。</p>
<p>历史归档：{arch or '（暂无）'} ｜ <a href="index.html">返回首页</a></p>
</footer></div></body></html>""")
    return "\n".join(parts)


def render_md(payload: dict, summ: dict) -> str:
    d = payload["date"]
    ps = summ.get("papers", {})
    L = [f"# 网安与 AI 前沿简报 · {d}", ""]
    L.append(f"> 生成时间：{payload['generated_at']}　｜　学科方向：网络空间安全 · AI 安全交叉")
    L.append("")
    if summ.get("overview"):
        L.append("## 一、今日速览")
        L += [f"- {x}" for x in summ["overview"]]
        L.append("")
    L.append("## 二、学术前沿")
    L.append("")
    for p in payload["papers"]:
        s = ps.get(p["id"], {})
        L.append(f"### {p['title']}")
        L.append(f"- 作者：{', '.join(p['authors'][:4])}")
        L.append(f"- 分类：{', '.join(p['categories'][:3])}　｜　{p['published']}　｜　[原文]({p['url']})")
        L.append(f"- 一句话结论：{s.get('tldr') or p['abstract'][:160]}")
        if s.get("why"):
            L.append(f"- 为什么值得看：{s['why']}")
        L.append("")
    if payload["kev"]:
        L.append("## 三、在野利用（CISA KEV）")
        L.append("")
        L.append("| CVE | 厂商 / 产品 | 名称 | 入库 | 勒索利用 |")
        L.append("|---|---|---|---|---|")
        for k in payload["kev"]:
            L.append(f"| {k['cve']} | {k['vendor']} / {k['product']} | {k['name']} | {k['added']} | {k['ransomware']} |")
        L.append("")
    if payload["nvd"]:
        L.append("## 四、新增高危漏洞（NVD）")
        L.append("")
        L.append("| CVE | CVSS | 摘要 |")
        L.append("|---|---|---|")
        for v in payload["nvd"]:
            L.append(f"| {v['cve']} | {v['score']} | {v['desc'][:150]} |")
        L.append("")
    if payload["news"]:
        L.append("## 五、行业动态")
        L.append("")
        for n in payload["news"]:
            L.append(f"- [{n['title']}]({n['url']}) —— {n['feed']}")
        L.append("")
    if summ.get("trends"):
        L.append("## 六、趋势观察")
        L += [f"- {t}" for t in summ["trends"]]
        L.append("")
    if summ.get("selfcheck"):
        L.append(f"**信息密度自评：{summ['selfcheck'].get('score')}/10** —— {summ['selfcheck'].get('reason','')}")
    return "\n".join(L)


# --------------------------------------------------------------------------
# 判断层：LLM 摘要（可选）
# --------------------------------------------------------------------------
PROMPT = """你是网络安全方向的研究生助教，为「网安 + AI 前沿简报」撰写判断层。

规则（必须遵守）：
1. 事实字段（标题、作者、CVE 编号、CVSS、链接）已经由脚本抓取，你**绝不要**生成或修改；
2. 只基于给定材料写作，不确定就说得保守，不要编造数字；
3. 全部用简体中文，语气克制、专业，避免营销腔和"赋能""闭环"这类词；
4. 每篇论文的 why 要回答"读者该拿它做什么"，而不是复述摘要。

只输出一个 JSON 对象，不要任何解释文字，结构如下：
{
  "overview": ["3~4 条今日速览，每条一句话，点出该先做什么"],
  "papers": {"<论文id>": {"tldr": "一句话结论", "why": "为什么值得看，2~3 句，可操作"}},
  "trends": ["3 条跨条目二次提炼：今天这一批放在一起说明了什么"],
  "selfcheck": {"score": 1到10的整数, "reason": "一句自评理由，要说清扣分在哪"}
}

材料：
"""


def cmd_summarize(date: str) -> None:
    """调用 OpenAI 兼容接口写判断层。无 key 时跳过，简报仍可渲染（摘要兜底）。"""
    import urllib.error

    key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
    base = os.environ.get("BRIEF_API_BASE", "https://api.deepseek.com")
    model = os.environ.get("BRIEF_MODEL", "deepseek-chat")
    if not key:
        print("  · 未配置 DEEPSEEK_API_KEY / OPENAI_API_KEY，跳过判断层（将用摘要原文兜底）")
        return

    src = DATA / f"{date}.json"
    payload = json.loads(src.read_text(encoding="utf-8"))
    material = {
        "papers": [
            {"id": p["id"], "title": p["title"], "abstract": p["abstract"]}
            for p in payload["papers"]
        ],
        "kev": [
            {k: v for k, v in item.items() if k in ("cve", "vendor", "product", "name", "added")}
            for item in payload["kev"]
        ],
        "nvd": [
            {k: v for k, v in item.items() if k in ("cve", "score", "desc")}
            for item in payload["nvd"]
        ],
        "news": [{"title": n["title"], "feed": n["feed"]} for n in payload["news"]],
        "date": date,
    }
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": "你只输出 JSON，不输出任何其他文字。"},
                {"role": "user", "content": PROMPT + json.dumps(material, ensure_ascii=False)},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.3,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read())
        content = resp["choices"][0]["message"]["content"]
        summ = json.loads(content)
    except Exception as e:  # noqa: BLE001
        print(f"  ! 判断层调用失败（简报将用摘要兜底）：{type(e).__name__}: {e}", file=sys.stderr)
        return

    if not isinstance(summ.get("papers"), dict):
        print("  ! 返回结构异常，已忽略", file=sys.stderr)
        return
    summ["date"] = date
    summ["author"] = f"LLM（{model}）"
    out = DATA / f"{date}.summaries.json"
    out.write_text(json.dumps(summ, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"      判断层已写入 {out}")


def cmd_render(date: str) -> None:
    src = DATA / f"{date}.json"
    if not src.exists():
        sys.exit(f"找不到 {src}，先跑 fetch")
    payload = json.loads(src.read_text(encoding="utf-8"))
    spath = DATA / f"{date}.summaries.json"
    summ = json.loads(spath.read_text(encoding="utf-8")) if spath.exists() else {}
    if not summ:
        print("  ! 没有 summaries.json，将用摘要原文兜底（结构与渲染仍可验证）", file=sys.stderr)

    SITE.mkdir(exist_ok=True)
    dates = sorted([p.stem for p in DATA.glob("*.json") if not p.stem.endswith(".summaries")])
    (SITE / f"{date}.html").write_text(render_html(payload, summ, dates), encoding="utf-8")
    (SITE / f"{date}.md").write_text(render_md(payload, summ), encoding="utf-8")

    # 首页
    rows = "".join(
        f'<li><a href="{d}.html">{d}</a></li>' for d in sorted(dates, reverse=True)
    )
    (SITE / "index.html").write_text(
        f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>网安与 AI 前沿简报 · 归档</title><style>{CSS}</style></head><body><div class="wrap">
<div class="masthead"><div class="kicker">Security &amp; AI Frontier Daily</div>
<h1>网安与 AI 前沿简报</h1>
<div class="meta">每天自动抓取 arXiv cs.CR、CISA KEV、NVD 与安全资讯，输出结构化简报</div></div>
<h2><span class="num">00</span>历史归档</h2><ul class="trends">{rows}</ul>
<footer><p>抓取脚本 + 智能体：事实字段全部来自官方接口，LLM 只写摘要与判断。</p></footer>
</div></body></html>""",
        encoding="utf-8",
    )
    print(f"已生成：{SITE / (date + '.html')}")
    print(f"        {SITE / (date + '.md')}")
    print(f"        {SITE / 'index.html'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="网安 + AI 前沿信息每日简报")
    ap.add_argument("cmd", choices=["fetch", "summarize", "render", "all"])
    ap.add_argument("--date", default=dt.date.today().isoformat())
    a = ap.parse_args()
    if a.cmd in ("fetch", "all"):
        cmd_fetch(a.date)
    if a.cmd in ("summarize", "all"):
        cmd_summarize(a.date)
    if a.cmd in ("render", "all"):
        cmd_render(a.date)


if __name__ == "__main__":
    main()
