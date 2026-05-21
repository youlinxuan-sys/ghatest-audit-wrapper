#!/usr/bin/env bash
# audit-workflows.sh
#
# 靜態 audit GitHub Actions workflow YAML，輸出 unified report。
# 涵蓋兩類風險：
#   1. Hardening — 缺 timeout-minutes / permissions、floating 或缺失的 action ref
#   2. Secret exposure — pull_request_target + secrets 同框、run 裡 secret 可能落 log、hardcoded credential
#
# 用 PyYAML 真正 parse workflow（不再用 regex 假裝解析），所以 quoted key、
# 跨行陣列、key order、註解、跳脫引號這些 YAML 合法寫法都自然處理掉。
#
# 依賴：python3 + PyYAML。CI 會在跑 audit 前 pip install pyyaml。
#
# Env vars:
#   WORKFLOW_GLOB        default: .github/workflows/*.y*ml
#   OUTPUT_FORMAT        text | markdown | json   (default: markdown)
#   FAIL_ON_CRITICAL     0 | 1                    (default: 0)
#   WARN_SCORE           default: 3
#   CRITICAL_SCORE       default: 7
#
# Exit codes:
#   0 — clean OR FAIL_ON_CRITICAL=0
#   2 — critical findings AND FAIL_ON_CRITICAL=1
#   3 — invalid input / no workflow files matched / PyYAML 不可用

set -euo pipefail

WORKFLOW_GLOB="${WORKFLOW_GLOB:-.github/workflows/*.y*ml}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-markdown}"
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-0}"
WARN_SCORE="${WARN_SCORE:-3}"
CRITICAL_SCORE="${CRITICAL_SCORE:-7}"

# shellcheck disable=SC2206
FILES=( $WORKFLOW_GLOB )
if [[ ! -e "${FILES[0]:-}" ]]; then
  echo "no workflow files matched glob: $WORKFLOW_GLOB" >&2
  exit 3
fi

# sentinel 檔放 mktemp 暫存區，不污染 cwd。trap 確保結束時清掉。
SENTINEL="$(mktemp -t audit-critical.XXXXXX)"
trap 'rm -f "$SENTINEL"' EXIT

python3 - "$OUTPUT_FORMAT" "$WARN_SCORE" "$CRITICAL_SCORE" "$SENTINEL" "${FILES[@]}" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

VALID_FORMATS = {"text", "markdown", "json"}

output_format = sys.argv[1]
warn_score = int(sys.argv[2])
critical_score = int(sys.argv[3])
sentinel_path = Path(sys.argv[4])
files = [Path(p) for p in sys.argv[5:]]

# OUTPUT_FORMAT 拼錯 fail fast，不默默落回 markdown
if output_format not in VALID_FORMATS:
    sys.stderr.write(
        f"invalid OUTPUT_FORMAT: {output_format!r} "
        f"(expected one of {sorted(VALID_FORMATS)})\n"
    )
    sys.exit(3)

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "PyYAML 不可用 —— 請先 `pip install pyyaml`。\n"
    )
    sys.exit(3)


# ---- Patterns（只用於掃 run 字串內容，不用來解析 YAML 結構）----
RE_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
# 會把資料寫到 stdout / log 的常見指令。S2 用「保守標記」策略 —— 不嘗試
# 精準解析 shell（heredoc / quote / 子shell 語法角落追不完），只要 run
# 裡同時出現輸出指令 + secret 就標 warn，交給人看。
RE_OUTPUT_CMD = re.compile(
    r"\b(echo|printf|tee|cat|set-output)\b", re.IGNORECASE
)
RE_HARDCODED = re.compile(
    r"(token|password|api[_-]?key|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    re.IGNORECASE,
)
FLOATING_REF_RE = re.compile(r"@(main|master|latest|v\d+)$")


def strip_shell_comments(script: str) -> str:
    """逐行剝掉 shell 註解（行首為 # 的整行）。

    保守標記策略只需要排除「整行就是註解」的情況，避免
    `# echo "${{ secrets.X }}"` 被誤標。不處理行尾 inline 註解
    （# 在 shell 行尾的語意要看 quote，又是另一個 parse 坑）——
    行首註解涵蓋絕大多數情況，剩下的就讓保守標記去 warn。
    """
    out = []
    for ln in script.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        out.append(ln)
    return "\n".join(out)


def best_effort_line(raw: str, needle: str) -> int | None:
    """在原始檔內容找 needle 第一次出現的行號（1-based）。

    PyYAML safe_load 不保留行號，所以 secret echo 這類需要行號的 finding
    用「回原文搜字串」補回。找不到回 None（呼叫端就不標行號）。
    needle 內容重複時只標第一處 —— best-effort，可接受。
    """
    idx = raw.find(needle)
    if idx < 0:
        return None
    return raw[:idx].count("\n") + 1


def as_list(v) -> list:
    """把 YAML 值正規化成 list —— scalar 包成單元素 list、None 回空 list。"""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def collect_secret_env_vars(env) -> set:
    """從一個 env: mapping 收出『值是 ${{ secrets.* }}』的變數名。"""
    out = set()
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str) and RE_SECRETS_REF.search(v):
                out.add(str(k))
    return out


def iter_uses(steps) -> list:
    """從 steps list 收出所有 `uses` 值。"""
    out = []
    for step in steps or []:
        if isinstance(step, dict) and "uses" in step:
            val = step["uses"]
            if isinstance(val, str):
                out.append(val)
    return out


def iter_strings(node):
    """遞迴走訪 parsed YAML，yield 出所有 string 純量值『與 dict key』。

    用於把 secret 判斷限縮在『workflow 真正用到的值』 —— parse 後註解
    已不存在，所以掃這裡不會被註解裡的 ${{ secrets.* }} 誤觸發。
    dict key 也掃（複審 round 4 Low）—— expression 當 key 雖罕見但仍是值。
    """
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from iter_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from iter_strings(v)


def audit_file(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    score = 0

    # ---- parse YAML ----
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        # 語法錯的 workflow：報一個 warn，不 crash、不誤判成 clean
        findings.append(("warn", "P0",
            f"YAML 解析失敗，無法 audit —— {str(e).splitlines()[0]}"))
        return _result(path, 1, findings)

    if not isinstance(doc, dict):
        findings.append(("warn", "P0",
            "workflow 最外層不是 mapping，無法 audit"))
        return _result(path, 1, findings)

    # PyYAML 會把未加引號的 `on:` 解析成 boolean True（YAML 1.1 坑）。
    # workflow 真正的 on key 因此可能是字串 "on" 或 boolean True，兩個都看。
    on_value = doc.get("on", doc.get(True))
    top_perms = "permissions" in doc
    jobs = doc.get("jobs")

    # ---- H1 / H2：逐 job 檢查 permissions / timeout-minutes ----
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_has_perms = "permissions" in job
            job_has_timeout = "timeout-minutes" in job
            if not top_perms and not job_has_perms:
                findings.append(("warn", "H1",
                    f"job `{job_name}` 缺 `permissions:`（workflow-level 也沒設）— "
                    "預設拿到 read+write 的 GITHUB_TOKEN，建議顯式宣告最小權限"))
                score += 2
            if not job_has_timeout:
                findings.append(("warn", "H2",
                    f"job `{job_name}` 缺 `timeout-minutes` — "
                    "失控 job 可能跑滿 6 小時 quota，建議設 15-30 分鐘"))
                score += 2

    # ---- H3：floating / missing action ref ----
    floating, missing_ref = [], []
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for ref in iter_uses(job.get("steps")):
                # 本地 action / docker action 不適用 ref 規則
                if ref.startswith("./") or ref.startswith("docker://"):
                    continue
                if "@" not in ref:
                    missing_ref.append(ref)
                    continue
                if FLOATING_REF_RE.search(ref):
                    floating.append(ref)
    for ref in sorted(set(floating)):
        findings.append(("warn", "H3",
            f"floating action ref: `{ref}` — 建議 pin SHA 或 specific patch tag"))
        score += 1
    for ref in sorted(set(missing_ref)):
        findings.append(("warn", "H3",
            f"action `{ref}` 沒有 `@<ref>` — 等同隱性追最新版，建議 pin SHA"))
        score += 1

    # ---- S1：pull_request_target + secrets ----
    on_keys = []
    if isinstance(on_value, dict):
        on_keys = [str(k) for k in on_value.keys()]
    else:
        on_keys = [str(x) for x in as_list(on_value)]
    has_pr_target = "pull_request_target" in on_keys
    # secret 判斷走 parsed doc 的 string 值，不掃 raw —— 避免註解裡的
    # ${{ secrets.* }} 造成 false positive（複審 bug 2）。
    has_secret_ref = any(
        RE_SECRETS_REF.search(s) for s in iter_strings(doc))
    if has_pr_target and has_secret_ref:
        findings.append(("critical", "S1",
            "`pull_request_target` 同時引用 `${{ secrets.* }}` — "
            "可被 fork PR 利用偷 secret，極高風險"))
        score += 6

    # ---- S2：secret 可能落 log（保守標記策略）----
    # 不嘗試精準解析 shell（heredoc / quote / 子shell 角落追不完，
    # 五輪 review 證明這是無底洞）。改成：一個 step 的 run 裡同時出現
    #   輸出指令（echo/printf/tee/cat/set-output） + secret
    # 就標 warn 提醒人看 —— 寧可保守多標、不漏真正的 leak。
    # 因為是「可疑非確定」，級別用 warn（不擋 CI），S1 才維持 critical。
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_env_vars = collect_secret_env_vars(job.get("env"))
            for step in as_list(job.get("steps")):
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                # 剝掉整行 shell 註解，避免 `# echo "${{ secrets }}"` 誤標
                scan = strip_shell_comments(run)
                if not RE_OUTPUT_CMD.search(scan):
                    continue  # 沒有輸出指令 → 不可能 echo 落 log

                ln = best_effort_line(
                    raw, next((x for x in run.splitlines() if x.strip()),
                              "").strip())
                loc = f"L{ln}: " if ln else ""

                # S2a：run 裡有輸出指令 + 直接出現 ${{ secrets.* }}
                if RE_SECRETS_REF.search(scan):
                    findings.append(("warn", "S2",
                        f"{loc}step 的 run 同時有輸出指令與 `${{{{ secrets.* }}}}`"
                        f" — secret 可能落 log，請確認"))
                    score += 3
                    continue  # 同 step 已標一次，不再重複標 S2b

                # S2b：run 裡有輸出指令 + 引用綁 secret 的 env 變數
                step_env_vars = job_env_vars | collect_secret_env_vars(
                    step.get("env"))
                for var in step_env_vars:
                    if re.search(r"\$\{?" + re.escape(var) + r"\b\}?", scan):
                        findings.append(("warn", "S2",
                            f"{loc}step 的 run 有輸出指令且引用 `${var}`"
                            f"（由 env 綁定 secret） — secret 可能落 log，請確認"))
                        score += 3
                        break

    # ---- S3：hardcoded credential ----
    for m in RE_HARDCODED.finditer(raw):
        snippet = m.group(0)
        # 排除 env: KEY: ${{ secrets.X }} 這種正常映射
        if "secrets." in raw[max(0, m.start() - 20):m.end() + 5]:
            continue
        ln = raw[:m.start()].count("\n") + 1
        findings.append(("warn", "S3",
            f"L{ln}: 看起來像 hardcoded credential — `{snippet[:40]}...`"))
        score += 3

    return _result(path, score, findings)


def _result(path: Path, score: int, findings: list) -> dict:
    """組 finding list → 結果 dict，並算 severity。

    severity 取「finding 自身級別」與「分數門檻」較重者 —— 分數門檻只能
    往上加重（多個 warn 累積成 critical），不能把 critical finding 降級。
    """
    levels = {f[0] for f in findings}
    if "critical" in levels:
        severity = "critical"
    elif "warn" in levels:
        severity = "warn"
    else:
        severity = "ok"
    if score >= critical_score:
        severity = "critical"
    elif score >= warn_score and severity == "ok":
        severity = "warn"
    return {
        "file": str(path),
        "score": score,
        "severity": severity,
        "findings": [
            {"level": lvl, "code": code, "message": msg}
            for lvl, code, msg in findings
        ],
    }


results = [audit_file(p) for p in files]
overall_critical = any(r["severity"] == "critical" for r in results)

if output_format == "json":
    print(json.dumps({"results": results, "critical": overall_critical},
                     ensure_ascii=False, indent=2))
elif output_format == "text":
    for r in results:
        print(f"[{r['severity'].upper()}] {r['file']} (score={r['score']})")
        for f in r["findings"]:
            print(f"  {f['level'].upper():>8} {f['code']}: {f['message']}")
else:  # markdown
    print("# GitHub Actions Workflow Audit Report")
    print()
    counts = {"ok": 0, "warn": 0, "critical": 0}
    for r in results:
        counts[r["severity"]] += 1
    print(f"**Summary**: {counts['critical']} critical · "
          f"{counts['warn']} warn · {counts['ok']} clean")
    print()
    if overall_critical:
        print("> 🚨 至少一個 workflow 有 **critical** 級別發現，merge 前必須處理。")
        print()
    for r in results:
        emoji = {"ok": "✅", "warn": "⚠️", "critical": "🚨"}[r["severity"]]
        print(f"## {emoji} `{r['file']}` (score: {r['score']})")
        print()
        if not r["findings"]:
            print("沒發現問題。")
            print()
            continue
        print("| Level | Code | Finding |")
        print("|-------|------|---------|")
        for f in r["findings"]:
            level_emoji = {"warn": "⚠️", "critical": "🚨"}[f["level"]]
            msg = f["message"].replace("|", "\\|")
            print(f"| {level_emoji} {f['level']} | {f['code']} | {msg} |")
        print()
    print("---")
    print()
    print("**Codes**: H1=permissions / H2=timeout / H3=floating-ref · "
          "S1=pr_target+secrets / S2=secret-may-log / S3=hardcoded · "
          "P0=parse-error")

# Signal to bash via sentinel file
sentinel_path.write_text("1" if overall_critical else "0")
PYEOF

critical=$(cat "$SENTINEL" 2>/dev/null || echo 0)

if [[ "$critical" == "1" && "$FAIL_ON_CRITICAL" == "1" ]]; then
  echo "::error::critical audit findings, failing per FAIL_ON_CRITICAL=1" >&2
  exit 2
fi
