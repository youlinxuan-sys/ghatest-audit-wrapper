#!/usr/bin/env bash
# audit-workflows.sh
#
# 靜態 audit GitHub Actions workflow YAML，輸出 unified report。
# 涵蓋兩類風險：
#   1. Hardening — 缺 timeout-minutes / permissions、floating 或缺失的 action ref
#   2. Secret exposure — pull_request_target + secrets 同框、echo secret、hardcoded credential
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
RE_ECHO_SECRET = re.compile(
    r"\b(echo|printf|tee|set-output)\b[^\n]*\$\{\{\s*secrets\.", re.IGNORECASE
)
RE_ECHO_LINE = re.compile(r"\b(echo|printf|tee)\b[^\n]*", re.IGNORECASE)
RE_HARDCODED = re.compile(
    r"(token|password|api[_-]?key|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    re.IGNORECASE,
)
FLOATING_REF_RE = re.compile(r"@(main|master|latest|v\d+)$")


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
    has_secret_ref = bool(RE_SECRETS_REF.search(raw))
    if has_pr_target and has_secret_ref:
        findings.append(("critical", "S1",
            "`pull_request_target` 同時引用 `${{ secrets.* }}` — "
            "可被 fork PR 利用偷 secret，極高風險"))
        score += 6

    # ---- S2：secret 落 log（直接 echo + env-then-echo）----
    # 走 parse 後的 step 結構：env scope 精確到 step（step env 不流到下一個
    # step），job-level env 對該 job 所有 step 生效。
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            job_env_vars = collect_secret_env_vars(job.get("env"))
            for step in as_list(job.get("steps")):
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                # 該 step 可見的 secret env 變數 = job-level + 該 step env
                step_env_vars = job_env_vars | collect_secret_env_vars(
                    step.get("env"))

                # S2a：run 內直接出現 ${{ secrets.* }}
                if RE_ECHO_SECRET.search(run):
                    ln = best_effort_line(raw, run.strip().splitlines()[0])
                    loc = f"L{ln}: " if ln else ""
                    findings.append(("critical", "S2",
                        f"{loc}在 shell 輸出 secret 表達式 — secret 會落 log"))
                    score += 4

                # S2b：env-then-echo —— echo 引用了綁 secret 的 env 變數
                for em in RE_ECHO_LINE.finditer(run):
                    echo_line = em.group(0)
                    for var in step_env_vars:
                        if re.search(r"\$\{?" + re.escape(var) + r"\b\}?",
                                     echo_line):
                            ln = best_effort_line(raw, echo_line.strip())
                            loc = f"L{ln}: " if ln else ""
                            findings.append(("critical", "S2",
                                f"{loc}echo `${var}` — 該變數由 env 綁定 "
                                f"`${{{{ secrets.* }}}}`，secret 會間接落 log"))
                            score += 4
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
          "S1=pr_target+secrets / S2=echo-secret / S3=hardcoded · P0=parse-error")

# Signal to bash via sentinel file
sentinel_path.write_text("1" if overall_critical else "0")
PYEOF

critical=$(cat "$SENTINEL" 2>/dev/null || echo 0)

if [[ "$critical" == "1" && "$FAIL_ON_CRITICAL" == "1" ]]; then
  echo "::error::critical audit findings, failing per FAIL_ON_CRITICAL=1" >&2
  exit 2
fi
