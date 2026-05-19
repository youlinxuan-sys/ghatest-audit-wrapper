#!/usr/bin/env bash
# audit-workflows.sh
#
# 靜態 audit GitHub Actions workflow YAML，輸出 unified markdown report。
# 涵蓋兩類風險：
#   1. Hardening — 缺 timeout-minutes / permissions、floating action refs (@main, @v4)
#   2. Secret exposure — pull_request_target + secrets 同框、echo secret、unpinned action 收 secret
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
#   3 — invalid input / no workflow files matched

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

python3 - "$OUTPUT_FORMAT" "$WARN_SCORE" "$CRITICAL_SCORE" "${FILES[@]}" <<'PYEOF'
import re
import sys
import json
from pathlib import Path

output_format = sys.argv[1]
warn_score = int(sys.argv[2])
critical_score = int(sys.argv[3])
files = [Path(p) for p in sys.argv[4:]]

# --- Patterns ---
RE_PR_TARGET = re.compile(r"^\s*-?\s*pull_request_target\b", re.MULTILINE)
RE_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
RE_ECHO_SECRET = re.compile(
    r"\b(echo|printf|tee|set-output)\b[^\n]*\$\{\{\s*secrets\.", re.IGNORECASE
)
RE_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
RE_TIMEOUT = re.compile(r"^\s*timeout-minutes\s*:", re.MULTILINE)
RE_PERMISSIONS = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
RE_JOBS_BLOCK = re.compile(r"^jobs\s*:\s*$", re.MULTILINE)
RE_HARDCODED = re.compile(
    r"(token|password|api[_-]?key|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    re.IGNORECASE,
)

FLOATING_REF_RE = re.compile(r"@(main|master|latest|v\d+)$")

def audit_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    score = 0

    has_jobs = bool(RE_JOBS_BLOCK.search(text))
    has_top_perms = bool(RE_PERMISSIONS.search(text))
    has_timeout = bool(RE_TIMEOUT.search(text))

    # H1: missing top-level permissions
    if has_jobs and not has_top_perms:
        findings.append(("warn", "H1",
            "缺 workflow-level `permissions:` — 預設拿到 read+write 的 GITHUB_TOKEN，建議顯式宣告最小權限"))
        score += 2

    # H2: missing timeout-minutes (job or workflow)
    if has_jobs and not has_timeout:
        findings.append(("warn", "H2",
            "缺 `timeout-minutes` — 失控 job 可能跑滿 6 小時 quota，建議設 15-30 分鐘"))
        score += 2

    # H3: floating action refs
    floating = []
    for m in RE_USES.finditer(text):
        ref = m.group(1)
        if "@" not in ref:
            continue
        if FLOATING_REF_RE.search(ref):
            floating.append(ref)
    if floating:
        for ref in sorted(set(floating)):
            findings.append(("warn", "H3",
                f"floating action ref: `{ref}` — 建議 pin SHA 或 specific patch tag"))
            score += 1

    # S1: pull_request_target + secrets
    if RE_PR_TARGET.search(text) and RE_SECRETS_REF.search(text):
        findings.append(("critical", "S1",
            "`pull_request_target` 同時引用 `${{ secrets.* }}` — 可被 fork PR 利用偷 secret，極高風險"))
        score += 6

    # S2: echo / printf / tee secret
    for m in RE_ECHO_SECRET.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        findings.append(("critical", "S2",
            f"L{line_no}: 在 shell 輸出 secret 表達式 — secret 會落 log"))
        score += 4

    # S3: hardcoded credential-looking value
    for m in RE_HARDCODED.finditer(text):
        # exclude obvious env: secrets.X mapping
        snippet = m.group(0)
        if "secrets." in text[max(0, m.start()-20):m.end()+5]:
            continue
        line_no = text[:m.start()].count("\n") + 1
        findings.append(("warn", "S3",
            f"L{line_no}: 看起來像 hardcoded credential — `{snippet[:40]}...`"))
        score += 3

    severity = "ok"
    if score >= critical_score:
        severity = "critical"
    elif score >= warn_score:
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
    print(json.dumps({"results": results, "critical": overall_critical}, ensure_ascii=False, indent=2))
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
    print(f"**Summary**: {counts['critical']} critical · {counts['warn']} warn · {counts['ok']} clean")
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
    print("**Codes**: H1=permissions / H2=timeout / H3=floating-ref · S1=pr_target+secrets / S2=echo-secret / S3=hardcoded")

# Signal to bash via sentinel file (subprocess return code is limited)
Path(".audit-critical").write_text("1" if overall_critical else "0")
PYEOF

critical=$(cat .audit-critical 2>/dev/null || echo 0)
rm -f .audit-critical

if [[ "$critical" == "1" && "$FAIL_ON_CRITICAL" == "1" ]]; then
  echo "::error::critical audit findings, failing per FAIL_ON_CRITICAL=1" >&2
  exit 2
fi
