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

# sentinel 檔放 mktemp 暫存區，不污染 cwd（nit 6）。trap 確保結束時清掉。
SENTINEL="$(mktemp -t audit-critical.XXXXXX)"
trap 'rm -f "$SENTINEL"' EXIT

python3 - "$OUTPUT_FORMAT" "$WARN_SCORE" "$CRITICAL_SCORE" "$SENTINEL" "${FILES[@]}" <<'PYEOF'
import re
import sys
import json
from pathlib import Path

VALID_FORMATS = {"text", "markdown", "json"}

output_format = sys.argv[1]
warn_score = int(sys.argv[2])
critical_score = int(sys.argv[3])
sentinel_path = Path(sys.argv[4])
files = [Path(p) for p in sys.argv[5:]]

# nit 5: OUTPUT_FORMAT 拼錯要 fail fast，不要默默落回 markdown
if output_format not in VALID_FORMATS:
    sys.stderr.write(
        f"invalid OUTPUT_FORMAT: {output_format!r} "
        f"(expected one of {sorted(VALID_FORMATS)})\n"
    )
    sys.exit(3)

# --- Patterns ---
# nit 2: pull_request_target 兩種寫法都要抓 —
#   block 形式  on:\n  pull_request_target:
#   shorthand   on: [pull_request_target]  /  on: pull_request_target
RE_PR_TARGET = re.compile(r"\bpull_request_target\b")
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

# nit 3: env-then-echo —— `env:` 把 secret 存進變數，後面 run 再 echo $VAR。
#   先抓 env mapping：    VAR_NAME: ${{ secrets.X }}
#   再看 shell 有沒有引用 $VAR_NAME / ${VAR_NAME}
RE_ENV_SECRET_MAP = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}",
    re.MULTILINE,
)
RE_ECHO_LINE = re.compile(
    r"\b(echo|printf|tee)\b[^\n]*", re.IGNORECASE
)


def split_jobs(text: str) -> list:
    """把 `jobs:` 區塊底下每個 job 切成 (job_name, job_body) list。

    純 regex / 縮排切割（保持零依賴）。GitHub Actions YAML 強制
    job 名稱固定縮一級、step 等內容縮更深，所以靠縮排切是穩的。
    切不出來（無 jobs: 或格式怪）回空 list。
    """
    m = RE_JOBS_BLOCK.search(text)
    if not m:
        return []
    lines = text[m.end():].splitlines()
    # 找第一個 job 名稱行的縮排深度當基準
    job_indent = None
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:  # 已經離開 jobs: 區塊
            return []
        job_indent = indent
        break
    if job_indent is None:
        return []

    jobs = []
    cur_name = None
    cur_body: list = []
    for ln in lines:
        stripped = ln.strip()
        indent = len(ln) - len(ln.lstrip())
        # 縮排回到 0 且非空 → jobs: 區塊結束
        if stripped and indent == 0:
            break
        # job 名稱行：剛好 job_indent 縮排、以冒號結尾
        if (indent == job_indent and stripped
                and not stripped.startswith("#")
                and re.match(r"^[A-Za-z0-9_\-]+\s*:\s*$", stripped)):
            if cur_name is not None:
                jobs.append((cur_name, "\n".join(cur_body)))
            cur_name = stripped.rstrip(":").strip()
            cur_body = []
        elif cur_name is not None:
            cur_body.append(ln)
    if cur_name is not None:
        jobs.append((cur_name, "\n".join(cur_body)))
    return jobs

def audit_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    score = 0

    has_jobs = bool(RE_JOBS_BLOCK.search(text))
    has_top_perms = bool(RE_PERMISSIONS.search(text))
    jobs = split_jobs(text)

    # H1/H2: permissions / timeout-minutes —— 逐 job 檢查（nit 1）。
    # 一個 job 在 job body 沒設、且 workflow top-level 也沒設 → 才算缺。
    # （top-level 設了會被所有 job 繼承，所以 top-level 有就全 job 過。）
    if has_jobs and jobs:
        for job_name, body in jobs:
            job_has_perms = bool(RE_PERMISSIONS.search(body))
            job_has_timeout = bool(RE_TIMEOUT.search(body))
            if not has_top_perms and not job_has_perms:
                findings.append(("warn", "H1",
                    f"job `{job_name}` 缺 `permissions:`（workflow-level 也沒設）— "
                    "預設拿到 read+write 的 GITHUB_TOKEN，建議顯式宣告最小權限"))
                score += 2
            if not job_has_timeout:
                findings.append(("warn", "H2",
                    f"job `{job_name}` 缺 `timeout-minutes` — "
                    "失控 job 可能跑滿 6 小時 quota，建議設 15-30 分鐘"))
                score += 2
    elif has_jobs:
        # 有 jobs: 但切不出 job（格式異常）— 退回全檔粗檢，至少不漏報
        if not has_top_perms:
            findings.append(("warn", "H1",
                "缺 workflow-level `permissions:` — 建議顯式宣告最小權限"))
            score += 2
        if not RE_TIMEOUT.search(text):
            findings.append(("warn", "H2",
                "缺 `timeout-minutes` — 建議設 15-30 分鐘"))
            score += 2

    # H3: floating action refs + missing ref（nit 4）
    floating = []
    missing_ref = []
    for m in RE_USES.finditer(text):
        ref = m.group(1)
        # 本地 action（./ 開頭）跟 docker:// 不適用 ref 規則
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            # nit 4: `uses: actions/checkout` 沒有 @ref —— 抓不到版本、隱性 floating
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

    # S1: pull_request_target + secrets
    if RE_PR_TARGET.search(text) and RE_SECRETS_REF.search(text):
        findings.append(("critical", "S1",
            "`pull_request_target` 同時引用 `${{ secrets.* }}` — 可被 fork PR 利用偷 secret，極高風險"))
        score += 6

    # S2: echo / printf / tee secret —— 直接形式（echo ${{ secrets.X }}）
    for m in RE_ECHO_SECRET.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        findings.append(("critical", "S2",
            f"L{line_no}: 在 shell 輸出 secret 表達式 — secret 會落 log"))
        score += 4

    # S2: env-then-echo —— 間接形式（nit 3）。
    # env: 把 secret 存進變數，後面 echo $VAR 一樣會把 secret 印進 log。
    env_secret_vars = {m.group(1) for m in RE_ENV_SECRET_MAP.finditer(text)}
    if env_secret_vars:
        for m in RE_ECHO_LINE.finditer(text):
            echo_line = m.group(0)
            for var in env_secret_vars:
                # 抓 $VAR 或 ${VAR}（用 \b 與邊界避免 VAR 是另一變數的前綴）
                if re.search(r"\$\{?" + re.escape(var) + r"\b\}?", echo_line):
                    line_no = text[:m.start()].count("\n") + 1
                    findings.append(("critical", "S2",
                        f"L{line_no}: echo `${var}` — 該變數由 env 綁定 "
                        f"`${{{{ secrets.* }}}}`，secret 會間接落 log"))
                    score += 4
                    break

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

    # severity：取「finding 自身級別」與「分數門檻」兩者的較重者。
    # 修正先前 bug —— 有 critical finding 卻因分數沒到門檻被歸成 warn/ok。
    # 分數門檻只能往上加重（多個 warn 累積成 critical），不能往下蓋過 finding 級別。
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
sentinel_path.write_text("1" if overall_critical else "0")
PYEOF

critical=$(cat "$SENTINEL" 2>/dev/null || echo 0)

if [[ "$critical" == "1" && "$FAIL_ON_CRITICAL" == "1" ]]; then
  echo "::error::critical audit findings, failing per FAIL_ON_CRITICAL=1" >&2
  exit 2
fi
