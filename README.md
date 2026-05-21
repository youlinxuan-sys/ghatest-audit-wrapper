# ghatest-audit-wrapper

GitHub Actions workflow 安全 audit 工具。單一 scanner，把 workflow YAML 的安全問題掃成一份 PR comment 友善的 markdown report。

## 動機

GitHub Actions workflow 預設不安全：缺 `timeout-minutes`、`permissions` 寫太鬆、`uses: foo@main` 浮動 ref、`pull_request_target` 配 `${{ secrets.* }}` 等。`./scripts/audit-workflows.sh` 是一支 unified scanner，用 PyYAML 真正 parse workflow（不靠 regex 猜結構，所以 quoted key、跨行陣列、key order 等 YAML 合法寫法都正確處理），涵蓋兩類規則：

- **Hardening (H1-H3)** — 逐 job 檢查缺 `permissions` / `timeout-minutes`、floating 或缺失的 action ref
- **Secret exposure (S1-S3)** — `pull_request_target` 配 secret（critical）、run 裡 secret 可能落 log（warn，保守標記）、hardcoded credential（warn）

> 註：
> - **S1** 走 parse 後的結構判斷（`on` 的 key、所有 string 值），確定性高、列 critical。
> - **S2** 採「保守標記」：一個 step 的 `run` 裡同時出現輸出指令（`echo`/`printf`/`tee`/`cat`/`set-output`）與 secret，就標 **warn**。它不精準解析 shell（heredoc / quote / 子shell 角落無法靠靜態分析窮盡），刻意寧可多標一個 warn 讓人看，也不漏真正的 leak —— 所以 echo 與 secret 在同 `run` 不同指令時也會標。整行 shell 註解會先剝掉、不誤標。
> - **S3（hardcoded credential）刻意掃原始文字**，連註解裡 credential-looking 的值也會報 —— 註解裡留真 token 同樣有外洩風險。

輸出 `markdown` / `text` / `json` 三種格式，可直接貼 PR comment 或當 CI fail gate（`FAIL_ON_CRITICAL=1`）。

## 三方協作 flow（這個 repo 用的）

- **主人**：唯一能 merge 到 `main` 的人；最終看過所有 PR
- **小璁芛**（Mac Claude Opus）：寫 code、review 小璁璁的 PR
- **小璁璁**（B 機 codex gpt-5.5）：寫 code、跑 audit、review 小璁芛的 PR

### Commit / PR conventions

| 項目 | 規則 |
|---|---|
| branch 命名 | `feat/xxx` / `fix/xxx` / `docs/xxx` |
| commit message 開頭 | `[claude] ...` / `[xiaocongcong] ...` / `[主人] ...` |
| PR comment | 開頭標 `**Reviewer: 小璁芛**` / `**Reviewer: 小璁璁**` |
| merge 策略 | 主人手動 squash merge，linear history |

### `main` 受 branch protection 保護

- 禁止直推 `main`
- 所有改動走 PR
- linear history
- status checks（audit workflow）必須通過

## 依賴

`python3` + `PyYAML`。本機跑前先裝：

```bash
pip install pyyaml
```

CI 已在 audit 步驟前自動 `pip install pyyaml`，不需手動處理。

## 使用

```bash
# 預設掃 .github/workflows/*.y*ml、輸出 markdown
./scripts/audit-workflows.sh

# 換格式 / 指定掃描範圍 / 開 critical fail gate
OUTPUT_FORMAT=text ./scripts/audit-workflows.sh
WORKFLOW_GLOB='tests/fixtures/*.yml' ./scripts/audit-workflows.sh
FAIL_ON_CRITICAL=1 ./scripts/audit-workflows.sh   # 有 critical 時 exit 2
```

| Env var | 預設 | 說明 |
|---|---|---|
| `WORKFLOW_GLOB` | `.github/workflows/*.y*ml` | 要掃的檔案 glob |
| `OUTPUT_FORMAT` | `markdown` | `markdown` / `text` / `json`，拼錯會 fail fast |
| `FAIL_ON_CRITICAL` | `0` | `1` = 有 critical 發現時 exit 2 |
| `WARN_SCORE` / `CRITICAL_SCORE` | `3` / `7` | severity 分數門檻 |

`tests/fixtures/` 下有 20 個 workflow fixture，涵蓋各條規則的正反案例與邊界，CI 每次跑會對它們做 sanity check。

## 狀態

🟢 運行中。audit script + CI workflow 已就緒，自己的 workflow 由自己 audit（dogfood）。
