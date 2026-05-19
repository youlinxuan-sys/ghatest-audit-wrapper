# ghatest-audit-wrapper

GitHub Actions workflow 安全 audit 的 wrapper 工具。包兩個 audit 來源成一個 PR comment 友善的 markdown report。

## 動機

GitHub Actions workflow 預設不安全：缺 `timeout-minutes`、`permissions` 寫太鬆、`uses: foo@main` 浮動 ref、`pull_request_target` 配 `${{ secrets.* }}` 等。這支工具把兩類靜態 audit 包成 `./scripts/audit-workflows.sh`：

- **Hardening audit** — 抓缺 timeout/permissions/concurrency、floating action ref
- **Secret exposure audit** — 抓 secret echo、unpinned action 收 secret、hardcoded credential

兩份報告合併輸出 unified markdown，可直接貼 PR comment 或當 CI fail gate。

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

## 使用

```bash
./scripts/audit-workflows.sh
```

（後續 PR 補 scaffold；目前為佔位）

## 狀態

🌱 初始化階段。第一個 PR 會帶入 audit script + GitHub Actions workflow。
