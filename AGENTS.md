# Repository Guidelines

## Project Structure & Module Organization
`Windows-Auto-Login-Tool.ps1` in the repo root contains the full PowerShell workflow for enabling and disabling Windows domain auto-login; treat it as the single source of truth for business logic and UI prompts. Session transcripts are written to `logs/` (auto-created by `Start-Log`), so avoid committing generated `.log` files. Documentation such as `README.md`, `CLAUDE.md`, `GEMINI.md`, and goal tracking notes stay in the root for quick discovery.

## Build, Test, and Development Commands
- `pwsh .\Windows-Auto-Login-Tool.ps1` — run the interactive menu locally (use Windows Terminal or VS Code’s PowerShell profile).  
- `pwsh -File .\Windows-Auto-Login-Tool.ps1 2>&1 | Tee-Object .\logs\dev-run.log` — capture output when iterating on registry or logging changes.  
- `Get-ChildItem .\logs\*.log | Remove-Item` — purge local logs before committing if you produced sensitive data.

## Coding Style & Naming Conventions
PowerShell scripts should use 4-space indentation, `PascalCase` for functions (`Enable-AutoLogin`), and `camelCase` for local variables (`$logDir`, `$registryPath`). Favor explicit helper functions over inline script blocks so new automation fits the existing `Start-Log`/`Stop-Log` pattern. Prefer `Write-Host` for user messaging and `try { } catch { }` with `-ErrorAction Stop` when touching the registry. Inline comments should clarify intent, especially around security-sensitive steps like handling credentials.

## Testing Guidelines
No automated framework is currently wired up; rely on manual verification on a non-production Windows VM. Test both menu paths: enabling auto-login (confirm registry values under `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`) and disabling it (password cleared). Capture transcripts from `logs/` as artifacts when reporting results. Name exploratory test scripts `Test-*` so they remain easy to prune.

## Commit & Pull Request Guidelines
History shows concise, capitalized summaries (`Initial commit`). Follow that style: use an imperative headline under 72 characters (“Add registry validation step”), reference related issues in the body, and describe any security implications. PRs should include: purpose, manual test notes (commands + environment), screenshots of console prompts if UI changed, and confirmation that logs/secrets were not committed.

## Security & Configuration Tips
Run scripts from an elevated PowerShell session because registry edits target `HKLM`. Never store plaintext passwords outside of the transient `DefaultPassword` value; scrub them from logs before sharing. Keep domain-specific defaults configurable near the top of the script so deployments can be audited quickly.
