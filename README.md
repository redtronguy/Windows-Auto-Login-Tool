# Windows Auto-Login Tool (WALT)

WALT is an interactive PowerShell utility that safely enables or disables Windows auto-login for domain or local accounts. It wraps the full workflow—credential validation, registry updates, status reporting, and transcript logging—so you can configure auto-login without touching the registry manually.

## Requirements

- Windows Powershell 5.1+ (or PowerShell 7+)
- Administrator privileges (HKLM writes)
- Execution policy allowing script execution

## Usage

1. Clone this repository and open an elevated PowerShell session in the repo root.
2. (Optional) If your execution policy blocks scripts, launch with:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\WALT.ps1
   ```

   or start pwsh/cmd and run:

   ```powershell
   pwsh -ExecutionPolicy Bypass -File .\WALT.ps1
   ```

3. Otherwise, run normally with:

   ```powershell
   pwsh .\WALT.ps1
   ```

4. Follow the on-screen menu to:
   - Enable Auto-Login (validates credentials, sets Winlogon values, shows status)
   - Disable Auto-Login (removes stored password, resets flags)
   - Show Current Status (read-only view of current registry values)

Transcripts/logs are written under `.\logs`. Clear sensitive logs with `Get-ChildItem .\logs\*.log | Remove-Item` before committing or sharing.

## Security Notes

Enabling auto-login stores your password in plaintext inside `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. Only enable on secured devices, and disable auto-login if requirements change.
