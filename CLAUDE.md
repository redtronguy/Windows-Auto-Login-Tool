# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows Auto-Login Tool is a PowerShell-based application for managing auto-login functionality on Windows systems (domain-joined, local, or hybrid configurations). The tool uses **PSDialog** for a text-based, dialog-style interface within the CLI, resembling Linux dialog/whiptail menus. **Important:** This project must NOT use WinForms or WPF - all UI interactions occur within the terminal using PSDialog.

## Running the Tool

```powershell
# Execute the main script
.\Windows-Auto-Login-Tool.ps1

# May require execution policy adjustment
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Architecture

### Core Functionality Flow

1. **Startup Menu**: Three-option PSDialog menu (Enable Auto-Login, Disable Auto-Login, Cancel)
2. **Domain Detection**: Automatically detects domain vs local computer name
3. **Registry Management**: Modifies Windows registry to enable/disable auto-login
4. **Logging Framework**: Verbose logging to structured log directory for troubleshooting

### Registry Operations

The tool manipulates Windows auto-login registry keys under:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Key registry values managed:
- `AutoAdminLogon` (enable/disable flag)
- `DefaultUserName` (username)
- `DefaultPassword` (password - handle with security considerations)
- `DefaultDomainName` (domain or computer name)

### User Workflows

**Enable Auto-Login:**
1. Detect domain/computer name
2. Display PSDialog form with pre-filled domain, username/password input boxes
3. Validate and write registry keys
4. Show success/failure dialog with log path on failure

**Disable Auto-Login:**
1. Scan for existing auto-login registry keys
2. Remove or clear registry values
3. Display success/failure status dialog

## Development Considerations

### Security Requirements
- Handle password storage in registry appropriately (LSA secrets or registry with ACLs)
- Clear sensitive data from memory after use
- Validate all user input to prevent registry corruption
- Log operations without exposing passwords in plaintext

### Domain Handling
- Gracefully detect domain membership status (joined, not joined, configured but disconnected)
- Support both domain users (DOMAIN\username) and local users (.\username or COMPUTERNAME\username)
- Handle domain override field for edge cases

### PSDialog Interface Requirements
- All dialogs must use PSDialog components (menu, inputbox, msgbox, etc.)
- Interface must work in CLI-only PowerShell sessions
- No WinForms, WPF, or graphical window dependencies
- Maintain consistent terminal-based UI resembling Linux dialog tools

### Error Handling
- Validate registry write operations succeed
- Provide detailed failure messages with log file paths
- Handle insufficient permissions gracefully (requires admin rights)
- Robust against malformed input or partial domain membership

## Project Status

The `Windows-Auto-Login-Tool.ps1` file is currently a placeholder. Implementation is needed following the specifications in `goal.txt`.
