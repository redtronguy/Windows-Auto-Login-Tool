
function Start-Log {
    $logDir = ".\logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir
    }
    $logFile = "$logDir\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    Start-Transcript -Path $logFile
}

function Stop-Log {
    Stop-Transcript
}

function Enable-AutoLogin {
    Start-Log
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $computerInfo = Get-ComputerInfo
    $domainName = $computerInfo.Domain
    if ($domainName -eq $null) {
        $domainName = $computerInfo.CsName
    }

    Write-Host "Current domain or computer name: $domainName"
    $username = Read-Host "Please enter your username"
    $password = Read-Host "Please enter your password" -AsSecureString

    try {
        Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value "1" -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value ($password | ConvertFrom-SecureString -AsPlainText) -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name "DefaultDomainName" -Value $domainName -ErrorAction Stop
        Write-Host "Auto-login enabled successfully."
    }
    catch {
        Write-Host "Error enabling auto-login: $_"
    }
    Read-Host "Press Enter to continue"
    Stop-Log
}

function Disable-AutoLogin {
    Start-Log
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try {
        Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value "0" -ErrorAction Stop
        Write-Host "Auto-login disabled successfully."
        # Clear the password
        Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value "" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Error disabling auto-login: $_"
    }
    Read-Host "Press Enter to continue"
    Stop-Log
}

# Main Menu
function Show-MainMenu {
    Clear-Host
    Write-Host "========================================"
    Write-Host "  Windows Auto-Login Management Tool"
    Write-Host "========================================"
    Write-Host
    Write-Host "  1. Enable Auto-Login"
    Write-Host "  2. Disable Auto-Login"
    Write-Host "  3. Cancel"
    Write-Host
}

while ($true) {
    Show-MainMenu
    $selection = Read-Host "Please enter your selection"

    switch ($selection) {
        "1" {
            # Enable Auto-Login
            Enable-AutoLogin
            break
        }
        "2" {
            # Disable Auto-Login
            Disable-AutoLogin
            break
        }
        "3" {
            # Cancel
            Write-Host "Exiting..."
            exit
        }
        default {
            Write-Host "Invalid selection. Please try again."
            Read-Host "Press Enter to continue"
        }
    }
}