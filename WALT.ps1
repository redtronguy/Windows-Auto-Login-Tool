<#
.SYNOPSIS
    Windows Auto-Login Tool (WALT) - Manage secure domain auto-login settings.
.DESCRIPTION
    Provides a menu-driven workflow to enable or disable Windows auto-login while
    enforcing logging, admin elevation, credential validation, and compatibility checks.
.NOTES
    Execute from an elevated PowerShell session. Logs are stored under .\logs.
#>

[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
$script:LogFilePath = $null
$script:WinlogonRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

function Initialize-Logging {
    if (-not (Test-Path -Path $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $script:LogFilePath = Join-Path -Path $script:LogDirectory -ChildPath "$timestamp.log"
    try {
        Start-Transcript -Path $script:LogFilePath -Append | Out-Null
        Write-LogInfo "Logging initialized at $script:LogFilePath"
    }
    catch {
        Write-Warning "Failed to start transcript logging: $_"
    }
}

function Stop-Logging {
    if (-not $script:LogFilePath) {
        return
    }

    try {
        Stop-Transcript | Out-Null
    }
    catch {
        Write-Warning "Failed to stop transcript: $_"
    }
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$Color = 'Gray'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp][$Level] $Message" -ForegroundColor $Color
}

function Write-LogInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-LogMessage -Level 'INFO' -Message $Message -Color 'Cyan'
}

function Write-LogWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-LogMessage -Level 'WARN' -Message $Message -Color 'Yellow'
}

function Write-LogError {
    param([Parameter(Mandatory)][string]$Message)
    Write-LogMessage -Level 'ERROR' -Message $Message -Color 'Red'
}

function Write-LogSuccess {
    param([Parameter(Mandatory)][string]$Message)
    Write-LogMessage -Level 'SUCCESS' -Message $Message -Color 'Green'
}

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-Administrator {
    if (Test-IsAdministrator) {
        return
    }

    Write-LogWarning 'Administrator privileges are required. Attempting self-elevation...'
    $quotedScript = '"' + $PSCommandPath + '"'
    $arguments = "-ExecutionPolicy Bypass -File $quotedScript"
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -WindowStyle Normal | Out-Null
        Write-LogInfo 'Elevated process started. Exiting current session.'
    }
    catch {
        Write-LogError "Elevation request failed: $_"
    }
    finally {
        Stop-Logging
        exit
    }
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord')][string]$Type = 'String'
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -Force -PropertyType $Type | Out-Null
    $verify = Get-RegistryValue -Path $Path -Name $Name
    if ($verify -ne $Value) {
        throw "Failed to set registry value $Name."
    }
}

function Remove-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        Write-LogInfo "Removed registry value $Name."
    }
    catch {
        Write-LogWarning "Value $Name not present or could not be removed: $_"
    }
}

function Get-ComputerDomainInfo {
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        return [pscustomobject]@{
            Name           = $system.Name
            Domain         = $system.Domain
            DomainRole     = $system.DomainRole
            IsDomainJoined = $system.PartOfDomain
        }
    }
    catch {
        Write-LogWarning "Unable to read computer information: $_"
        return [pscustomobject]@{
            Name           = $env:COMPUTERNAME
            Domain         = ''
            DomainRole     = -1
            IsDomainJoined = $false
        }
    }
}

function Get-DefaultDomainName {
    param([Parameter(Mandatory)]$DomainInfo)

    if ($DomainInfo.IsDomainJoined -and -not [string]::IsNullOrWhiteSpace($DomainInfo.Domain)) {
        return $DomainInfo.Domain
    }

    return $DomainInfo.Name
}

function Read-ValidatedInput {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter()][scriptblock]$ValidationScript,
        [string]$ErrorMessage = 'Invalid input.',
        [switch]$AllowEmpty
    )

    while ($true) {
        $value = Read-Host -Prompt $Prompt
        if ([string]::IsNullOrWhiteSpace($value) -and $AllowEmpty) {
            return ''
        }

        if (-not $ValidationScript) {
            return $value
        }

        if (& $ValidationScript $value) {
            return $value
        }

        Write-LogWarning $ErrorMessage
    }
}

function Test-Username {
    param([Parameter(Mandatory)][string]$InputValue)

    if ([string]::IsNullOrWhiteSpace($InputValue)) {
        return $false
    }

    if ($InputValue -match '[\\/:*?"<>|]') {
        return $false
    }

    return $true
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Test-Credentials {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][System.Security.SecureString]$Password,
        [Parameter(Mandatory)][string]$Domain
    )

    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $contextType = if ($Domain -eq $env:COMPUTERNAME -or [string]::IsNullOrWhiteSpace($Domain)) {
            'Machine'
        }
        else {
            'Domain'
        }

        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::$contextType,
            $Domain
        )
        $plainPassword = Convert-SecureStringToPlainText -SecureString $Password
        try {
            return $principalContext.ValidateCredentials($UserName, $plainPassword)
        }
        finally {
            $plainPassword = $null
            $principalContext.Dispose()
        }
    }
    catch {
        Write-LogWarning "Credential validation failed: $_"
        return $false
    }
}

function Test-AutoLoginCompatibility {
    $results = @()

    $results += [pscustomobject]@{
        Check    = 'Administrator privileges'
        Passed   = Test-IsAdministrator
        Severity = 'Error'
        Details  = 'Script must run elevated to update HKLM.'
    }

    $winlogonPathExists = Test-Path -Path $script:WinlogonRegistryPath
    $results += [pscustomobject]@{
        Check    = 'Winlogon registry path'
        Passed   = $winlogonPathExists
        Severity = 'Error'
        Details  = if ($winlogonPathExists) { 'Registry path found.' } else { 'HKLM:\...\Winlogon missing or inaccessible.' }
    }

    $domainInfo = Get-ComputerDomainInfo
    $results += [pscustomobject]@{
        Check    = 'Domain membership'
        Passed   = $true
        Severity = 'Warning'
        Details  = if ($domainInfo.IsDomainJoined) { "Joined to $($domainInfo.Domain)." } else { 'Not domain joined. Local accounts only.' }
    }

    return $results
}

function Show-CompatibilityReport {
    param([Parameter(Mandatory)]$CompatibilityResults)

    Write-Host ''
    Write-Host 'Compatibility Report' -ForegroundColor White
    Write-Host '--------------------'
    foreach ($result in $CompatibilityResults) {
        $color = if ($result.Passed) { 'Green' } elseif ($result.Severity -eq 'Warning') { 'Yellow' } else { 'Red' }
        $status = if ($result.Passed) { 'PASS' } else { 'FAIL' }
        Write-Host ("[{0}] {1}: {2}" -f $status, $result.Check, $result.Details) -ForegroundColor $color
    }
    Write-Host ''
}

function Get-AutoLoginStatus {
    $autoLogon = Get-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoAdminLogon'
    return [pscustomobject]@{
        Enabled  = $autoLogon -eq '1'
        UserName = (Get-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultUserName')
        Domain   = (Get-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultDomainName')
    }
}

function Show-AutoLoginStatus {
    param([Parameter()]$Status = (Get-AutoLoginStatus))

    $user = if ([string]::IsNullOrWhiteSpace($Status.UserName)) { '<not set>' } else { $Status.UserName }
    $domain = if ([string]::IsNullOrWhiteSpace($Status.Domain)) { '<not set>' } else { $Status.Domain }

    Write-Host ''
    Write-Host 'Auto-Login Status' -ForegroundColor White
    Write-Host '-----------------'
    Write-Host ("Enabled : {0}" -f $Status.Enabled)
    Write-Host ("User    : {0}" -f $user)
    Write-Host ("Domain  : {0}" -f $domain)
    Write-Host ''
}

function Disable-AutoLoginSecure {
    Write-LogInfo 'Disabling auto-login...'

    Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoAdminLogon' -Value '0'
    Remove-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultPassword'
    Remove-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoLogonCount'
    Remove-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoLogonChecked'

    $status = Get-AutoLoginStatus
    if ($status.Enabled) {
        throw 'Auto-login disable verification failed.'
    }

    Write-LogSuccess 'Auto-login disabled successfully.'
    Show-AutoLoginStatus -Status $status
}

function Enable-AutoLoginSecure {
    $domainInfo = Get-ComputerDomainInfo
    $defaultDomain = Get-DefaultDomainName -DomainInfo $domainInfo
    $compatibility = Test-AutoLoginCompatibility
    Show-CompatibilityReport -CompatibilityResults $compatibility

    $criticalFailures = $compatibility | Where-Object { -not $_.Passed -and $_.Severity -eq 'Error' }
    if ($criticalFailures) {
        throw 'Resolve the failed compatibility checks before enabling auto-login.'
    }

    $confirmation = Read-Host 'Proceed with enabling auto-login? (Y/N)'
    if ($confirmation -notin @('Y','y','Yes','YES')) {
        Write-LogInfo 'Enable request canceled by user.'
        return
    }

    $userName = Read-ValidatedInput -Prompt 'Enter the username for auto-login' -ValidationScript { param($value) Test-Username -InputValue $value } -ErrorMessage 'Usernames cannot be blank or contain invalid characters.'
    $domainPrompt = "Enter the domain for auto-login [$defaultDomain]"
    $domainInput = Read-Host -Prompt $domainPrompt
    $domainName = if ([string]::IsNullOrWhiteSpace($domainInput)) { $defaultDomain } else { $domainInput }

    $maxAttempts = 3
    $validated = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $password = Read-Host -Prompt 'Enter the password for auto-login' -AsSecureString
        if (Test-Credentials -UserName $userName -Password $password -Domain $domainName) {
            $plainPassword = Convert-SecureStringToPlainText -SecureString $password
            try {
                Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoAdminLogon' -Value '1'
                Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultUserName' -Value $userName
                Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultPassword' -Value $plainPassword
                Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'DefaultDomainName' -Value $domainName
                Set-RegistryValue -Path $script:WinlogonRegistryPath -Name 'AutoLogonCount' -Value 1 -Type 'DWord'
            }
            finally {
                $plainPassword = $null
            }

            $status = Get-AutoLoginStatus
            if (-not $status.Enabled) {
                throw 'Auto-login enable verification failed.'
            }

            Write-LogSuccess 'Auto-login enabled successfully.'
            Show-AutoLoginStatus -Status $status
            $validated = $true
            break
        }

        Write-LogWarning "Credential validation failed (attempt $attempt/$maxAttempts)."
    }

    if (-not $validated) {
        throw 'Failed to validate credentials. Auto-login not enabled.'
    }
}

function Show-WelcomeScreen {
    Clear-Host
    Write-Host '=============================================' -ForegroundColor White
    Write-Host ' Windows Auto-Login Management Tool (WALT) ' -ForegroundColor White
    Write-Host '=============================================' -ForegroundColor White
    Write-Host 'Warning: Enabling auto-login stores credentials in plaintext' -ForegroundColor Yellow
    Write-Host 'within the Windows registry. Only proceed on secured devices.' -ForegroundColor Yellow
    Write-Host ''
}

function Show-MainMenu {
    Write-Host 'Select an option:'
    Write-Host '  1. Enable Auto-Login'
    Write-Host '  2. Disable Auto-Login'
    Write-Host '  3. Show Current Status'
    Write-Host '  4. Exit'
    Write-Host ''
}

Initialize-Logging
Ensure-Administrator

try {
    Show-WelcomeScreen
    while ($true) {
        Show-MainMenu
        $choice = Read-Host 'Enter selection (1-4)'
        switch ($choice) {
            '1' {
                try {
                    Enable-AutoLoginSecure
                }
                catch {
                    Write-LogError $_
                }
            }
            '2' {
                try {
                    Disable-AutoLoginSecure
                }
                catch {
                    Write-LogError $_
                }
            }
            '3' {
                Show-AutoLoginStatus
            }
            '4' {
                Write-LogInfo 'Exiting tool.'
                break
            }
            default {
                Write-LogWarning 'Invalid menu selection.'
            }
        }

        if ($choice -eq '4') {
            break
        }

        [void] (Read-Host 'Press Enter to return to the main menu')
        Show-WelcomeScreen
    }
}
finally {
    Stop-Logging
}
