#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Update hardening for endpoints: Microsoft Update, expedited restart, metered downloads,
    restart notification, automatic active hours, update notifications re-enabled, enforced restart.

.DESCRIPTION
    Designed to run with no parameters (download, run, done):

        curl.exe -fsSL <raw-url>/Harden-WindowsUpdate.ps1 -o $env:TEMP\Harden-WindowsUpdate.ps1
        powershell -ExecutionPolicy Bypass -File $env:TEMP\Harden-WindowsUpdate.ps1

    Default behavior: self-elevate (UAC prompt if needed), apply, verify, then restart the computer
    immediately once the script finishes (running applications are closed without warning, unsaved
    work is lost). Use -NoRestart to skip the restart.

    Applied settings (one table drives both apply and verify, so they cannot drift):
      1. Receive updates for other Microsoft products : enabled (registry + Microsoft Update registration)
      2. Get me up to date                            : enabled (IsExpedited, restart ASAP after install)
      3. Download updates over metered connections    : enabled
      4. Notify me when a restart is required         : enabled
      5. Active hours                                 : automatic, manual policy removed
      N. Update notifications                         : policy suppression removed (HKLM) and, for every
         user profile on the machine, toast notifications that the user turned off are turned back on
         (global toasts, Windows Update / Update Orchestrator, Security and Maintenance).
      E. Enforcement                                  : compliance deadlines with auto-restart, blockers removed
         (NoAutoUpdate, NoAutoRebootWithLoggedOnUsers, Windows Update access disabled).

      A. Automatic install                            : AUOptions=4 (auto download and scheduled install), every day
         at -InstallHour (default 22:00, outside working hours).

    Not touched: Focus assist / Do Not Disturb state.

.PARAMETER NoRestart
    Do not restart after the run. Without this switch the computer restarts when every item passes.

.PARAMETER RestartDelaySeconds
    Countdown before the restart (0-3600). Default 0 (restart immediately). A value above 0 can be
    cancelled during the countdown with: shutdown /a

.PARAMETER QualityDeadlineDays
    Days from update offer to forced install for quality updates (0-30). Default 2.

.PARAMETER FeatureDeadlineDays
    Days from update offer to forced install for feature updates (0-30). Default 7.

.PARAMETER GracePeriodDays
    Days after the deadline before the forced restart (0-7). Default 1.

.PARAMETER EnableLatestUpdates
    Also enables "Get the latest updates as soon as they're available" (non-security preview updates).

.PARAMETER SkipDeadlines
    Skip the compliance deadline policies.

.PARAMETER InstallHour
    Hour of day (0-23, local time) when scheduled automatic install runs. Default 22 (22:00).
    Pick an hour outside working hours. Applies every day.

.PARAMETER WakeToInstall
    Also lets Windows Update wake the computer from sleep to install scheduled updates (AUPowerManagement).
    Off by default because it changes power behavior.

.PARAMETER VerifyOnly
    Only read and report the current state. Changes nothing, never restarts.

.PARAMETER BackupPath
    Folder for the registry backup and the log. Default C:\ProgramData\WinUpdateHardening.

.PARAMETER Relaunched
    Internal. Set by the script when it re-runs itself elevated.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden-WindowsUpdate.ps1 -WhatIf
    Preview all changes without applying them.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden-WindowsUpdate.ps1
    Apply, verify, restart immediately.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden-WindowsUpdate.ps1 -NoRestart
    Apply and verify without restarting.

.NOTES
    Version : v2.2
    Exit    : 0 all items compliant, 1 one or more items non-compliant, 2 not elevated / elevation declined

    Change history
    | Version | Date       | Description |
    |---------|------------|-------------|
    | 1.0     | 2026-11-18 | Initial release |
    | 1.1     | 2026-11-18 | Add -Restart and -RestartDelaySeconds |
    | 2.0     | 2026-11-18 | Restart is now the default (-NoRestart to skip); self-elevation for curl-and-run use; re-enable suppressed update notifications for all user profiles |
    | 2.1     | 2026-11-18 | Restart immediately after the script finishes (default delay 0, forced); restart is issued after the log is closed |
    | 2.2     | 2026-11-18 | Add automatic download and scheduled install outside working hours (AUOptions=4, -InstallHour, optional -WakeToInstall) |
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$NoRestart,
    [ValidateRange(0, 3600)][int]$RestartDelaySeconds = 0,
    [ValidateRange(0, 30)][int]$QualityDeadlineDays = 2,
    [ValidateRange(0, 30)][int]$FeatureDeadlineDays = 7,
    [ValidateRange(0, 7)][int]$GracePeriodDays = 1,
    [switch]$EnableLatestUpdates,
    [ValidateRange(0, 23)][int]$InstallHour = 22,
    [switch]$WakeToInstall,
    [switch]$SkipDeadlines,
    [switch]$VerifyOnly,
    [string]$BackupPath = (Join-Path $env:ProgramData 'WinUpdateHardening'),
    [switch]$Relaunched
)

$ErrorActionPreference = 'Stop'
$script:exitCode = $null
$script:restartScheduled = $false

# ---------------------------------------------------------------- elevation (self-relaunch)
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $PSCommandPath) {
        Write-Error 'Save the script to a file and run it with -File (it cannot self-elevate from a pipe).'
        exit 2
    }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) {
            if ($kv.Value.IsPresent) { $argList += "-$($kv.Key)" }
        } else {
            $argList += "-$($kv.Key)"
            $argList += "`"$($kv.Value)`""
        }
    }
    $argList += '-Relaunched'
    Write-Host 'Administrator rights are required. Approve the UAC prompt to continue.'
    try {
        $proc = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argList -Verb RunAs -Wait -PassThru
        exit $proc.ExitCode
    } catch {
        Write-Error "Elevation failed or was declined: $($_.Exception.Message)"
        exit 2
    }
}

# ---------------------------------------------------------------- paths
$UX = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$WU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$AU = "$WU\AU"
$PolPush     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
$PolExplorer = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
$MU_SERVICE_ID = '7971f918-a847-4430-9279-4a52d1efe18d'

# Per-user notification entries (subkey names under ...\Notifications\Settings) treated as update related
$NotifPatterns = @('*MusNotification*', '*WindowsUpdate*', '*SecurityAndMaintenance*', 'Windows.SystemToast.Update*')

# ---------------------------------------------------------------- machine setting table
$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param([string]$Req, [string]$Path, [string]$Name, $Value, [string]$Action = 'Set')
    $script:checks.Add([pscustomobject]@{
        Req = $Req; Path = $Path; Name = $Name; Value = $Value; Action = $Action
    })
}

# 1. Receive updates for other Microsoft products
Add-Check '1 Other MS products' $UX 'AllowMUUpdateService' 1
Add-Check '1 Other MS products' $WU 'AllowMUUpdateService' 1

# 2. Get me up to date (restart as soon as possible after install)
Add-Check '2 Get me up to date' $UX 'IsExpedited' 1
if ($EnableLatestUpdates) {
    Add-Check '2b Latest updates ASAP' $UX 'IsContinuousInnovationOptedIn' 1
    Add-Check '2b Latest updates ASAP' $WU 'SetAllowOptionalContent' 1
    Add-Check '2b Latest updates ASAP' $WU 'AllowOptionalContent' 1
}

# 3. Download updates over metered connections
Add-Check '3 Metered download' $UX 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork' 1

# 4. Notify when a restart is required
Add-Check '4 Restart notification' $UX 'RestartNotificationsAllowed2' 1
Add-Check '4 Restart notification' $AU 'SetAutoRestartNotificationDisable' 0

# 5. Active hours: automatic (a manual policy would override it, so remove it)
Add-Check '5 Active hours auto' $UX 'SmartActiveHoursState' 1
Add-Check '5 Active hours auto' $WU 'SetActiveHours'   $null 'Remove'
Add-Check '5 Active hours auto' $WU 'ActiveHoursStart' $null 'Remove'
Add-Check '5 Active hours auto' $WU 'ActiveHoursEnd'   $null 'Remove'

# A. Automatic download and scheduled install outside working hours
#    AUOptions 4 = auto download and schedule the install; ScheduledInstallDay 0 = every day
Add-Check 'A Auto install' $AU 'NoAutoUpdate' 0
Add-Check 'A Auto install' $AU 'AUOptions' 4
Add-Check 'A Auto install' $AU 'ScheduledInstallDay' 0
Add-Check 'A Auto install' $AU 'ScheduledInstallTime' $InstallHour
if ($WakeToInstall) {
    Add-Check 'A Auto install' $AU 'AUPowerManagement' 1
}

# N. Update notifications: remove machine-wide suppression
Add-Check 'N Notifications' $WU 'SetUpdateNotificationLevel' $null 'Remove'
Add-Check 'N Notifications' $WU 'UpdateNotificationLevel'    $null 'Remove'
Add-Check 'N Notifications' $PolPush 'NoToastApplicationNotification' $null 'Remove'
Add-Check 'N Notifications' $PolExplorer 'DisableNotificationCenter'  $null 'Remove'

# E. Enforcement: remove blockers
Add-Check 'E Blocker removal' $AU 'NoAutoUpdate' 0
Add-Check 'E Blocker removal' $AU 'NoAutoRebootWithLoggedOnUsers' 0
Add-Check 'E Blocker removal' $WU 'SetDisableUXWUAccess' 0
Add-Check 'E Blocker removal' $WU 'DisableWindowsUpdateAccess' 0

# E. Enforcement: deadlines and auto-restart
if (-not $SkipDeadlines) {
    Add-Check 'E Deadlines' $WU 'SetComplianceDeadline' 1
    Add-Check 'E Deadlines' $WU 'ConfigureDeadlineForQualityUpdates' $QualityDeadlineDays
    Add-Check 'E Deadlines' $WU 'ConfigureDeadlineForFeatureUpdates' $FeatureDeadlineDays
    Add-Check 'E Deadlines' $WU 'ConfigureDeadlineGracePeriod' $GracePeriodDays
    Add-Check 'E Deadlines' $WU 'ConfigureDeadlineGracePeriodForFeatureUpdates' $GracePeriodDays
    Add-Check 'E Deadlines' $WU 'ConfigureDeadlineNoAutoReboot' 0
}

# ---------------------------------------------------------------- helpers
function Get-RegValue {
    param([string]$Path, [string]$Name)
    $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return $p.$Name
}

function Test-MicrosoftUpdateRegistered {
    try {
        $sm  = New-Object -ComObject Microsoft.Update.ServiceManager
        $svc = $sm.Services | Where-Object { $_.ServiceID -eq $MU_SERVICE_ID }
        return [bool]($svc -and $svc.IsRegisteredWithAU)
    } catch { return $false }
}

function Register-MicrosoftUpdate {
    # flags 7 = AllowPendingRegistration (1) + AllowOnlineRegistration (2) + RegisterServiceWithAU (4)
    $sm = New-Object -ComObject Microsoft.Update.ServiceManager
    $sm.ClientApplicationID = 'Harden-WindowsUpdate'
    [void]$sm.AddService2($MU_SERVICE_ID, 7, '')
}

# Returns the notification suppressions found in one user hive. Fix = Set (value must become 1) or Remove (policy value).
function Get-NotificationSuppressions {
    param([string]$Root)
    $hits = New-Object System.Collections.Generic.List[object]
    $push = "$Root\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    $noc  = "$Root\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

    $mustBeOne = New-Object System.Collections.Generic.List[object]
    $mustBeOne.Add(@{ Path = $push; Name = 'ToastEnabled' })
    $mustBeOne.Add(@{ Path = $noc;  Name = 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' })
    if (Test-Path -LiteralPath $noc) {
        foreach ($k in (Get-ChildItem -LiteralPath $noc -ErrorAction SilentlyContinue)) {
            $match = $false
            foreach ($pat in $NotifPatterns) { if ($k.PSChildName -like $pat) { $match = $true; break } }
            if ($match) {
                foreach ($n in 'Enabled', 'ShowInActionCenter', 'ShowBanner') {
                    $mustBeOne.Add(@{ Path = $k.PSPath; Name = $n })
                }
            }
        }
    }
    foreach ($t in $mustBeOne) {
        $v = Get-RegValue $t.Path $t.Name
        if ($null -ne $v -and "$v" -eq '0') {
            $hits.Add([pscustomobject]@{ Path = $t.Path; Name = $t.Name; Fix = 'Set' })
        }
    }

    $policyValues = @(
        @{ Path = "$Root\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name = 'NoToastApplicationNotification' },
        @{ Path = "$Root\Software\Policies\Microsoft\Windows\Explorer"; Name = 'DisableNotificationCenter' }
    )
    foreach ($t in $policyValues) {
        if ($null -ne (Get-RegValue $t.Path $t.Name)) {
            $hits.Add([pscustomobject]@{ Path = $t.Path; Name = $t.Name; Fix = 'Remove' })
        }
    }
    return $hits.ToArray()
}

# Runs $Action once per local user profile hive (loaded ones directly, offline ones via reg load/unload).
function Invoke-ForEachUserHive {
    param([scriptblock]$Action)
    $sidPattern = '^S-1-(5-21|12-1)-[\d-]+$'
    $loadedSids = @()

    foreach ($k in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -match $sidPattern) {
            $loadedSids += $k.PSChildName
            & $Action "Registry::HKEY_USERS\$($k.PSChildName)" $k.PSChildName
        }
    }

    foreach ($p in (Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue)) {
        if ($p.Special -or $p.Loaded) { continue }
        if ($p.SID -notmatch $sidPattern) { continue }
        if ($loadedSids -contains $p.SID) { continue }
        $dat = Join-Path $p.LocalPath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $tmp = "HW_$($p.SID)"
        & reg.exe load "HKU\$tmp" $dat 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not load hive for $($p.SID), skipped."; continue }
        try {
            & $Action "Registry::HKEY_USERS\$tmp" $p.SID
        } finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            & reg.exe unload "HKU\$tmp" 2>&1 | Out-Null
        }
    }
}

# ---------------------------------------------------------------- log + backup
if (-not (Test-Path -LiteralPath $BackupPath)) { New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log   = Join-Path $BackupPath "harden-$($env:COMPUTERNAME)-$stamp.log"
Start-Transcript -Path $log | Out-Null

try {
    Write-Host "Host: $($env:COMPUTERNAME)  OS: $((Get-CimInstance Win32_OperatingSystem).Caption)  Build: $([Environment]::OSVersion.Version)"

    if (-not $VerifyOnly) {
        # Registry backup (skipped silently for keys that do not exist yet)
        foreach ($k in @(
            @{ Reg = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Ps = $WU; Tag = 'policy' },
            @{ Reg = 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings';      Ps = $UX; Tag = 'ux' }
        )) {
            if (Test-Path -LiteralPath $k.Ps) {
                $file = Join-Path $BackupPath "backup-$($k.Tag)-$stamp.reg"
                if ($PSCmdlet.ShouldProcess($k.Reg, "Export backup to $file")) {
                    & reg.exe export $k.Reg $file /y | Out-Null
                }
            }
        }

        # Apply machine registry settings
        foreach ($c in $checks) {
            if ($c.Action -eq 'Set') {
                if ($PSCmdlet.ShouldProcess("$($c.Path)\$($c.Name)", "Set DWORD = $($c.Value)")) {
                    if (-not (Test-Path -LiteralPath $c.Path)) { New-Item -Path $c.Path -Force | Out-Null }
                    New-ItemProperty -LiteralPath $c.Path -Name $c.Name -PropertyType DWord -Value ([int]$c.Value) -Force | Out-Null
                }
            } else {
                if ($null -ne (Get-RegValue $c.Path $c.Name)) {
                    if ($PSCmdlet.ShouldProcess("$($c.Path)\$($c.Name)", 'Remove value')) {
                        Remove-ItemProperty -LiteralPath $c.Path -Name $c.Name -Force
                    }
                }
            }
        }

        # Per-user notifications (every local profile)
        Write-Host 'Checking per-user notification settings...'
        $userAction = {
            param($Root, $Sid)
            foreach ($h in @(Get-NotificationSuppressions $Root)) {
                $old   = Get-RegValue $h.Path $h.Name
                $short = ($h.Path -replace '^.*?Software\\', 'Software\') + '\' + $h.Name
                if ($WhatIfPreference) { Write-Host "[WhatIf] $Sid  $short ($($h.Fix))"; continue }
                try {
                    if ($h.Fix -eq 'Set') { Set-ItemProperty -LiteralPath $h.Path -Name $h.Name -Value 1 -Type DWord }
                    else { Remove-ItemProperty -LiteralPath $h.Path -Name $h.Name -Force }
                    Write-Host "[fixed] $Sid  $short  (was $old)"
                } catch {
                    Write-Warning "Could not fix $short for ${Sid}: $($_.Exception.Message)"
                }
            }
        }
        Invoke-ForEachUserHive -Action $userAction

        # Microsoft Update service registration (setting 1, the part the registry value alone does not do)
        if ($PSCmdlet.ShouldProcess('Microsoft Update service', 'Register with Automatic Updates')) {
            try { Register-MicrosoftUpdate } catch { Write-Warning "Microsoft Update registration failed: $($_.Exception.Message)" }
        }

        # Services must not be disabled, otherwise nothing else matters
        foreach ($svcName in 'wuauserv', 'UsoSvc', 'BITS') {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartMode -eq 'Disabled') {
                if ($PSCmdlet.ShouldProcess($svcName, 'Set startup type Manual (was Disabled)')) {
                    Set-Service -Name $svcName -StartupType Manual
                }
            }
        }
    }

    # ------------------------------------------------------------ verify
    if ($WhatIfPreference) {
        Write-Host 'WhatIf mode: no changes made, verification and restart skipped.'
        return
    }

    $results = foreach ($c in $checks) {
        $actual = Get-RegValue $c.Path $c.Name
        if ($c.Action -eq 'Set') {
            $ok  = ($null -ne $actual) -and ([int]$actual -eq [int]$c.Value)
            $exp = $c.Value
        } else {
            $ok  = ($null -eq $actual)
            $exp = '(absent)'
        }
        [pscustomobject]@{
            Req      = $c.Req
            Value    = ($c.Path -replace '^HKLM:\\SOFTWARE\\(Policies\\)?', '') + '\' + $c.Name
            Expected = $exp
            Actual   = $(if ($null -eq $actual) { '(absent)' } else { $actual })
            Status   = $(if ($ok) { 'PASS' } else { 'FAIL' })
        }
    }

    $muOk = Test-MicrosoftUpdateRegistered
    $results = @($results) + [pscustomobject]@{
        Req = '1 Other MS products'; Value = 'Microsoft Update service registered with AU'
        Expected = 'True'; Actual = $muOk; Status = $(if ($muOk) { 'PASS' } else { 'FAIL' })
    }

    $countAction = { param($Root, $Sid) @(Get-NotificationSuppressions $Root).Count }
    $left = (Invoke-ForEachUserHive -Action $countAction | Measure-Object -Sum).Sum
    if ($null -eq $left) { $left = 0 }
    $results = @($results) + [pscustomobject]@{
        Req = 'N Notifications'; Value = 'Per-user suppressed update notifications (all profiles)'
        Expected = 0; Actual = $left; Status = $(if ($left -eq 0) { 'PASS' } else { 'FAIL' })
    }

    $results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host

    $fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
    Write-Host ("Result: {0} PASS, {1} FAIL. Log: {2}" -f (@($results).Count - $fail), $fail, $log)
    if ($fail -gt 0) {
        Write-Host 'If an item fails right after apply, a GPO/Intune policy is probably overwriting it. Set it there instead.'
    }
    $script:exitCode = $(if ($fail -eq 0) { 0 } else { 1 })

    # Restart is the default after a successful apply
    if (-not $NoRestart -and -not $VerifyOnly) {
        if ($fail -gt 0) {
            Write-Warning 'Restart skipped: one or more items FAILED. Fix them first.'
        } else {
            $script:restartScheduled = $true
            Write-Host 'Restarting now (log is closed first).'
        }
    }
}
finally {
    Stop-Transcript | Out-Null
}

# Restart is issued after the transcript is closed so the log is complete.
# /f forces running applications to close, otherwise an app with unsaved data can block a /t 0 restart.
if ($script:restartScheduled) {
    & shutdown.exe /r /f /t $RestartDelaySeconds /c "Windows Update hardening applied. Restarting to finish." /d p:2:17
} elseif ($Relaunched) {
    # Keep the elevated window readable when the script relaunched itself and no restart follows
    Read-Host 'Press Enter to close' | Out-Null
}
if ($null -ne $script:exitCode) { exit $script:exitCode }
