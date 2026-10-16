#Requires -Version 5.1
<#
  muse-bootstrap.ps1 - one-line bootstrap for a new Muse outpost (Windows 10/11 Pro+)
  Run in PowerShell:   irm https://cdn.jsdelivr.net/gh/hookjk100/muse-bootstrap@main/bootstrap.ps1 | iex
  What it does:
    1. Installs OpenSSH Server, authorizes Muse's public key (admin SSH access)
    2. Generates THIS machine's own tunnel keypair (the private key never leaves this box)
    3. Enrolls the tunnel public key with a one-time 6-char device code (15-min TTL)
       and waits until Muse claims the code and assigns this machine its reverse port
    4. Registers the MuseTunnel scheduled task (SYSTEM, at startup, 10s reconnect loop)
    5. Enables Remote Desktop + scoped firewall rules (3389: Tailscale range + LAN only)
    6. Offers a reboot (RDP listener only comes up after a full boot - learned the hard way)
  The script is intentionally ASCII-only so it survives any console code page.
#>

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}

# ---------------- constants ----------------
$MusePubKey  = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDh6EaZoY20pGyEu6Y7ce25Mdz9Cxz1q9TvjTNZT+6x muse'
$VpsHost     = '103.216.162.252'
$EnrollBase  = 'http://103.216.162.252:8909'
$SelfUrl     = 'https://cdn.jsdelivr.net/gh/hookjk100/muse-bootstrap@main/bootstrap.ps1'
$SshDir      = 'C:\ProgramData\ssh'
$KeyPath     = Join-Path $SshDir 'muse_tunnel_key'
$TunnelCmd   = Join-Path $SshDir 'muse-tunnel.cmd'
$LogPath     = Join-Path $SshDir 'muse-bootstrap.log'
$Alphabet    = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'   # no I/L/O/0/1 - read-aloud safe
$Words       = @('anchor','apple','arrow','banana','beach','bird','breeze','bridge',
                 'candle','cloud','coffee','coral','desert','dolphin','eagle','ember',
                 'falcon','forest','garden','harbor','island','jungle','ladder','lemon',
                 'maple','marble','meadow','melon','ocean','panda','rocket','sunset')

function Log([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding ASCII } catch {}
}
function StepOk([string]$name)   { Log "  OK   $name" }
function StepFail([string]$name, [string]$why) { Log "  FAIL $name - $why"; $script:Failures += $name }
$script:Failures = @()

# ---------------- 0. elevation ----------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Not elevated - relaunching as administrator (approve the UAC prompt)...'
    $self = $PSCommandPath
    if (-not $self) {
        $self = Join-Path $env:TEMP 'muse-bootstrap.ps1'
        Invoke-WebRequest -Uri $SelfUrl -OutFile $self -UseBasicParsing
    }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$self`"")
    return
}
New-Item -ItemType Directory -Path $SshDir -Force | Out-Null
Log "=== muse-bootstrap on $env:COMPUTERNAME ==="

# ---------------- 1. OpenSSH server + client ----------------
try {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
    }
    StepOk 'OpenSSH Server capability'
} catch { StepFail 'OpenSSH Server capability' $_.Exception.Message }

$SshExe     = "$env:WINDIR\System32\OpenSSH\ssh.exe"
$SshKeygen  = "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe"
if (-not (Test-Path $SshExe)) {
    try { Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' | Out-Null; StepOk 'OpenSSH Client capability' }
    catch { StepFail 'OpenSSH Client capability' $_.Exception.Message }
}

try {
    Start-Service sshd -ErrorAction Stop
    Set-Service sshd -StartupType Automatic
    StepOk 'sshd running, startup=Automatic'
} catch { StepFail 'sshd service' $_.Exception.Message }

# ---------------- 2. authorize Muse's key ----------------
try {
    $authFile = Join-Path $SshDir 'administrators_authorized_keys'
    $existing = ''
    if (Test-Path $authFile) { $existing = Get-Content $authFile -Raw }
    if ($existing -notmatch [regex]::Escape(($MusePubKey -split ' ')[1])) {
        Add-Content -Path $authFile -Value $MusePubKey -Encoding ASCII
    }
    & icacls $authFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    StepOk 'administrators_authorized_keys (Muse key + ACL)'
} catch { StepFail 'authorized_keys' $_.Exception.Message }

# ---------------- 3. this machine's tunnel keypair ----------------
try {
    if (-not (Test-Path $KeyPath)) {
        & $SshKeygen -t ed25519 -f $KeyPath -N '' -C "muse-$env:COMPUTERNAME" | Out-Null
    }
    StepOk 'tunnel keypair (private key stays on this machine)'
} catch { StepFail 'tunnel keypair' $_.Exception.Message }
$pubKeyLine = (Get-Content "$KeyPath.pub" -Raw).Trim()

# fingerprint words (same derivation on Muse's side - see runbook)
function Get-Words([string]$pubLine) {
    $blob = [Convert]::FromBase64String(($pubLine -split ' ')[1])
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($blob)
    return (($sha[0..2] | ForEach-Object { $Words[$_ % 32] }) -join ' ')
}
$fingerprintWords = Get-Words $pubKeyLine

function New-Code {
    $bytes = New-Object byte[] 6
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return (-join ($bytes | ForEach-Object { $Alphabet[$_ % $Alphabet.Length] }))
}

# ---------------- 4+5. enroll, then poll for the assigned port ----------------
$port = $null
$code = $null
$regen = 0
while (-not $port -and $regen -lt 3) {
    $code = New-Code
    try {
        $body = @{ code = $code; pubkey = $pubKeyLine; hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
        Invoke-RestMethod -Method Post -Uri "$EnrollBase/enroll" -Body $body -ContentType 'application/json' -TimeoutSec 25 | Out-Null
    } catch {
        StepFail 'enroll POST' $_.Exception.Message
        break
    }
    Write-Host ''
    Write-Host '  ============================================================'
    Write-Host "    DEVICE CODE:  $($code.Substring(0,3))-$($code.Substring(3,3))"
    Write-Host '    Send this code to Muse. Waiting for Muse to claim it...'
    Write-Host "    Fingerprint words (Muse will show you the same): $fingerprintWords"
    Write-Host '  ============================================================'
    Write-Host ''
    for ($i = 0; $i -lt 40 -and -not $port; $i++) {
        Start-Sleep -Seconds 15
        try {
            $r = Invoke-RestMethod -Method Get -Uri "$EnrollBase/assignment?code=$code" -TimeoutSec 20
            if ($r.status -eq 'assigned') { $port = [int]$r.port }
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
                Log '  Device code expired - generating a fresh one.'
                break   # outer while regenerates
            }
        }
        if (($i % 4) -eq 3) { Log "  still waiting for Muse to claim $($code.Substring(0,3))-$($code.Substring(3,3)) ..." }
    }
    $regen++
}
if (-not $port) {
    Log 'Enrollment did not complete. Re-run the script to get a fresh device code.'
    return
}
StepOk "claimed by Muse - reverse port $port"

# ---------------- 6. tunnel task ----------------
try {
    $cmdText = @"
@echo off
:loop
"$SshExe" -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SshDir\known_hosts_tunnel -i $KeyPath -R 127.0.0.1:${port}:127.0.0.1:22 root@$VpsHost
timeout /t 10 /nobreak >nul
goto loop
"@
    Set-Content -Path $TunnelCmd -Value $cmdText -Encoding ASCII
    $action    = New-ScheduledTaskAction -Execute $TunnelCmd
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'MuseTunnel' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName 'MuseTunnel'
    StepOk 'MuseTunnel task registered and started'
} catch { StepFail 'MuseTunnel task' $_.Exception.Message }

# ---------------- 7. Remote Desktop + scoped firewall ----------------
try {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0 -Type DWord
    Set-ItemProperty -Path $ts -Name StartRCM -Value 1 -Type DWord
    Set-ItemProperty -Path $ts -Name TSUserEnabled -Value 1 -Type DWord
    StepOk 'RDP enabled (takes effect after the reboot below)'
} catch { StepFail 'RDP registry' $_.Exception.Message }

try {
    $scope = @('100.64.0.0/10', '192.168.0.0/16')
    if (-not (Get-NetFirewallRule -DisplayName 'RemoteDesktop-TCP (Muse)' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'RemoteDesktop-TCP (Muse)' -Direction Inbound -Protocol TCP -LocalPort 3389 `
            -Action Allow -Profile Any -RemoteAddress $scope | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName 'RemoteDesktop-UDP (Muse)' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'RemoteDesktop-UDP (Muse)' -Direction Inbound -Protocol UDP -LocalPort 3389 `
            -Action Allow -Profile Any -RemoteAddress $scope | Out-Null
    }
    Get-NetFirewallRule -Name 'RemoteDesktop-*-In-*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    StepOk 'firewall: profiles on, 3389 scoped to Tailscale + LAN'
} catch { StepFail 'firewall template' $_.Exception.Message }

# ---------------- summary + reboot ----------------
Write-Host ''
Log '================ SUMMARY ================'
Log "  Machine        : $env:COMPUTERNAME"
Log "  Device code    : $($code.Substring(0,3))-$($code.Substring(3,3))"
Log "  Reverse port   : $port (via $VpsHost)"
Log "  Fingerprint    : $fingerprintWords"
Log "  Log file       : $LogPath"
if ($script:Failures.Count -gt 0) { Log "  Steps to check : $($script:Failures -join ', ')" }
Log '  SSH + tunnel are live NOW. Remote Desktop needs ONE reboot.'
Write-Host ''
try {
    $ans = Read-Host 'Reboot now to finish? [Y/n]'
    if ($ans -eq '' -or $ans -match '^[Yy]') {
        Log 'Rebooting in 5 seconds...'
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    } else {
        Log 'Skipped reboot - remember: RDP will not listen until this machine reboots once.'
    }
} catch {
    Log 'Non-interactive session - reboot skipped. Please reboot once to finish (RDP).'
}
