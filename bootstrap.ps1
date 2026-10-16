#Requires -Version 5.1
<#
  muse-bootstrap.ps1 v2 - one-line bootstrap + node manager for a Muse outpost (Windows 10/11 Pro+)
  Install (PowerShell, as admin):  irm https://cdn.jsdelivr.net/gh/hookjk100/muse-bootstrap@main/bootstrap.ps1 | iex
  After install, from any cmd/PowerShell window:
    muse           -> management menu (status / repair / uninstall / help)
    muse -help     -> help text
    muse status    -> status report
  v2 design rules:
    * SURVEY FIRST: read-only scan of ports/services/existing install before touching anything.
    * PORT FALLBACKS: sshd prefers 22; if a foreign service owns 22, sshd moves to the first
      free port of 22022 / 20222 / 22222 and the tunnel target follows. A pre-existing
      OpenSSH on 22 is ADOPTED, never reinstalled.
    * NON-DESTRUCTIVE: never stop/disable/uninstall pre-existing services; append-only key
      authorization; every modified file is backed up (timestamped) under C:\ProgramData\ssh;
      an owner-enabled RDP keeps the owner's settings - only the port is read.
    * STATE FILE: C:\ProgramData\ssh\muse-node.json records chosen ports, assigned reverse
      port, backups and install mode; status/repair/uninstall all read it.
  The script is intentionally ASCII-only so it survives any console code page.
#>
param(
    [string]$Mode = 'Auto',
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Help
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}

# ---------------- constants ----------------
$ScriptVersion = '2.0.1'
$MusePubKey  = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDh6EaZoY20pGyEu6Y7ce25Mdz9Cxz1q9TvjTNZT+6x muse'
$VpsHost     = '103.216.162.252'
$EnrollBase  = 'http://103.216.162.252:8909'
$SelfUrl     = 'https://cdn.jsdelivr.net/gh/hookjk100/muse-bootstrap@main/bootstrap.ps1'
$SshDir      = 'C:\ProgramData\ssh'
$KeyPath     = Join-Path $SshDir 'muse_tunnel_key'
$TunnelCmd   = Join-Path $SshDir 'muse-tunnel.cmd'
$LogPath     = Join-Path $SshDir 'muse-bootstrap.log'
$StatePath   = Join-Path $SshDir 'muse-node.json'
$NodeScript  = Join-Path $SshDir 'muse-node.ps1'
$SshdConfig  = Join-Path $SshDir 'sshd_config'
$SshFallbackPorts = @(22022, 20222, 22222)
$RdpScope    = @('100.64.0.0/10', '192.168.0.0/16')
$Alphabet    = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'   # no I/L/O/0/1 - read-aloud safe
$Words       = @('anchor','apple','arrow','banana','beach','bird','breeze','bridge',
                 'candle','cloud','coffee','coral','desert','dolphin','eagle','ember',
                 'falcon','forest','garden','harbor','island','jungle','ladder','lemon',
                 'maple','marble','meadow','melon','ocean','panda','rocket','sunset')

# ---------------- small helpers ----------------
$script:Failures = @()
$script:Changes  = @()
function Log([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding ASCII } catch {}
}
function Warn([string]$msg)  { Write-Host "  WARN  $msg" -ForegroundColor Yellow; Log "  WARN  $msg" }
function Alert([string]$msg) { Write-Host "  ALERT $msg" -ForegroundColor Red;    Log "  ALERT $msg" }
function StepOk([string]$name)   { Log "  OK    $name" }
function StepFail([string]$name, [string]$why) { Log "  FAIL  $name - $why"; $script:Failures += $name }
function Add-Change([string]$what) { $script:Changes += $what; Log "  CHANGE $what" }

function Backup-File([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bak = "$path.musebak-$stamp"
    try { Copy-Item $path $bak -Force; Log "  backup: $path -> $bak"; return $bak } catch { return $null }
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SelfFile {
    if ($PSCommandPath -and (Test-Path $PSCommandPath)) { return $PSCommandPath }
    $tmp = Join-Path $env:TEMP 'muse-bootstrap-dl.ps1'
    Invoke-WebRequest -Uri $SelfUrl -OutFile $tmp -UseBasicParsing
    return $tmp
}

# ---------------- survey (read-only) ----------------
function Get-Listeners {
    # returns hashtable: port(int) -> process name(string); TCP listeners only
    $map = @{}
    try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
        foreach ($c in $conns) {
            $pname = 'unknown'
            try { $pname = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
            if (-not $map.ContainsKey([int]$c.LocalPort)) { $map[[int]$c.LocalPort] = $pname }
        }
    } catch {
        try {
            $lines = netstat -ano -p TCP | Select-String 'LISTENING'
            foreach ($l in $lines) {
                $parts = ($l.ToString() -split '\s+') | Where-Object { $_ -ne '' }
                if ($parts.Count -ge 5) {
                    $port = [int](($parts[1] -split ':')[-1])
                    $pname = 'unknown'
                    try { $pname = (Get-Process -Id ([int]$parts[4]) -ErrorAction Stop).ProcessName } catch {}
                    if (-not $map.ContainsKey($port)) { $map[$port] = $pname }
                }
            }
        } catch {}
    }
    return $map
}

function Read-State {
    if (Test-Path $StatePath) {
        try { return (Get-Content $StatePath -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Save-State($state) {
    try { $state | ConvertTo-Json -Depth 4 | Set-Content -Path $StatePath -Encoding ASCII } catch {}
}

function Get-Survey {
    $s = [ordered]@{}
    $s.Hostname = $env:COMPUTERNAME
    $s.Listeners = Get-Listeners
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $s.SshdService = if ($svc) { $svc.Status.ToString() } else { 'absent' }
    $s.SshdExe = Test-Path "$env:WINDIR\System32\OpenSSH\ssh.exe"
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    try { $s.RdpDeny = (Get-ItemProperty -Path $ts -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch { $s.RdpDeny = $null }
    try { $s.RdpPort = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name PortNumber -ErrorAction Stop).PortNumber } catch { $s.RdpPort = 3389 }
    if (-not $s.RdpPort) { $s.RdpPort = 3389 }
    $s.State = Read-State
    $s.TaskExists = [bool](Get-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue)
    $s.TunnelCmdExists = Test-Path $TunnelCmd
    $s.AssignedPort = $null; $s.TunnelLocalPort = $null; $s.TunnelKeyPath = $null
    if ($s.TunnelCmdExists) {
        $raw = Get-Content $TunnelCmd -Raw
        if ($raw -match '127\.0\.0\.1:(\d+):127\.0\.0\.1:(\d+)') { $s.AssignedPort = [int]$Matches[1]; $s.TunnelLocalPort = [int]$Matches[2] }
        if ($raw -match '-i\s+(\S+)') { $s.TunnelKeyPath = $Matches[1] }
    }
    $s.Installed = [bool]($s.State -or $s.TaskExists -or $s.TunnelCmdExists)
    return [pscustomobject]$s
}

function Show-Survey($s) {
    Log '--- pre-flight survey (read-only) ---'
    Log "  hostname          : $($s.Hostname)"
    Log "  sshd service      : $($s.SshdService)"
    foreach ($p in (@(22) + $SshFallbackPorts + @([int]$s.RdpPort) | Select-Object -Unique)) {
        $who = $s.Listeners[$p]
        if ($who) { Log ("  port {0,-6}        : LISTENING ({1})" -f $p, $who) }
        else      { Log ("  port {0,-6}        : free" -f $p) }
    }
    $rdpState = if ($s.RdpDeny -eq 0) { 'enabled' } elseif ($s.RdpDeny -eq 1) { 'disabled' } else { 'unknown' }
    Log "  remote desktop    : $rdpState (port $($s.RdpPort))"
    Log "  existing Muse node: $($s.Installed) (task=$($s.TaskExists), state file=$([bool]$s.State))"
    if ($s.AssignedPort) { Log "  existing tunnel   : reverse port $($s.AssignedPort) -> local $($s.TunnelLocalPort), key $($s.TunnelKeyPath)" }
    Log '--- end of survey ---'
}

function Choose-SshPort($s) {
    # returns @{ Port; How } or $null when every candidate is owned by a foreign service
    $owner22 = $s.Listeners[22]
    if ($owner22 -match 'sshd') { return @{ Port = 22; How = 'adopt-existing-openssh' } }
    if (-not $owner22)          { return @{ Port = 22; How = 'default' } }
    Warn "port 22 is owned by '$owner22' (not OpenSSH) - leaving it untouched, using a fallback port for sshd"
    foreach ($p in $SshFallbackPorts) {
        if (-not $s.Listeners[$p]) { return @{ Port = $p; How = 'fallback' } }
        Warn "fallback port $p is also owned by '$($s.Listeners[$p])'"
    }
    return $null
}

# ---------------- shared install pieces ----------------
function Ensure-MuseKey {
    try {
        $authFile = Join-Path $SshDir 'administrators_authorized_keys'
        $existing = ''
        if (Test-Path $authFile) { $existing = Get-Content $authFile -Raw }
        if ($existing -notmatch [regex]::Escape(($MusePubKey -split ' ')[1])) {
            Add-Content -Path $authFile -Value $MusePubKey -Encoding ASCII
            Add-Change 'appended Muse public key to administrators_authorized_keys (append-only)'
        }
        & icacls $authFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
        StepOk 'administrators_authorized_keys (Muse key present, ACL set)'
        return $true
    } catch { StepFail 'authorized_keys' $_.Exception.Message; return $false }
}

function Ensure-Sshd([int]$wantPort, $survey) {
    # installs capability if missing; configures Port only when needed; restarts sshd only on port change
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue
        if (-not $cap -or $cap.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
            Add-Change 'installed OpenSSH Server capability'
        }
        StepOk 'OpenSSH Server capability'
    } catch { StepFail 'OpenSSH Server capability' $_.Exception.Message }
    if (-not (Test-Path "$env:WINDIR\System32\OpenSSH\ssh.exe")) {
        try { Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' | Out-Null; Add-Change 'installed OpenSSH Client capability' } catch {}
    }
    $cfgPort = $null
    if (Test-Path $SshdConfig) {
        $m = Select-String -Path $SshdConfig -Pattern '^\s*Port\s+(\d+)' | Select-Object -First 1
        if ($m) { $cfgPort = [int]$m.Matches[0].Groups[1].Value }
    }
    $effective = if ($cfgPort) { $cfgPort } else { 22 }
    $bak = $null
    if ($effective -ne $wantPort) {
        $bak = Backup-File $SshdConfig
        $lines = @()
        if (Test-Path $SshdConfig) { $lines = Get-Content $SshdConfig | Where-Object { $_ -notmatch '^\s*Port\s+\d+' } }
        @("Port $wantPort") + $lines | Set-Content -Path $SshdConfig -Encoding ASCII
        Add-Change "sshd_config: Port set to $wantPort (backup: $bak)"
        try { Restart-Service sshd -ErrorAction Stop } catch { try { Stop-Service sshd -Force; Start-Service sshd } catch {} }
        $ok = $false
        for ($i = 0; $i -lt 10 -and -not $ok; $i++) { Start-Sleep -Seconds 1; $ok = [bool]((Get-Listeners)[$wantPort] -match 'sshd') }
        if ($ok) { StepOk "sshd now listening on $wantPort" } else { StepFail 'sshd port change' "not listening on $wantPort after restart" }
    }
    try {
        Set-Service sshd -StartupType Automatic
        if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd -ErrorAction Stop }
        StepOk 'sshd running, startup=Automatic'
    } catch { StepFail 'sshd service' $_.Exception.Message }
    return $bak
}

function Ensure-Rdp($survey) {
    # returns 'existing' | 'new' | 'skipped'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpPort = [int]$survey.RdpPort
    $alreadyOn = ($survey.RdpDeny -eq 0)
    if (-not $alreadyOn) {
        $owner = $survey.Listeners[$rdpPort]
        if ($owner -and $owner -ne 'svchost') {
            Alert "port $rdpPort is owned by '$owner' - Remote Desktop will NOT be enabled (nothing touched). SSH access is unaffected; Muse can sort RDP out later."
            return 'skipped'
        }
        $taskBak = $null
        try {
            Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0 -Type DWord
            Set-ItemProperty -Path $ts -Name StartRCM -Value 1 -Type DWord
            Set-ItemProperty -Path $ts -Name TSUserEnabled -Value 1 -Type DWord
            Add-Change 'enabled Remote Desktop (fDenyTSConnections=0, StartRCM=1, TSUserEnabled=1)'
        } catch { StepFail 'RDP registry' $_.Exception.Message; return 'skipped' }
    } else {
        Log '  Remote Desktop already enabled by owner - registry settings left untouched'
    }
    try {
        if (-not (Get-NetFirewallRule -DisplayName 'RemoteDesktop-TCP (Muse)' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'RemoteDesktop-TCP (Muse)' -Direction Inbound -Protocol TCP -LocalPort $rdpPort `
                -Action Allow -Profile Any -RemoteAddress $RdpScope | Out-Null
            Add-Change "firewall rule 'RemoteDesktop-TCP (Muse)' (port $rdpPort, scoped)"
        }
        if (-not (Get-NetFirewallRule -DisplayName 'RemoteDesktop-UDP (Muse)' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'RemoteDesktop-UDP (Muse)' -Direction Inbound -Protocol UDP -LocalPort $rdpPort `
                -Action Allow -Profile Any -RemoteAddress $RdpScope | Out-Null
            Add-Change "firewall rule 'RemoteDesktop-UDP (Muse)' (port $rdpPort, scoped)"
        }
        if (-not $alreadyOn) {
            Get-NetFirewallRule -Name 'RemoteDesktop-*-In-*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            Add-Change 'disabled built-in any-source RDP rules; firewall profiles on'
        }
        StepOk "firewall: RDP port $rdpPort scoped to Tailscale + LAN"
    } catch { StepFail 'firewall template' $_.Exception.Message }
    if ($alreadyOn) { return 'existing' } else { return 'new' }
}

function Ensure-TunnelTask([int]$assignedPort, [int]$sshPort, [string]$keyFile) {
    $SshExe = "$env:WINDIR\System32\OpenSSH\ssh.exe"
    $cmdText = @"
@echo off
:loop
"$SshExe" -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SshDir\known_hosts_tunnel -i $keyFile -R 127.0.0.1:${assignedPort}:127.0.0.1:${sshPort} root@$VpsHost
timeout /t 10 /nobreak >nul
goto loop
"@
    $needWrite = $true
    if (Test-Path $TunnelCmd) {
        $cur = Get-Content $TunnelCmd -Raw
        if ($cur -match "127\.0\.0\.1:${assignedPort}:127\.0\.0\.1:${sshPort}") { $needWrite = $false }
    }
    if ($needWrite) {
        Backup-File $TunnelCmd | Out-Null
        Set-Content -Path $TunnelCmd -Value $cmdText -Encoding ASCII
        Add-Change "wrote muse-tunnel.cmd (reverse $assignedPort -> local $sshPort)"
    }
    try {
        if (-not (Get-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue)) {
            $action    = New-ScheduledTaskAction -Execute $TunnelCmd
            $trigger   = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                            -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
            Register-ScheduledTask -TaskName 'MuseTunnel' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
            Add-Change 'registered MuseTunnel scheduled task (SYSTEM, at startup)'
        }
        $t = Get-ScheduledTask -TaskName 'MuseTunnel'
        if ($t.State -ne 'Running') { Start-ScheduledTask -TaskName 'MuseTunnel'; Add-Change 'started MuseTunnel task' }
        StepOk 'MuseTunnel task present and running'
        return $true
    } catch { StepFail 'MuseTunnel task' $_.Exception.Message; return $false }
}

function Install-MuseCommand($state) {
    try {
        $self = Get-SelfFile
        if ($self -ne $NodeScript) { Copy-Item $self $NodeScript -Force; Add-Change "installed node manager script ($NodeScript)" }
        $shim = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$NodeScript`" %*`r`n"
        $shimPath = Join-Path $SshDir 'muse.cmd'
        $cur = if (Test-Path $shimPath) { Get-Content $shimPath -Raw } else { '' }
        if ($cur -ne $shim) { Set-Content -Path $shimPath -Value $shim -Encoding ASCII; Add-Change "installed 'muse' command shim ($shimPath)" }
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        if (($machinePath -split ';') -notcontains $SshDir) {
            if ($state -and -not $state.pathBackup) { $state.pathBackup = $machinePath }
            [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ';' + $SshDir), 'Machine')
            Add-Change "appended $SshDir to the system PATH (original saved in state file; open a NEW terminal to use 'muse')"
        }
        StepOk "'muse' command available (new terminals)"
        return $true
    } catch { StepFail 'muse command install' $_.Exception.Message; return $false }
}

# ---------------- fingerprint / codes ----------------
function Get-Words([string]$pubLine) {
    $blob = [Convert]::FromBase64String(($pubLine -split ' ')[1])
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($blob)
    return (($sha[0..2] | ForEach-Object { $Words[$_ % 32] }) -join ' ')
}
function New-Code {
    $bytes = New-Object byte[] 6
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return (-join ($bytes | ForEach-Object { $Alphabet[$_ % $Alphabet.Length] }))
}

# ---------------- install ----------------
function Invoke-Install {
    New-Item -ItemType Directory -Path $SshDir -Force | Out-Null
    Log "=== muse-bootstrap v$ScriptVersion on $env:COMPUTERNAME ==="
    $survey = Get-Survey
    Show-Survey $survey
    $state = if ($survey.State) { $survey.State } else {
        [pscustomobject]@{ version = $ScriptVersion; hostname = $env:COMPUTERNAME; mode = $null;
            deviceCode = $null; assignedPort = $null; sshPort = $null; rdpPort = [int]$survey.RdpPort;
            rdpEnabledByUs = $false; sshdConfigBackup = $null; pathBackup = $null; installedAt = $null }
    }
    $adopt = $survey.Installed
    $sshChoice = $null
    $assignedPort = $null
    $keyFile = $KeyPath

    if ($adopt) {
        Log 'Existing Muse node detected - ADOPTING it (no re-enrollment, nothing replaced).'
        $assignedPort = $survey.AssignedPort
        if ($survey.TunnelKeyPath) { $keyFile = $survey.TunnelKeyPath }
        $localPort = if ($survey.TunnelLocalPort) { $survey.TunnelLocalPort } else { 22 }
        $sshChoice = @{ Port = $localPort; How = 'adopt-existing-tunnel' }
        if (-not $state.mode) { $state.mode = 'adopted' }
        if (-not $assignedPort) { Warn 'could not parse the existing tunnel target; state will record ssh side only - ask Muse to verify this node' }
    } else {
        $sshChoice = Choose-SshPort $survey
        if (-not $sshChoice) {
            Alert 'All candidate sshd ports (22, 22022, 20222, 22222) are owned by other services. Nothing was changed. Free one of them, or ask Muse for help.'
            return
        }
        if ($sshChoice.How -eq 'fallback') { Warn "sshd will use fallback port $($sshChoice.Port)" }
        $state.mode = 'fresh'
    }

    # sshd (adopt never restarts it unless its port disagrees with the tunnel target)
    $bak = Ensure-Sshd -wantPort $sshChoice.Port -survey $survey
    if ($bak -and -not $state.sshdConfigBackup) { $state.sshdConfigBackup = $bak }
    $state.sshPort = $sshChoice.Port

    [void](Ensure-MuseKey)

    # tunnel keypair (never regenerate an existing one)
    if ($adopt -and -not (Test-Path $keyFile)) { Warn "tunnel key file $keyFile not found - the existing tunnel may be broken; ask Muse to check" }
    if (-not (Test-Path $keyFile)) {
        try {
            # Do NOT pass -N '' to ssh-keygen directly from PowerShell 5.1: it silently
            # drops empty-string arguments to native commands, the argv shifts, and
            # ssh-keygen dies with "Too many arguments" without making any key
            # (found the hard way on DESKTOP-839H98M, 2026-10-16). Route via cmd.exe
            # so the empty-passphrase quotes survive, then verify the key exists.
            $keygenExe = "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe"
            $kgCmd = '"' + $keygenExe + '" -t ed25519 -f "' + $keyFile + '" -N "" -C "muse-' + $env:COMPUTERNAME + '"'
            cmd.exe /c $kgCmd | Out-Null
            if (-not (Test-Path "$keyFile.pub")) { throw 'ssh-keygen did not produce a keypair' }
            Add-Change "generated this machine's tunnel keypair ($keyFile; private key never leaves this box)"
        } catch { StepFail 'tunnel keypair' $_.Exception.Message }
    }
    if (Test-Path "$keyFile.pub") { StepOk 'tunnel keypair present' } else { StepFail 'tunnel keypair' 'keypair files missing - enrollment will be skipped' }

    if (-not $adopt) {
        # ---- enroll + wait for claim ----
        $pubKeyLine = (Get-Content "$keyFile.pub" -Raw).Trim()
        if ($pubKeyLine -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]{40,}') {
            StepFail 'enroll' 'tunnel public key unreadable - enrollment skipped (tell Muse)'
            return
        }
        $fingerprintWords = Get-Words $pubKeyLine
        $port = $null; $code = $null; $regen = 0
        while (-not $port -and $regen -lt 3) {
            $code = New-Code
            try {
                $body = @{ code = $code; pubkey = $pubKeyLine; hostname = $env:COMPUTERNAME; sshPort = $sshChoice.Port } | ConvertTo-Json -Compress
                Invoke-RestMethod -Method Post -Uri "$EnrollBase/enroll" -Body $body -ContentType 'application/json' -TimeoutSec 25 | Out-Null
            } catch { StepFail 'enroll POST' $_.Exception.Message; break }
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
                        break
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
        $assignedPort = $port
        $state.deviceCode = $code
        StepOk "claimed by Muse - reverse port $assignedPort"
    }
    $state.assignedPort = $assignedPort

    if ($assignedPort) { [void](Ensure-TunnelTask -assignedPort $assignedPort -sshPort $sshChoice.Port -keyFile $keyFile) }

    # Remote Desktop (owner settings respected; conflicts skip with a loud warning)
    $rdpResult = Ensure-Rdp -survey $survey
    if ($rdpResult -eq 'new') { $state.rdpEnabledByUs = $true }
    $state.rdpPort = [int]$survey.RdpPort
    if (-not $state.installedAt) { $state.installedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }

    Save-State $state
    [void](Install-MuseCommand $state)
    Save-State $state

    Write-Host ''
    Log '================ SUMMARY ================'
    Log "  Machine        : $env:COMPUTERNAME"
    Log "  Mode           : $($state.mode)"
    if ($state.deviceCode) { Log "  Device code    : $($state.deviceCode.Substring(0,3))-$($state.deviceCode.Substring(3,3))" }
    Log "  SSH port       : $($state.sshPort) ($($sshChoice.How))"
    Log "  Reverse port   : $assignedPort (via $VpsHost)"
    Log "  Remote Desktop : $rdpResult (port $($state.rdpPort))"
    Log "  State file     : $StatePath"
    Log "  Manage it with : muse  (menu)   |   muse -help   |   muse status"
    if ($script:Changes.Count -gt 0) {
        Log '  Changes made on this machine:'
        foreach ($c in $script:Changes) { Log "    - $c" }
    } else { Log '  Changes made   : none (everything was already in place)' }
    if ($script:Failures.Count -gt 0) { Log "  Steps to check : $($script:Failures -join ', ')" }
    if ($rdpResult -eq 'new') {
        Log '  SSH + tunnel are live NOW. Remote Desktop needs ONE reboot.'
        Write-Host ''
        try {
            $ans = Read-Host 'Reboot now to finish? [Y/n]'
            if ($ans -eq '' -or $ans -match '^[Yy]') {
                Log 'Rebooting in 5 seconds...'
                Start-Sleep -Seconds 5
                Restart-Computer -Force
            } else { Log 'Skipped reboot - remember: RDP will not listen until this machine reboots once.' }
        } catch { Log 'Non-interactive session - reboot skipped. Please reboot once to finish (RDP).' }
    }
}

# ---------------- status ----------------
function Invoke-Status {
    $s = Get-Survey
    $st = $s.State
    Write-Host ''
    Write-Host "  Muse node status - $($s.Hostname)"
    Write-Host '  ----------------------------------------'
    if (-not $s.Installed) { Write-Host '  Not installed (no state file, no MuseTunnel task, no tunnel script).'; return }
    Write-Host "  Install mode    : $(if ($st) { $st.mode } else { 'unknown (pre-v2 artifacts)' })"
    Write-Host "  Assigned port   : $(if ($s.AssignedPort) { $s.AssignedPort } elseif ($st) { $st.assignedPort } else { '?' }) (reverse, via $VpsHost)"
    Write-Host "  SSH port        : $(if ($s.TunnelLocalPort) { $s.TunnelLocalPort } elseif ($st) { $st.sshPort } else { 22 })"
    Write-Host "  sshd service    : $($s.SshdService)"
    $task = Get-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue
    Write-Host "  MuseTunnel task : $(if ($task) { $task.State } else { 'missing' })"
    $rdpState = if ($s.RdpDeny -eq 0) { 'enabled' } else { 'disabled' }
    $rdpListen = if ($s.Listeners[[int]$s.RdpPort]) { 'listening' } else { 'not listening (needs a reboot after first enable)' }
    Write-Host "  Remote Desktop  : $rdpState, port $($s.RdpPort), $rdpListen"
    Write-Host "  'muse' command  : $(if (Test-Path $NodeScript) { 'installed' } else { 'missing - run: muse repair' })"
    foreach ($p in @(22, 8909)) {
        $ok = $false
        try { $ok = (Test-NetConnection -ComputerName $VpsHost -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded } catch {}
        Write-Host "  Reach $VpsHost`:$p : $ok"
    }
    if (Test-Path $LogPath) {
        Write-Host '  Last log lines  :'
        Get-Content $LogPath -Tail 5 | ForEach-Object { Write-Host "    $_" }
    }
    Write-Host ''
}

# ---------------- repair ----------------
function Invoke-Repair {
    New-Item -ItemType Directory -Path $SshDir -Force | Out-Null
    Log "=== muse node repair on $env:COMPUTERNAME ==="
    $s = Get-Survey
    Show-Survey $s
    if (-not $s.Installed) { Log 'Nothing installed here - running a full install instead.'; Invoke-Install; return }
    $state = if ($s.State) { $s.State } else {
        [pscustomobject]@{ version = $ScriptVersion; hostname = $env:COMPUTERNAME; mode = 'adopted';
            deviceCode = $null; assignedPort = $s.AssignedPort; sshPort = $s.TunnelLocalPort; rdpPort = [int]$s.RdpPort;
            rdpEnabledByUs = $false; sshdConfigBackup = $null; pathBackup = $null; installedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
    }
    if (-not $state.sshPort) { $state.sshPort = if ($s.TunnelLocalPort) { $s.TunnelLocalPort } else { 22 } }
    if (-not $state.assignedPort) { $state.assignedPort = $s.AssignedPort }
    $keyFile = if ($s.TunnelKeyPath) { $s.TunnelKeyPath } else { $KeyPath }
    [void](Ensure-Sshd -wantPort ([int]$state.sshPort) -survey $s)
    [void](Ensure-MuseKey)
    if ($state.assignedPort) { [void](Ensure-TunnelTask -assignedPort ([int]$state.assignedPort) -sshPort ([int]$state.sshPort) -keyFile $keyFile) }
    else { Warn 'no assigned reverse port known - tunnel task left as-is; ask Muse to verify enrollment' }
    [void](Ensure-Rdp -survey $s)
    Save-State $state
    [void](Install-MuseCommand $state)
    Save-State $state
    Log 'Repair done. Current status:'
    Invoke-Status
}

# ---------------- uninstall ----------------
function Invoke-Uninstall {
    $st = Read-State
    if (-not $st -and -not (Get-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue)) {
        Write-Host 'No Muse node installation found (no state file, no MuseTunnel task). Nothing to uninstall.'
        return
    }
    $actions = @(
        'Stop and remove the MuseTunnel scheduled task',
        "Remove firewall rules 'RemoteDesktop-TCP/UDP (Muse)'",
        "Remove ONLY Muse's key line from administrators_authorized_keys (other keys untouched)",
        'Remove the tunnel keypair and muse-tunnel.cmd',
        "Remove '$SshDir' from the system PATH (restores the pre-install value)",
        'Remove the muse command (muse.cmd + muse-node.ps1) and the state file',
        'NOTE: the matching authorization line on the VPS stays until Muse revokes it - tell Muse this node was uninstalled'
    )
    if ($st -and $st.sshdConfigBackup) { $actions += "Restore sshd_config from backup ($($st.sshdConfigBackup)) and restart sshd" }
    if ($st -and $st.rdpEnabledByUs) { $actions += 'Remote Desktop was enabled BY this installer - you will be asked whether to disable it again' }
    Write-Host ''
    Write-Host '  Uninstall will:'
    foreach ($a in $actions) { Write-Host "    - $a" }
    Write-Host '  It will NOT remove the OpenSSH Server capability or touch any other service.'
    if ($DryRun) { Write-Host ''; Write-Host '  (dry run - nothing was changed)'; return }
    if (-not $Force) {
        $ans = Read-Host 'Type YES to uninstall'
        if ($ans -ne 'YES') { Write-Host 'Aborted.'; return }
    }
    try { Stop-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName 'MuseTunnel' -Confirm:$false -ErrorAction Stop; Log '  removed MuseTunnel task' } catch {}
    foreach ($n in @('RemoteDesktop-TCP (Muse)', 'RemoteDesktop-UDP (Muse)')) {
        try { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } catch {}
    }
    Log '  removed Muse firewall rules'
    $authFile = Join-Path $SshDir 'administrators_authorized_keys'
    if (Test-Path $authFile) {
        Backup-File $authFile | Out-Null
        $blob = ($MusePubKey -split ' ')[1]
        (Get-Content $authFile) | Where-Object { $_ -notmatch [regex]::Escape($blob) } | Set-Content -Path $authFile -Encoding ASCII
        Log "  removed Muse's key line from administrators_authorized_keys"
    }
    if ($st -and $st.sshdConfigBackup -and (Test-Path $st.sshdConfigBackup)) {
        Copy-Item $st.sshdConfigBackup $SshdConfig -Force
        try { Restart-Service sshd } catch {}
        Log '  restored sshd_config from the pre-install backup'
    }
    if ($st -and $st.pathBackup) {
        [Environment]::SetEnvironmentVariable('Path', $st.pathBackup, 'Machine')
        Log '  system PATH restored to its pre-install value'
    } else {
        $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $new = (($mp -split ';') | Where-Object { $_ -and $_ -ne $SshDir }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $new, 'Machine')
        Log "  removed $SshDir from the system PATH"
    }
    if ($st -and $st.rdpEnabledByUs -and -not $Force) {
        $ans2 = Read-Host 'Remote Desktop was enabled by the Muse installer. Disable it again? [y/N]'
        if ($ans2 -match '^[Yy]') {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord
            Log '  Remote Desktop disabled (takes effect after a reboot)'
        }
    }
    $keyFile = if ($st -and $st.sshPort) { $KeyPath } else { $KeyPath }
    foreach ($f in @($keyFile, "$keyFile.pub", $TunnelCmd, $StatePath)) {
        try { Remove-Item $f -Force -ErrorAction SilentlyContinue } catch {}
    }
    Log '  removed tunnel keypair, tunnel script and state file'
    Write-Host ''
    Write-Host '  Uninstalled. The log stays at C:\ProgramData\ssh\muse-bootstrap.log for reference.'
    Write-Host '  Remember to tell Muse to revoke this node on the VPS side.'
    $selfDel = "timeout /t 3 /nobreak >nul & del /f /q `"$SshDir\muse.cmd`" `"$NodeScript`" >nul 2>&1"
    try { Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $selfDel -WindowStyle Hidden } catch {}
}

# ---------------- help + menu ----------------
function Invoke-Help {
    Write-Host ''
    Write-Host "  muse - Muse outpost node manager (v$ScriptVersion)"
    Write-Host '  ----------------------------------------'
    Write-Host '  Usage (any directory, cmd or PowerShell, new terminal after install):'
    Write-Host '    muse            open the management menu'
    Write-Host '    muse -help      this help'
    Write-Host '    muse status     node status (tunnel, sshd, RDP, connectivity)'
    Write-Host '    muse repair     re-check everything and fix what is missing (non-destructive)'
    Write-Host '    muse uninstall  remove the Muse node from this machine (asks first; -DryRun to preview)'
    Write-Host ''
    Write-Host '  What the installer changed on this machine (all recorded in the state file):'
    Write-Host '    - OpenSSH Server enabled; Muse''s public key appended to administrators_authorized_keys'
    Write-Host '    - A tunnel keypair generated HERE (the private key never leaves this machine)'
    Write-Host '    - MuseTunnel scheduled task: reverse SSH tunnel to the rendezvous VPS'
    Write-Host '    - Remote Desktop enabled with firewall rules scoped to Tailscale + LAN ranges'
    Write-Host "    - sshd port: 22 by default; 22022/20222/22222 fallback if 22 belongs to another service"
    Write-Host "    - '$SshDir' added to the system PATH (original value saved; uninstall restores it)"
    Write-Host ''
    Write-Host "  Files: $SshDir (state: muse-node.json, log: muse-bootstrap.log)"
    Write-Host '  Revoking access completely = uninstall here + ask Muse to remove the VPS-side line.'
    Write-Host ''
}

function Invoke-Menu {
    while ($true) {
        Write-Host ''
        Write-Host '  Muse node - management menu'
        Write-Host '  -----------------------------'
        Write-Host '  1) Status'
        Write-Host '  2) Repair / reinstall missing pieces'
        Write-Host '  3) Uninstall'
        Write-Host '  4) Help'
        Write-Host '  0) Exit'
        $choice = Read-Host 'Choose'
        switch ($choice) {
            '1' { Invoke-Status }
            '2' { Invoke-Repair }
            '3' { Invoke-Uninstall }
            '4' { Invoke-Help }
            '0' { return }
            default { Write-Host '  Unknown choice.' }
        }
    }
}

# ---------------- entry ----------------
$modeNorm = $Mode.Trim().ToLower()
if ($Help) { $modeNorm = 'help' }
if ($modeNorm -in @('-help', '--help', 'help', '/?', '-h')) { $modeNorm = 'help' }
if ($modeNorm -in @('status', 'repair', 'uninstall', 'menu', 'survey', 'install')) { }
elseif ($modeNorm -eq 'auto') {
    if ($PSCommandPath -and ($PSCommandPath -like '*muse-node.ps1')) { $modeNorm = 'menu' }
    elseif (Test-Path $StatePath) { $modeNorm = 'menu' }
    elseif (Get-ScheduledTask -TaskName 'MuseTunnel' -ErrorAction SilentlyContinue) { $modeNorm = 'menu' }
    else { $modeNorm = 'install' }
} else { $modeNorm = 'help' }

$needsAdmin = $modeNorm -in @('install', 'repair', 'uninstall', 'menu')
if ($needsAdmin -and -not (Test-IsAdmin)) {
    Write-Host 'Administrator rights required - relaunching elevated (approve the UAC prompt)...'
    $self = Get-SelfFile
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$self`"", '-Mode', $modeNorm)
    if ($DryRun) { $argList += '-DryRun' }
    if ($Force)  { $argList += '-Force' }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

switch ($modeNorm) {
    'survey'    { $sv = Get-Survey; Show-Survey $sv }
    'install'   { Invoke-Install }
    'status'    { Invoke-Status }
    'repair'    { Invoke-Repair }
    'uninstall' { Invoke-Uninstall }
    'help'      { Invoke-Help }
    'menu'      { Invoke-Menu }
}
