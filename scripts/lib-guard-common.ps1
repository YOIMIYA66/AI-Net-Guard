# AI-Net-Guard v5.8.9 - shared security helpers (write lock, recursive ACL audit, Fail-Closed policy loader, strict CN CIDR validation).
# Pure ASCII script. Dot-sourced by 07-mode.ps1, 09-rollback.ps1, 10-sync-node-rule.ps1, 12-regression.ps1, 13-harden-acl.ps1, 14-apply-policy.ps1.

function Enter-GuardWriteLock {
    param(
        [int]$TimeoutMs = 30000,
        [string]$LockName = 'Global\AI-Net-Guard-PolicyEngine'
    )

    # Allow nested parent -> child guard invocations in the same process tree to share
    # the outer lock instead of self-deadlocking on a cross-process Mutex.
    if ($env:AI_GUARD_LOCK_TOKEN) {
        return [pscustomobject]@{
            Mutex     = $null
            Owned     = $false
            Inherited = $true
            Token     = [string]$env:AI_GUARD_LOCK_TOKEN
        }
    }

    $mtx = $null
    $effectiveName = $LockName
    try {
        $mtx = New-Object System.Threading.Mutex($false, $effectiveName)
    }
    catch [System.UnauthorizedAccessException] {
        $effectiveName = 'Local\AI-Net-Guard-PolicyEngine'
        $mtx = New-Object System.Threading.Mutex($false, $effectiveName)
    }

    $acquired = $false
    try {
        try {
            $acquired = $mtx.WaitOne($TimeoutMs)
        }
        catch [System.Threading.AbandonedMutexException] {
            # Previous holder died unexpectedly; OS grants ownership to us cleanly.
            $acquired = $true
        }
    }
    catch {
        if ($mtx) { try { $mtx.Dispose() } catch { } }
        throw
    }

    if (-not $acquired) {
        try { $mtx.Dispose() } catch { }
        throw ('Timed out waiting for AI-Net-Guard write lock (' + $effectiveName + ')')
    }

    $token = [guid]::NewGuid().ToString('N')
    $env:AI_GUARD_LOCK_TOKEN = $token
    return [pscustomobject]@{
        Mutex     = $mtx
        Owned     = $true
        Inherited = $false
        Token     = $token
    }
}

function Exit-GuardWriteLock {
    param($Handle)
    if (-not $Handle -or -not $Handle.Owned) { return }
    if ($Handle.Mutex) {
        try { $Handle.Mutex.ReleaseMutex() } catch { }
        try { $Handle.Mutex.Dispose() } catch { }
    }
    if ($Handle.Token -and $env:AI_GUARD_LOCK_TOKEN -eq $Handle.Token) {
        Remove-Item Env:\AI_GUARD_LOCK_TOKEN -ErrorAction SilentlyContinue
    }
}

function Get-GuardInstallAclIssues {
    param([string]$Path)

    # Trusted writers: Administrators, SYSTEM, CREATOR OWNER (inherit-only), TrustedInstaller
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # WriteData|AppendData|WriteEA|DeleteChild|WriteAttributes|Delete|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL
    $writeMask = [int64]0x500D0156
    $issues = New-Object System.Collections.Generic.List[string]
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        $issues.Add('install root missing: ' + $Path)
        return $issues.ToArray()
    }

    $targets = New-Object System.Collections.Generic.List[object]
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $addTarget = {
        param($item)
        if (-not $item -or -not $item.FullName) { return }
        if ($seenPaths.Add($item.FullName)) { $targets.Add($item) }
    }

    & $addTarget (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
    foreach ($rf in @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction SilentlyContinue)) {
        & $addTarget $rf
    }
    foreach ($sub in @('backup', 'logs', 'scripts')) {
        $sp = Join-Path $Path $sub
        if (Test-Path -LiteralPath $sp) {
            & $addTarget (Get-Item -LiteralPath $sp -Force -ErrorAction SilentlyContinue)
        }
    }

    # Recursively audit everything under scripts\ (files and directories executed as SYSTEM).
    $scriptsDir = Join-Path $Path 'scripts'
    if (Test-Path -LiteralPath $scriptsDir) {
        foreach ($si in @(Get-ChildItem -LiteralPath $scriptsDir -Recurse -Force -ErrorAction SilentlyContinue)) {
            & $addTarget $si
        }
    }

    # Audit security-critical policy and exception files under backup\.
    foreach ($bf in @('guard-policy.json', 'guard-policy.last-good.json', 'allowed-outbound-rules.json')) {
        $bp = Join-Path (Join-Path $Path 'backup') $bf
        if (Test-Path -LiteralPath $bp) {
            & $addTarget (Get-Item -LiteralPath $bp -Force -ErrorAction SilentlyContinue)
        }
    }

    $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
    foreach ($t in $targets) {
        try {
            if (($t.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $issues.Add($t.Name + ': reparse-point(symlink/junction) not allowed')
            }
            $acl = if ($t.PSIsContainer) { New-Object System.Security.AccessControl.DirectorySecurity($t.FullName, $sections) }
                   else { New-Object System.Security.AccessControl.FileSecurity($t.FullName, $sections) }
            $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($trusted -notcontains $owner) { $issues.Add($t.Name + ': owner=' + $owner) }
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sid = $ace.IdentityReference.Value
                if ($trusted -contains $sid) { continue }
                if (([int64]$ace.FileSystemRights -band $writeMask) -ne 0) {
                    $issues.Add($t.Name + ': ' + $sid + ' has ' + $ace.FileSystemRights)
                }
            }
        }
        catch {
            $issues.Add($t.Name + ': ACL unreadable (' + $_.Exception.Message + ')')
        }
    }
    return $issues.ToArray()
}

function ConvertFrom-StrictPolicyJson {
    param(
        [string]$FilePath,
        [System.Collections.IDictionary]$BaseDefaults
    )

    $rawText = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
    $raw = $rawText | ConvertFrom-Json
    if (-not $raw) { throw 'empty JSON object' }

    $out = [ordered]@{}
    foreach ($key in $BaseDefaults.Keys) { $out[$key] = $BaseDefaults[$key] }

    $boolKeys = @(
        'AllowCnDirect', 'AllowLan', 'AllowNcsi', 'QuarantineRogueAllow', 'LockPhysicalDns',
        'DisableSmhnr', 'DisableLlmnrNetbios', 'StrictNrptDoh', 'DisablePhysicalIpv6', 'PreferIpv4Prefix',
        'ZeroResidentMonitor', 'AutoNodeSync', 'AutoHealStaleProxy', 'DomesticNtp', 'HardenInstallAcl', 'BlockWebRtcLeak'
    )
    foreach ($k in $boolKeys) {
        if ($raw.PSObject.Properties.Name -contains $k -and $null -ne $raw.$k) {
            if ($raw.$k -isnot [bool]) {
                throw ('policy field ' + $k + ' must be boolean, got ' + $raw.$k.GetType().Name)
            }
            $out[$k] = [bool]$raw.$k
        }
    }

    $strKeys = @('Version', 'Preset', 'DnsServer', 'V2rayNRoot')
    foreach ($sk in $strKeys) {
        if ($raw.PSObject.Properties.Name -contains $sk -and $null -ne $raw.$sk) {
            if ($raw.$sk -isnot [string]) {
                throw ('policy field ' + $sk + ' must be string, got ' + $raw.$sk.GetType().Name)
            }
            if ($raw.$sk.Length -gt 0) {
                $out[$sk] = [string]$raw.$sk
            }
        }
    }
    return $out
}

function Read-GuardPolicyStrict {
    param(
        [string]$PolicyPath,
        [System.Collections.IDictionary]$Defaults,
        [string]$LastGoodPath = '',
        [switch]$NoSaveLastGood
    )

    if (-not $PolicyPath -or -not (Test-Path -LiteralPath $PolicyPath)) {
        $def = [ordered]@{}
        foreach ($key in $Defaults.Keys) { $def[$key] = $Defaults[$key] }
        $def['PolicyHealth'] = 'default'
        $def['PolicyWarning'] = ''
        return [pscustomobject]$def
    }

    $primaryErr = ''
    try {
        $parsed = ConvertFrom-StrictPolicyJson -FilePath $PolicyPath -BaseDefaults $Defaults
        if (-not $NoSaveLastGood -and $LastGoodPath) {
            try {
                $lgDir = Split-Path -Parent $LastGoodPath
                if ($lgDir -and -not (Test-Path -LiteralPath $lgDir)) {
                    New-Item -ItemType Directory -Path $lgDir -Force | Out-Null
                }
                $tmpLg = $LastGoodPath + '.tmp.' + $PID
                $rawJson = [System.IO.File]::ReadAllText($PolicyPath, [System.Text.Encoding]::UTF8)
                [System.IO.File]::WriteAllText($tmpLg, $rawJson, (New-Object System.Text.UTF8Encoding($false)))
                Move-Item -LiteralPath $tmpLg -Destination $LastGoodPath -Force -ErrorAction Stop
            }
            catch { }
        }
        $parsed['PolicyHealth'] = 'ok'
        $parsed['PolicyWarning'] = ''
        return [pscustomobject]$parsed
    }
    catch {
        $primaryErr = $_.Exception.Message
    }

    if ($LastGoodPath -and (Test-Path -LiteralPath $LastGoodPath)) {
        try {
            $lgParsed = ConvertFrom-StrictPolicyJson -FilePath $LastGoodPath -BaseDefaults $Defaults
            $lgParsed['PolicyHealth'] = 'recovered-last-good'
            $lgParsed['PolicyWarning'] = ('primary policy corrupt (' + $primaryErr + '); fell back to last-known-good')
            return [pscustomobject]$lgParsed
        }
        catch {
            $primaryErr += '; last-good also failed: ' + $_.Exception.Message
        }
    }

    # Fail-Closed: never silently relax security switches when policy JSON is corrupted.
    $fc = [ordered]@{}
    foreach ($key in $Defaults.Keys) { $fc[$key] = $Defaults[$key] }
    $fc['Preset'] = 'FailClosed'
    $fc['AllowCnDirect'] = $false
    $fc['AllowLan'] = $false
    $fc['AllowNcsi'] = $false
    $fc['QuarantineRogueAllow'] = $true
    $fc['LockPhysicalDns'] = $true
    $fc['DisableSmhnr'] = $true
    $fc['DisableLlmnrNetbios'] = $true
    $fc['StrictNrptDoh'] = $false
    $fc['BlockWebRtcLeak'] = $true
    $fc['DisablePhysicalIpv6'] = $true
    $fc['PreferIpv4Prefix'] = $true
    $fc['ZeroResidentMonitor'] = $true
    $fc['AutoNodeSync'] = $true
    $fc['AutoHealStaleProxy'] = $true
    $fc['DomesticNtp'] = $true
    $fc['HardenInstallAcl'] = $true
    $fc['PolicyHealth'] = 'corrupt-fail-closed'
    $fc['PolicyWarning'] = ('policy corrupt (' + $primaryErr + ') and no valid last-known-good; entered Fail-Closed state')
    return [pscustomobject]$fc
}

function Get-ValidatedCnPrefixes {
    param(
        [string[]]$Lines,
        [int]$MinCount = 1000
    )

    if (-not $Lines -or $Lines.Count -eq 0) { return @() }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[string] ($Lines.Count)

    foreach ($ln in $Lines) {
        if (-not $ln) { continue }
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $parts = $t.Split('/')
        if ($parts.Count -ne 2) { continue }

        $ipStr = $parts[0].Trim()
        $plenStr = $parts[1].Trim()
        if ($plenStr -notmatch '^\d{1,2}$') { continue }
        $plen = [int]$plenStr
        if ($plen -lt 8 -or $plen -gt 32) { continue }

        $ipObj = $null
        if (-not [System.Net.IPAddress]::TryParse($ipStr, [ref]$ipObj)) { continue }
        if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
        if ($ipObj.ToString() -ne $ipStr) { continue }

        $b = $ipObj.GetAddressBytes()
        $full = [int][Math]::Floor($plen / 8)
        $rem = $plen % 8
        $net = New-Object 'byte[]' 4
        for ($i = 0; $i -lt 4; $i++) {
            $m = if ($i -lt $full) { 255 }
                 elseif ($i -eq $full -and $rem -gt 0) { ((0xFF -shl (8 - $rem)) -band 0xFF) }
                 else { 0 }
            $net[$i] = [byte]($b[$i] -band $m)
        }

        $o0 = [int]$net[0]
        $o1 = [int]$net[1]
        # Reject reserved, loopback, RFC1918, link-local, multicast/future-use networks
        if ($o0 -eq 0 -or $o0 -eq 10 -or $o0 -eq 127 -or $o0 -ge 224) { continue }
        if ($o0 -eq 169 -and $o1 -eq 254) { continue }
        if ($o0 -eq 172 -and $o1 -ge 16 -and $o1 -le 31) { continue }
        if ($o0 -eq 192 -and $o1 -eq 168) { continue }

        $cidr = ([string]$o0) + '.' + ([string]$o1) + '.' + ([string]$net[2]) + '.' + ([string]$net[3]) + '/' + ([string]$plen)
        if ($seen.Add($cidr)) {
            $out.Add($cidr)
        }
    }

    if ($out.Count -lt $MinCount) { return @() }
    return $out.ToArray()
}
