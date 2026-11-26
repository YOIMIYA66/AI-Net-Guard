# AI-Net-Guard v5.9.6 - shared security helpers (write lock, recursive ACL audit, Fail-Closed policy loader, strict CN CIDR validation).
# Pure ASCII script. Dot-sourced by 02-killswitch.ps1, 07-mode.ps1, 09-rollback.ps1, 10-sync-node-rule.ps1, 12-regression.ps1, 13-harden-acl.ps1, 14-apply-policy.ps1.

function Enter-GuardWriteLock {
    param(
        [int]$TimeoutMs = 30000,
        [string]$LockName = 'Global\AI-Net-Guard-PolicyEngine'
    )

    # Allow nested parent -> child guard invocations in the same live process tree to
    # share the outer lock instead of self-deadlocking on a cross-process Mutex.
    # Require matching lock name and an alive owner PID so stale env vars cannot bypass locking.
    if ($env:AI_GUARD_LOCK_TOKEN) {
        $tokParts = ([string]$env:AI_GUARD_LOCK_TOKEN) -split '\|', 3
        $ownerPid = 0
        if ($tokParts.Count -eq 3 -and $tokParts[1] -eq $LockName -and [int]::TryParse($tokParts[0], [ref]$ownerPid) -and $ownerPid -gt 0) {
            $ownerAlive = $null
            if ($ownerPid -eq $PID) {
                $ownerAlive = $true
            }
            else {
                $ownerAlive = [bool](Get-Process -Id $ownerPid -ErrorAction SilentlyContinue)
            }
            if ($ownerAlive) {
                return [pscustomobject]@{
                    Mutex     = $null
                    Owned     = $false
                    Inherited = $true
                    Token     = [string]$env:AI_GUARD_LOCK_TOKEN
                }
            }
        }
    }

    if ($LockName -like 'Local\*') {
        throw ('Refusing insecure Local lock namespace: ' + $LockName + ' (Global\\ required)')
    }

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([System.Security.Principal.WindowsPrincipal]$id).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $mtxSec = New-Object System.Security.AccessControl.MutexSecurity
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $sysSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $mtxSec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule($adminSid, [System.Security.AccessControl.MutexRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
    $mtxSec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule($sysSid, [System.Security.AccessControl.MutexRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
    if ((-not $isAdmin) -and ($LockName -ne 'Global\AI-Net-Guard-PolicyEngine') -and $id -and $id.User) {
        $mtxSec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule($id.User, [System.Security.AccessControl.MutexRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
    }

    $mtx = $null
    $createdNew = $false
    $mtxAclType = [type]::GetType('System.Threading.MutexAcl, System.Threading.AccessControl', $false)
    try {
        if ($mtxAclType) {
            $mtx = [System.Threading.MutexAcl]::Create($false, $LockName, [ref]$createdNew, $mtxSec)
        }
        else {
            $mtx = New-Object System.Threading.Mutex($false, $LockName, [ref]$createdNew, $mtxSec)
        }
    }
    catch [System.UnauthorizedAccessException] {
        throw ('Access denied opening Global write lock (' + $LockName + '). Run elevated (Administrators/SYSTEM required).')
    }
    if (-not $mtx) {
        throw ('Failed to create or open Global write lock (' + $LockName + ').')
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
        throw ('Timed out waiting for AI-Net-Guard write lock (' + $LockName + ')')
    }

    $token = ([string]$PID) + '|' + $LockName + '|' + ([guid]::NewGuid().ToString('N'))
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

    try {
        $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        & $addTarget $rootItem
        $parentPath = Split-Path -Parent ($rootItem.FullName.TrimEnd('\'))
        if ($parentPath -and ($parentPath.TrimEnd('\').Length -gt 2) -and (Test-Path -LiteralPath $parentPath)) {
            $parentItem = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
            if (($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $issues.Add('parent(' + $parentItem.Name + '): reparse-point(symlink/junction) not allowed')
            }
            $pSections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
            $pAcl = New-Object System.Security.AccessControl.DirectorySecurity($parentItem.FullName, $pSections)
            $pOwner = $pAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($trusted -notcontains $pOwner) { $issues.Add('parent(' + $parentItem.Name + '): owner=' + $pOwner) }
            foreach ($pAce in $pAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($pAce.AccessControlType -ne 'Allow') { continue }
                $pSid = $pAce.IdentityReference.Value
                if ($trusted -contains $pSid) { continue }
                if (([int64]$pAce.FileSystemRights -band $writeMask) -ne 0) {
                    $issues.Add('parent(' + $parentItem.Name + '): ' + $pSid + ' has ' + $pAce.FileSystemRights)
                }
            }
        }
    }
    catch {
        $issues.Add('root/parent inspection failed: ' + $_.Exception.Message)
    }

    try {
        foreach ($rf in @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction Stop)) {
            & $addTarget $rf
        }
    }
    catch {
        $issues.Add('root file enumeration failed: ' + $_.Exception.Message)
    }

    foreach ($sub in @('backup', 'logs', 'scripts')) {
        $sp = Join-Path $Path $sub
        if (Test-Path -LiteralPath $sp) {
            try { & $addTarget (Get-Item -LiteralPath $sp -Force -ErrorAction Stop) }
            catch { $issues.Add($sub + ' inspection failed: ' + $_.Exception.Message) }
        }
    }

    # Recursively audit everything under scripts\ (files and directories executed as SYSTEM).
    $scriptsDir = Join-Path $Path 'scripts'
    if (Test-Path -LiteralPath $scriptsDir) {
        try {
            foreach ($si in @(Get-ChildItem -LiteralPath $scriptsDir -Recurse -Force -ErrorAction Stop)) {
                & $addTarget $si
            }
        }
        catch {
            $issues.Add('scripts enumeration failed: ' + $_.Exception.Message)
        }
    }

    # Audit security-critical policy and exception files under backup\.
    foreach ($bf in @('guard-policy.json', 'guard-policy.last-good.json', 'allowed-outbound-rules.json')) {
        $bp = Join-Path (Join-Path $Path 'backup') $bf
        if (Test-Path -LiteralPath $bp) {
            try { & $addTarget (Get-Item -LiteralPath $bp -Force -ErrorAction Stop) }
            catch { $issues.Add($bf + ' inspection failed: ' + $_.Exception.Message) }
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
        [System.Collections.IDictionary]$BaseDefaults,
        [switch]$RequireCriticalBools
    )

    $rawText = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
    $raw = $rawText | ConvertFrom-Json
    if (-not $raw) { throw 'empty JSON object' }

    $out = [ordered]@{}
    foreach ($key in $BaseDefaults.Keys) { $out[$key] = $BaseDefaults[$key] }

    $matchedKeys = 0
    $boolKeys = @(
        'AllowCnDirect', 'AllowLan', 'AllowNcsi', 'QuarantineRogueAllow', 'LockPhysicalDns',
        'DisableSmhnr', 'DisableLlmnrNetbios', 'StrictNrptDoh', 'DisablePhysicalIpv6', 'PreferIpv4Prefix',
        'ZeroResidentMonitor', 'AutoNodeSync', 'AutoHealStaleProxy', 'DomesticNtp', 'HardenInstallAcl', 'BlockWebRtcLeak'
    )
    foreach ($k in $boolKeys) {
        if ($raw.PSObject.Properties.Name -contains $k) {
            if ($null -eq $raw.$k) {
                throw ('policy field ' + $k + ' must be boolean, got null')
            }
            if ($raw.$k -isnot [bool]) {
                throw ('policy field ' + $k + ' must be boolean, got ' + $raw.$k.GetType().Name)
            }
            $out[$k] = [bool]$raw.$k
            $matchedKeys++
        }
    }

    if ($RequireCriticalBools) {
        $criticalBools = @(
            'AllowCnDirect', 'AllowLan', 'AllowNcsi', 'LockPhysicalDns',
            'DisablePhysicalIpv6', 'BlockWebRtcLeak', 'ZeroResidentMonitor', 'HardenInstallAcl'
        )
        foreach ($ck in $criticalBools) {
            if ($raw.PSObject.Properties.Name -notcontains $ck) {
                throw ('incomplete policy JSON on deployed host: missing required field ' + $ck)
            }
        }
    }

    $strKeys = @('Version', 'Preset', 'DnsServer', 'V2rayNRoot')
    foreach ($sk in $strKeys) {
        if ($raw.PSObject.Properties.Name -contains $sk) {
            if ($null -eq $raw.$sk) {
                throw ('policy field ' + $sk + ' must be string, got null')
            }
            if ($raw.$sk -isnot [string]) {
                throw ('policy field ' + $sk + ' must be string, got ' + $raw.$sk.GetType().Name)
            }
            if ($raw.$sk.Length -gt 0) {
                $out[$sk] = [string]$raw.$sk
            }
            $matchedKeys++
        }
    }

    if ($matchedKeys -eq 0) {
        throw 'policy JSON contains no recognized policy fields'
    }
    return $out
}

function Save-GuardPolicyLastGood {
    param(
        [Parameter(Mandatory = $true)][string]$PolicyPath,
        [Parameter(Mandatory = $true)][string]$LastGoodPath
    )
    if (-not (Test-Path -LiteralPath $PolicyPath)) {
        throw ('cannot save last-good policy: missing ' + $PolicyPath)
    }
    $lgDir = Split-Path -Parent $LastGoodPath
    if ($lgDir -and -not (Test-Path -LiteralPath $lgDir)) {
        New-Item -ItemType Directory -Path $lgDir -Force | Out-Null
    }
    $tmpLg = $LastGoodPath + '.tmp.' + $PID
    $rawJson = [System.IO.File]::ReadAllText($PolicyPath, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($tmpLg, $rawJson, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmpLg -Destination $LastGoodPath -Force -ErrorAction Stop
}

function Invoke-GuardPolicyTransaction {
    param(
        [Parameter(Mandatory = $true)][string]$CanonicalPolicyPath,
        [string]$PendingPolicyPath = '',
        [Parameter(Mandatory = $true)][string]$LastGoodPolicyPath,
        [Parameter(Mandatory = $true)][scriptblock]$ApplyAction
    )

    $hadPrevCanonical = Test-Path -LiteralPath $CanonicalPolicyPath
    $prevCanonicalRaw = if ($hadPrevCanonical) {
        [System.IO.File]::ReadAllText($CanonicalPolicyPath, [System.Text.Encoding]::UTF8)
    }
    else { '' }

    $state = [pscustomobject]@{
        CanonicalStaged = $false
        PolicyCommitted = $false
        ExitCode        = 0
        ErrorMessage    = ''
    }

    $stageCanonical = ({
        param([string]$JsonText)
        $canDir = Split-Path -Parent $CanonicalPolicyPath
        if ($canDir -and -not (Test-Path -LiteralPath $canDir)) {
            New-Item -ItemType Directory -Path $canDir -Force | Out-Null
        }
        $tmpCan = $CanonicalPolicyPath + '.tmp.' + $PID
        [System.IO.File]::WriteAllText($tmpCan, $JsonText, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmpCan -Destination $CanonicalPolicyPath -Force -ErrorAction Stop
        $state.CanonicalStaged = $true
    }).GetNewClosure()

    $commitPolicy = ({
        Save-GuardPolicyLastGood -PolicyPath $CanonicalPolicyPath -LastGoodPath $LastGoodPolicyPath
        $state.PolicyCommitted = $true
    }).GetNewClosure()

    try {
        & $ApplyAction $state $stageCanonical $commitPolicy
    }
    catch {
        $state.ErrorMessage = $_.Exception.Message
        if ($state.ExitCode -eq 0 -or $state.ExitCode -eq -1) {
            $state.ExitCode = 5
        }
    }
    finally {
        if ($state.CanonicalStaged -and (-not $state.PolicyCommitted)) {
            try {
                if ($hadPrevCanonical) {
                    $tmpRestore = $CanonicalPolicyPath + '.restore.' + $PID
                    [System.IO.File]::WriteAllText($tmpRestore, $prevCanonicalRaw, (New-Object System.Text.UTF8Encoding($false)))
                    Move-Item -LiteralPath $tmpRestore -Destination $CanonicalPolicyPath -Force -ErrorAction Stop
                    Write-Host '    [!] restored previous guard-policy.json because policy application did not commit' -ForegroundColor Yellow
                }
                elseif (Test-Path -LiteralPath $CanonicalPolicyPath) {
                    Remove-Item -LiteralPath $CanonicalPolicyPath -Force -ErrorAction SilentlyContinue
                    Write-Host '    [!] removed uncommitted guard-policy.json because policy application did not commit' -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host ('    [!] failed to restore previous guard-policy.json: ' + $_.Exception.Message) -ForegroundColor Red
            }
        }
        if ($PendingPolicyPath -and ([System.IO.Path]::GetFileName($PendingPolicyPath) -ieq 'guard-policy.pending.json') -and (Test-Path -LiteralPath $PendingPolicyPath)) {
            Remove-Item -LiteralPath $PendingPolicyPath -Force -ErrorAction SilentlyContinue
        }
    }

    return $state
}

function Read-GuardPolicyStrict {
    param(
        [string]$PolicyPath,
        [System.Collections.IDictionary]$Defaults,
        [string]$LastGoodPath = '',
        [switch]$NoSaveLastGood,
        [switch]$IsDeployed
    )

    $buildFailClosed = {
        param([string]$Reason)
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
        $fc['PolicyWarning'] = $Reason
        return [pscustomobject]$fc
    }

    if (-not $PolicyPath -or -not (Test-Path -LiteralPath $PolicyPath)) {
        $lgErr = ''
        if ($LastGoodPath -and (Test-Path -LiteralPath $LastGoodPath)) {
            try {
                $lgParsed = ConvertFrom-StrictPolicyJson -FilePath $LastGoodPath -BaseDefaults $Defaults -RequireCriticalBools:([bool]$IsDeployed)
                $lgParsed['PolicyHealth'] = 'recovered-last-good'
                $lgParsed['PolicyWarning'] = 'primary policy missing; fell back to last-known-good'
                return [pscustomobject]$lgParsed
            }
            catch {
                $lgErr = '; last-good also failed: ' + $_.Exception.Message
            }
        }
        if ($IsDeployed -or ($LastGoodPath -and (Test-Path -LiteralPath $LastGoodPath))) {
            return (& $buildFailClosed ('primary policy missing on deployed host' + $lgErr + '; entered Fail-Closed state'))
        }
        $def = [ordered]@{}
        foreach ($key in $Defaults.Keys) { $def[$key] = $Defaults[$key] }
        $def['PolicyHealth'] = 'default'
        $def['PolicyWarning'] = ''
        return [pscustomobject]$def
    }

    $primaryErr = ''
    try {
        $parsed = ConvertFrom-StrictPolicyJson -FilePath $PolicyPath -BaseDefaults $Defaults -RequireCriticalBools:([bool]$IsDeployed)
        $parsed['PolicyHealth'] = 'ok'
        $parsed['PolicyWarning'] = ''
        return [pscustomobject]$parsed
    }
    catch {
        $primaryErr = $_.Exception.Message
    }

    if ($LastGoodPath -and (Test-Path -LiteralPath $LastGoodPath)) {
        try {
            $lgParsed = ConvertFrom-StrictPolicyJson -FilePath $LastGoodPath -BaseDefaults $Defaults -RequireCriticalBools:([bool]$IsDeployed)
            $lgParsed['PolicyHealth'] = 'recovered-last-good'
            $lgParsed['PolicyWarning'] = ('primary policy corrupt (' + $primaryErr + '); fell back to last-known-good')
            return [pscustomobject]$lgParsed
        }
        catch {
            $primaryErr += '; last-good also failed: ' + $_.Exception.Message
        }
    }

    # Fail-Closed: never silently relax security switches when policy JSON is corrupted.
    return (& $buildFailClosed ('policy corrupt (' + $primaryErr + ') and no valid last-known-good; entered Fail-Closed state'))
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

function Expand-GuardQuarantineNode {
    param(
        $Node,
        [int]$Depth,
        [hashtable]$State,
        $Seen,
        $List
    )

    if ($null -eq $Node) {
        $State.Malformed = $true
        return
    }
    if ($Node -is [string] -or $Node.GetType().IsPrimitive) {
        $State.Malformed = $true
        return
    }
    if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [System.Collections.IDictionary])) {
        if ($Depth -gt 0) { $State.Malformed = $true }
        foreach ($child in $Node) {
            Expand-GuardQuarantineNode -Node $child -Depth ($Depth + 1) -State $State -Seen $Seen -List $List
        }
        return
    }

    $nameProp = $Node.PSObject.Properties['Name']
    if ($nameProp -and $null -ne $nameProp.Value) {
        $nameStr = ([string]$nameProp.Value).Trim()
        if ($nameStr) {
            if ($Seen.Add($nameStr)) {
                $dispProp = $Node.PSObject.Properties['DisplayName']
                $qatProp = $Node.PSObject.Properties['QuarantinedAt']
                $dispVal = if ($dispProp -and $null -ne $dispProp.Value) { [string]$dispProp.Value } else { '' }
                $qatVal = if ($qatProp -and $null -ne $qatProp.Value) { [string]$qatProp.Value } else { '' }
                $List.Add([pscustomobject]@{
                    Name          = $nameStr
                    DisplayName   = $dispVal
                    QuarantinedAt = $qatVal
                })
            }
            else {
                $State.Malformed = $true
            }
            return
        }
    }

    $valProp = $Node.PSObject.Properties['value']
    if ($valProp) {
        $State.Malformed = $true
        Expand-GuardQuarantineNode -Node $valProp.Value -Depth ($Depth + 1) -State $State -Seen $Seen -List $List
        return
    }

    $State.Malformed = $true
}

function Read-GuardQuarantineList {
    param(
        [string]$Path
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Items        = [object[]]@()
            NeedsRewrite = $false
        }
    }

    $state = @{ Malformed = $false }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.Generic.List[object]

    try {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [pscustomobject]@{
                Items        = [object[]]@()
                NeedsRewrite = $true
            }
        }
        $trimmed = $raw.Trim()
        if ($trimmed -match '^\[\s*\]$') {
            return [pscustomobject]@{
                Items        = [object[]]@()
                NeedsRewrite = $false
            }
        }
        if (-not $trimmed.StartsWith('[')) {
            $state.Malformed = $true
        }
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        Expand-GuardQuarantineNode -Node $parsed -Depth 0 -State $state -Seen $seen -List $list
    }
    catch {
        $state.Malformed = $true
    }

    return [pscustomobject]@{
        Items        = [object[]]$list.ToArray()
        NeedsRewrite = [bool]$state.Malformed
    }
}

function Write-GuardQuarantineList {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][object[]]$Items = @()
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $clean = New-Object System.Collections.Generic.List[object]

    if ($null -ne $Items) {
        foreach ($item in $Items) {
            if ($null -eq $item) { continue }
            $nameProp = $item.PSObject.Properties['Name']
            if (-not $nameProp -or $null -eq $nameProp.Value) { continue }
            $nameStr = ([string]$nameProp.Value).Trim()
            if (-not $nameStr) { continue }
            if (-not $seen.Add($nameStr)) { continue }
            $dispProp = $item.PSObject.Properties['DisplayName']
            $qatProp = $item.PSObject.Properties['QuarantinedAt']
            $dispVal = if ($dispProp -and $null -ne $dispProp.Value) { [string]$dispProp.Value } else { '' }
            $qatVal = if ($qatProp -and $null -ne $qatProp.Value) { [string]$qatProp.Value } else { '' }
            $clean.Add([pscustomobject]@{
                Name          = $nameStr
                DisplayName   = $dispVal
                QuarantinedAt = $qatVal
            })
        }
    }

    if ($clean.Count -eq 0) {
        $json = '[]'
    }
    else {
        [object[]]$arr = $clean.ToArray()
        $json = ConvertTo-Json -InputObject $arr -Depth 4
        if (-not $json.TrimStart().StartsWith('[')) {
            $json = '[' + $json + ']'
        }
    }

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $tmpPath = $Path + '.tmp.' + $PID
    [System.IO.File]::WriteAllText($tmpPath, $json + [Environment]::NewLine, $utf8NoBom)
    Move-Item -LiteralPath $tmpPath -Destination $Path -Force
}

function Test-GuardPublicNodeIpv4 {
    param([string]$IpStr)

    if (-not $IpStr) { return $false }
    $t = $IpStr.Trim()
    if (-not $t) { return $false }
    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($t, [ref]$ipObj)) { return $false }
    if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    if ($ipObj.ToString() -ne $t) { return $false }

    $b = $ipObj.GetAddressBytes()
    $o0 = [int]$b[0]
    $o1 = [int]$b[1]
    if ($o0 -eq 0 -or $o0 -eq 10 -or $o0 -eq 127 -or $o0 -ge 224) { return $false }
    if ($o0 -eq 169 -and $o1 -eq 254) { return $false }
    if ($o0 -eq 172 -and $o1 -ge 16 -and $o1 -le 31) { return $false }
    if ($o0 -eq 192 -and $o1 -eq 168) { return $false }
    return $true
}

function Test-GuardPortSpec {
    param([string]$Spec)

    if (-not $Spec) { return $false }
    $t = $Spec.Trim()
    if ($t -match '^(\d{1,5})$') {
        $p = [int]$matches[1]
        return ($p -ge 1 -and $p -le 65535)
    }
    if ($t -match '^(\d{1,5})-(\d{1,5})$') {
        $p1 = [int]$matches[1]
        $p2 = [int]$matches[2]
        return ($p1 -ge 1 -and $p2 -le 65535 -and $p1 -le $p2)
    }
    return $false
}

function Read-GuardCandidateNodes {
    param([string]$Path)

    $empty = [pscustomobject]@{
        Enabled   = $false
        Ips       = [string[]]@()
        TcpPorts  = [string[]]@()
        UdpPorts  = [string[]]@()
        UpdatedAt = ''
    }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $empty }

    try {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $empty }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj -or ($obj -is [string])) { return $empty }

        $ipSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $ipList = New-Object System.Collections.Generic.List[string]
        if ($obj.PSObject.Properties['Ips'] -and $null -ne $obj.Ips) {
            foreach ($candIp in @($obj.Ips)) {
                $s = if ($null -ne $candIp) { ([string]$candIp).Trim() } else { '' }
                if ((Test-GuardPublicNodeIpv4 -IpStr $s) -and $ipSet.Add($s)) {
                    $ipList.Add($s)
                }
            }
        }

        $tcpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $tcpList = New-Object System.Collections.Generic.List[string]
        if ($obj.PSObject.Properties['TcpPorts'] -and $null -ne $obj.TcpPorts) {
            foreach ($tp in @($obj.TcpPorts)) {
                $s = if ($null -ne $tp) { ([string]$tp).Trim() } else { '' }
                if ((Test-GuardPortSpec -Spec $s) -and $tcpSet.Add($s)) {
                    $tcpList.Add($s)
                }
            }
        }

        $udpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $udpList = New-Object System.Collections.Generic.List[string]
        if ($obj.PSObject.Properties['UdpPorts'] -and $null -ne $obj.UdpPorts) {
            foreach ($up in @($obj.UdpPorts)) {
                $s = if ($null -ne $up) { ([string]$up).Trim() } else { '' }
                if ((Test-GuardPortSpec -Spec $s) -and $udpSet.Add($s)) {
                    $udpList.Add($s)
                }
            }
        }

        $upd = if ($obj.PSObject.Properties['UpdatedAt'] -and $null -ne $obj.UpdatedAt) { [string]$obj.UpdatedAt } else { '' }
        $isEnabled = ($ipList.Count -gt 0) -and (($tcpList.Count -gt 0) -or ($udpList.Count -gt 0))
        return [pscustomobject]@{
            Enabled   = $isEnabled
            Ips       = [string[]]$ipList.ToArray()
            TcpPorts  = [string[]]$tcpList.ToArray()
            UdpPorts  = [string[]]$udpList.ToArray()
            UpdatedAt = $upd
        }
    }
    catch {
        return $empty
    }
}

function Write-GuardCandidateNodes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string[]]$Ips = @(),
        [AllowNull()][string[]]$TcpPorts = @(),
        [AllowNull()][string[]]$UdpPorts = @()
    )

    $ipSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $ipList = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Ips) {
        foreach ($candIp in $Ips) {
            $s = if ($null -ne $candIp) { ([string]$candIp).Trim() } else { '' }
            if ((Test-GuardPublicNodeIpv4 -IpStr $s) -and $ipSet.Add($s)) { $ipList.Add($s) }
        }
    }

    $tcpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $tcpList = New-Object System.Collections.Generic.List[string]
    if ($null -ne $TcpPorts) {
        foreach ($tp in $TcpPorts) {
            $s = if ($null -ne $tp) { ([string]$tp).Trim() } else { '' }
            if ((Test-GuardPortSpec -Spec $s) -and $tcpSet.Add($s)) { $tcpList.Add($s) }
        }
    }

    $udpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $udpList = New-Object System.Collections.Generic.List[string]
    if ($null -ne $UdpPorts) {
        foreach ($up in $UdpPorts) {
            $s = if ($null -ne $up) { ([string]$up).Trim() } else { '' }
            if ((Test-GuardPortSpec -Spec $s) -and $udpSet.Add($s)) { $udpList.Add($s) }
        }
    }

    $ipArr = @($ipList.ToArray() | Sort-Object)
    $tcpArr = @($tcpList.ToArray() | Sort-Object)
    $udpArr = @($udpList.ToArray() | Sort-Object)

    $payload = [pscustomobject]@{
        UpdatedAt = (Get-Date).ToString('o')
        Ips       = [string[]]$ipArr
        TcpPorts  = [string[]]$tcpArr
        UdpPorts  = [string[]]$udpArr
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 4
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $tmpPath = $Path + '.tmp.' + $PID
    [System.IO.File]::WriteAllText($tmpPath, $json + [Environment]::NewLine, $utf8NoBom)
    Move-Item -LiteralPath $tmpPath -Destination $Path -Force
}
