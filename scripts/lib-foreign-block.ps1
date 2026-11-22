# AI-Net-Guard v5.8.2 - shared helper for explicit physical-NIC foreign IPv4 block rule
# Pure ASCII script. Dot-sourced by 02-killswitch.ps1, 07-mode.ps1, 10-sync-node-rule.ps1, 14-apply-policy.ps1.
#
# Why this exists:
#   Third-party WFP callout drivers (e.g. Huorong hrwfpdrv, IDM idmwfp, NetFilter nfwfp) can return
#   a soft FWP_ACTION_PERMIT at ALE_AUTH_CONNECT_V4, which overrides Windows Defender Firewall's
#   soft DefaultOutboundAction=Block. An explicit Windows Firewall Action=Block rule (FWP_ACTION_BLOCK)
#   vetoes soft permits across sublayers and guarantees fail-closed physical egress.

function ConvertTo-UInt64IpV4([string]$IpStr) {
    $b = ([System.Net.IPAddress]::Parse($IpStr)).GetAddressBytes()
    return (([uint64]$b[0] -shl 24) -bor ([uint64]$b[1] -shl 16) -bor ([uint64]$b[2] -shl 8) -bor [uint64]$b[3])
}

function ConvertFrom-UInt64IpV4([uint64]$Val) {
    return (([string](($Val -shr 24) -band 255)) + '.' + ([string](($Val -shr 16) -band 255)) + '.' + ([string](($Val -shr 8) -band 255)) + '.' + ([string]($Val -band 255)))
}

function Get-ForeignComplementRanges {
    param(
        [string[]]$CnPrefixes = @(),
        [string[]]$NodeIps = @(),
        [bool]$AllowLan = $true,
        [bool]$AllowNcsi = $true
    )

    [uint64]$mask32 = 4294967295
    $allowList = New-Object System.Collections.Generic.List[string]
    foreach ($base in @('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3', '223.5.5.5/32', '223.6.6.6/32')) {
        $allowList.Add($base)
    }
    if ($AllowLan) {
        foreach ($lan in @('10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16')) {
            $allowList.Add($lan)
        }
    }
    if ($AllowNcsi) {
        $allowList.Add('13.107.4.52/32')
    }
    foreach ($nip in @($NodeIps)) {
        if ($nip -and ($nip -match '^\d{1,3}(\.\d{1,3}){3}$')) {
            $allowList.Add($nip + '/32')
        }
    }
    foreach ($cn in @($CnPrefixes)) {
        if ($cn) { $allowList.Add($cn) }
    }

    $intervals = New-Object System.Collections.Generic.List[uint64]
    foreach ($entry in $allowList) {
        $t = $entry.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $slash = $t.IndexOf('/')
        try {
            if ($slash -lt 0) {
                $ipStr = $t; $plen = 32
            }
            else {
                $ipStr = $t.Substring(0, $slash); $plen = [int]$t.Substring($slash + 1)
            }
            if ($plen -lt 0 -or $plen -gt 32) { continue }
            [uint64]$ipU = ConvertTo-UInt64IpV4 $ipStr
            [uint64]$mask = if ($plen -eq 0) { [uint64]0 } else { ($mask32 -shl (32 - $plen)) -band $mask32 }
            [uint64]$start = $ipU -band $mask
            [uint64]$end = $start -bor ($mask32 -bxor $mask)
            $intervals.Add(($start -shl 32) -bor $end)
        }
        catch { }
    }

    $arr = $intervals.ToArray()
    [Array]::Sort($arr)

    $comp = New-Object System.Collections.Generic.List[string]
    [uint64]$cursor = 0
    foreach ($iv in $arr) {
        [uint64]$s = $iv -shr 32
        [uint64]$e = $iv -band $mask32
        if ($s -gt $cursor) {
            $comp.Add((ConvertFrom-UInt64IpV4 $cursor) + '-' + (ConvertFrom-UInt64IpV4 ($s - 1)))
        }
        [uint64]$next = $e + 1
        if ($next -gt $cursor) { $cursor = $next }
    }
    if ($cursor -le $mask32) {
        $comp.Add((ConvertFrom-UInt64IpV4 $cursor) + '-255.255.255.255')
    }
    return ,$comp.ToArray()
}

function Sync-ForeignPhysicalBlockRule {
    param(
        [string]$Root = 'C:\AI-Net-Guard',
        [string[]]$PhysicalAliases = @(),
        [string[]]$NodeIps = @(),
        [bool]$AllowCnDirect = $true,
        [bool]$AllowLan = $true,
        [bool]$AllowNcsi = $true,
        [switch]$Force
    )

    $ruleName = 'AI-Guard-Block-Foreign-Physical'
    $physClean = @($PhysicalAliases | Where-Object { $_ -and $_ -notmatch '(?i)tun|wintun|sing-tun|mihomo|loopback' } | Sort-Object -Unique)
    if ($physClean.Count -eq 0) { return $false }

    $nodeClean = @($NodeIps | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Sort-Object -Unique)
    $cnFile = Join-Path $Root 'cn-ipv4.txt'
    $cnStamp = 'nocn'
    if ($AllowCnDirect -and (Test-Path -LiteralPath $cnFile)) {
        $ci = Get-Item -LiteralPath $cnFile -ErrorAction SilentlyContinue
        if ($ci) { $cnStamp = ($ci.Length.ToString() + ':' + $ci.LastWriteTimeUtc.Ticks.ToString()) }
    }

    $metaFile = Join-Path $Root 'backup\foreign-block.meta'
    $wantSig = ([int]$AllowCnDirect).ToString() + '|' + ([int]$AllowLan).ToString() + '|' + ([int]$AllowNcsi).ToString() + '|' + ($physClean -join ',') + '|' + ($nodeClean -join ',') + '|' + $cnStamp
    if (-not $Force -and (Test-Path -LiteralPath $metaFile)) {
        try {
            # UTF-8 on purpose: adapter aliases are localised (e.g. the Chinese name of
            # Ethernet), and an ASCII round-trip turned every non-ASCII name into '?', so the
            # stored signature never matched the live alias list again and the rule was
            # rebuilt - with a delete/recreate gap - on every single run.
            $oldSig = [System.IO.File]::ReadAllText($metaFile, [System.Text.Encoding]::UTF8).Trim()
            if ($oldSig -eq $wantSig) {
                $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                if ($existing -and $existing.Enabled -eq 'True') { return $false }
            }
        }
        catch { }
    }

    $cnPrefixes = @()
    if ($AllowCnDirect -and (Test-Path -LiteralPath $cnFile)) {
        $cnPrefixes = @([System.IO.File]::ReadAllLines($cnFile) | Where-Object { $_ -and (-not $_.StartsWith('#')) -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') })
    }

    $ranges = Get-ForeignComplementRanges -CnPrefixes $cnPrefixes -NodeIps $nodeClean -AllowLan $AllowLan -AllowNcsi $AllowNcsi
    if ($ranges.Count -eq 0) { return $false }

    # Rewrite in place when the rule already exists: removing it first left a window with no
    # explicit BLOCK rule, i.e. exactly the soft-permit-only state this rule exists to veto.
    $oldRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($oldRule) {
        try {
            Set-NetFirewallRule -InputObject $oldRule -InterfaceAlias $physClean -RemoteAddress $ranges `
                -Action Block -Profile Any -Enabled True -ErrorAction Stop
        }
        catch {
            $oldRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
                -Direction Outbound -Action Block -Protocol Any `
                -InterfaceAlias $physClean -RemoteAddress $ranges -Profile Any -Enabled True `
                -Description 'Explicitly block non-CN/non-LAN/non-Node IPv4 egress on physical NICs (vetoes third-party WFP soft-permit callouts).' | Out-Null
        }
    }
    else {
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
            -Direction Outbound -Action Block -Protocol Any `
            -InterfaceAlias $physClean -RemoteAddress $ranges -Profile Any -Enabled True `
            -Description 'Explicitly block non-CN/non-LAN/non-Node IPv4 egress on physical NICs (vetoes third-party WFP soft-permit callouts).' | Out-Null
    }

    $metaDir = Split-Path -Parent $metaFile
    if (-not (Test-Path -LiteralPath $metaDir)) { New-Item -ItemType Directory -Path $metaDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($metaFile, $wantSig, (New-Object System.Text.UTF8Encoding($false)))
    return $true
}
