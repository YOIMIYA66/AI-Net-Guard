<#
.SYNOPSIS
    AI-Net-Guard v5.6 - build standalone zero-dependency Windows native GUI executable (dist\AI-Net-Guard.exe).

.DESCRIPTION
    1. Verifies pure-ASCII encoding & PowerShell AST syntax across all *.ps1 scripts.
    2. Generates multi-resolution vector shield icon (gui\obj\app.ico: 16, 32, 48, 256 px).
    3. Packs all 16 core PowerShell scripts + cn-ipv4.txt + ai-domains.txt + docs
       into gui\obj\payload.zip (embedded inside AI-Net-Guard.exe).
    4. Compiles gui\AI-Net-Guard.Gui.csproj (net48 native Windows WPF, zero external DLLs)
       into dist\AI-Net-Guard.exe and writes dist\AI-Net-Guard.exe.sha256.
    5. Optional -RunSmokeTest builds an isolated asInvoker test binary, renders the
       live WPF UI, exercises all 15 toggles & presets, and verifies payload extraction.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [switch]$RunSmokeTest,
    [string]$SmokeOutDir = ''
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $RepoRoot = Split-Path -Parent $scriptDir
}

$GuiDir = Join-Path $RepoRoot 'gui'
$ObjDir = Join-Path $GuiDir 'obj'
$DistDir = Join-Path $RepoRoot 'dist'
New-Item -ItemType Directory -Path $ObjDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

function Write-BuildStep([string]$msg) { Write-Host ('[BUILD] ' + $msg) -ForegroundColor Cyan }

# ------------------------------------------------------------------ 1. Script hygiene & AST syntax check
Write-BuildStep 'verifying pure-ASCII encoding and AST syntax across PowerShell scripts'
$rootScripts = @(Get-ChildItem -Path $RepoRoot -Filter '*.ps1' -File | Sort-Object Name)
if ($rootScripts.Count -lt 16) {
    throw ('Expected at least 16 root PowerShell scripts, found ' + $rootScripts.Count)
}

foreach ($sf in ($rootScripts + @(Get-Item -LiteralPath $PSCommandPath))) {
    $rawBytes = [System.IO.File]::ReadAllBytes($sf.FullName)
    $badBytes = @($rawBytes | Where-Object { $_ -gt 127 })
    if ($badBytes.Count -gt 0) {
        throw ('Non-ASCII byte(s) detected in ' + $sf.FullName + ' (count=' + $badBytes.Count + ')')
    }
    $tok = $null; $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($sf.FullName, [ref]$tok, [ref]$errs)
    if ($errs.Count -gt 0) {
        throw ('Syntax error in ' + $sf.Name + ': ' + $errs[0].Message)
    }
}
Write-Host ('        checked ' + ($rootScripts.Count + 1) + ' scripts: 100% pure ASCII, 0 parse errors') -ForegroundColor Green

# ------------------------------------------------------------------ 2. Generate vector multi-size app.ico
Write-BuildStep 'generating vector shield icon (gui\obj\app.ico)'
Add-Type -AssemblyName System.Drawing

function New-ShieldIconPngBytes([int]$Size) {
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)

        $pad = [float]($Size * 0.06)
        $rect = New-Object System.Drawing.RectangleF($pad, $pad, [float]($Size - 2 * $pad), [float]($Size - 2 * $pad))
        $radius = [float]($Size * 0.22)

        # Rounded square gradient background
        $bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $d = $radius * 2
        $bgPath.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
        $bgPath.AddArc($rect.Right - $d, $rect.Y, $d, $d, 270, 90)
        $bgPath.AddArc($rect.Right - $d, $rect.Bottom - $d, $d, $d, 0, 90)
        $bgPath.AddArc($rect.X, $rect.Bottom - $d, $d, $d, 90, 90)
        $bgPath.CloseFigure()

        $bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $rect,
            [System.Drawing.Color]::FromArgb(255, 37, 99, 235),
            [System.Drawing.Color]::FromArgb(255, 15, 23, 42),
            45.0
        )
        $g.FillPath($bgBrush, $bgPath)
        $bgBrush.Dispose()
        $bgPath.Dispose()

        # White shield silhouette
        $s = [float]$Size
        $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
        $pts = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF(($s * 0.50), ($s * 0.17))),
            (New-Object System.Drawing.PointF(($s * 0.78), ($s * 0.28))),
            (New-Object System.Drawing.PointF(($s * 0.76), ($s * 0.55))),
            (New-Object System.Drawing.PointF(($s * 0.50), ($s * 0.83))),
            (New-Object System.Drawing.PointF(($s * 0.24), ($s * 0.55))),
            (New-Object System.Drawing.PointF(($s * 0.22), ($s * 0.28)))
        )
        $shield.AddPolygon($pts)
        $whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(248, 255, 255, 255))
        $g.FillPath($whiteBrush, $shield)
        $whiteBrush.Dispose()
        $shield.Dispose()

        # Checkmark inside shield
        $penWidth = [math]::Max(1.6, [float]($s * 0.085))
        $checkPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 29, 78, 216), $penWidth)
        $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $checkPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $checkPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $checkPts = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF(($s * 0.37), ($s * 0.51))),
            (New-Object System.Drawing.PointF(($s * 0.47), ($s * 0.61))),
            (New-Object System.Drawing.PointF(($s * 0.65), ($s * 0.40)))
        )
        $g.DrawLines($checkPen, $checkPts)
        $checkPen.Dispose()

        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        return ,$ms.ToArray()
    }
    finally {
        $g.Dispose()
        $bmp.Dispose()
    }
}

$icoPath = Join-Path $ObjDir 'app.ico'
$sizes = @(16, 32, 48, 256)
$pngBlobs = @()
foreach ($sz in $sizes) {
    $pngBlobs += ,(New-ShieldIconPngBytes -Size $sz)
}

$icoStream = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($icoStream)
$bw.Write([uint16]0)             # Reserved
$bw.Write([uint16]1)             # Type = 1 (ICO)
$bw.Write([uint16]$sizes.Count)  # Image count
$offset = 6 + (16 * $sizes.Count)
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $blob = $pngBlobs[$i]
    $wByte = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
    $bw.Write($wByte)
    $bw.Write($wByte)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]32)
    $bw.Write([uint32]$blob.Length)
    $bw.Write([uint32]$offset)
    $offset += $blob.Length
}
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $bw.Write($pngBlobs[$i])
}
$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $icoStream.ToArray())
$bw.Dispose()
$icoStream.Dispose()

# ------------------------------------------------------------------ 3. Pack embedded payload.zip
Write-BuildStep 'packing core scripts and CN IPv4 database into gui\obj\payload.zip'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$payloadZip = Join-Path $ObjDir 'payload.zip'
if (Test-Path -LiteralPath $payloadZip) {
    Remove-Item -LiteralPath $payloadZip -Force
}

$payloadFiles = @()
$payloadFiles += $rootScripts
foreach ($extraName in @('cn-ipv4.txt', 'ai-domains.txt', 'LICENSE', 'README.md', 'CURRENT-IMPLEMENTATION.md', 'Emergency-Rescue.bat')) {
    $ep = Join-Path $RepoRoot $extraName
    if (-not (Test-Path -LiteralPath $ep)) {
        throw ('Missing required payload file: ' + $ep)
    }
    $payloadFiles += (Get-Item -LiteralPath $ep)
}

$zipFs = New-Object System.IO.FileStream($payloadZip, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$zip = New-Object System.IO.Compression.ZipArchive($zipFs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
try {
    foreach ($pf in $payloadFiles) {
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip,
            $pf.FullName,
            $pf.Name,
            [System.IO.Compression.CompressionLevel]::Optimal
        )
    }
}
finally {
    $zip.Dispose()
    $zipFs.Dispose()
}
$zipSizeKb = [math]::Round(((Get-Item -LiteralPath $payloadZip).Length / 1KB), 1)
Write-Host ('        packed ' + $payloadFiles.Count + ' files -> payload.zip (' + $zipSizeKb + ' KB)') -ForegroundColor Green

# ------------------------------------------------------------------ 4. Compile Release single-file AI-Net-Guard.exe
Write-BuildStep 'compiling Windows-native WPF executable (net48, Release)'
$csproj = Join-Path $GuiDir 'AI-Net-Guard.Gui.csproj'
$releaseOut = Join-Path $GuiDir 'bin\Release\net48'
if (Test-Path -LiteralPath $releaseOut) {
    Remove-Item -LiteralPath $releaseOut -Recurse -Force
}

& dotnet build $csproj -c Release -nologo -v minimal
if ($LASTEXITCODE -ne 0) {
    throw ('dotnet build failed with exit code ' + $LASTEXITCODE)
}

$builtExe = Join-Path $releaseOut 'AI-Net-Guard.exe'
if (-not (Test-Path -LiteralPath $builtExe)) {
    throw ('Expected output executable missing: ' + $builtExe)
}

$extraDlls = @(Get-ChildItem -Path $releaseOut -Filter '*.dll' -File -ErrorAction SilentlyContinue)
if ($extraDlls.Count -gt 0) {
    throw ('Zero-dependency single-EXE check failed! Found external DLL(s): ' + (($extraDlls | ForEach-Object { $_.Name }) -join ', '))
}

# Clean dist\ and copy standalone AI-Net-Guard.exe
$distExe = Join-Path $DistDir 'AI-Net-Guard.exe'
if (Test-Path -LiteralPath $distExe) {
    try {
        Remove-Item -LiteralPath $distExe -Force -ErrorAction Stop
    }
    catch {
        $oldTmp = Join-Path $DistDir ('AI-Net-Guard.locked.' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp')
        Move-Item -LiteralPath $distExe -Destination $oldTmp -Force
    }
}
Get-ChildItem -Path $DistDir -Filter '*.sha256' -ErrorAction SilentlyContinue | Remove-Item -Force
Copy-Item -LiteralPath $builtExe -Destination $distExe -Force
$distRescue = Join-Path $DistDir 'Emergency-Rescue.bat'
Copy-Item -LiteralPath (Join-Path $RepoRoot 'Emergency-Rescue.bat') -Destination $distRescue -Force
$distZip = Join-Path $DistDir 'AI-Net-Guard-portable.zip'
Copy-Item -LiteralPath $payloadZip -Destination $distZip -Force

$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $exeBytes = [System.IO.File]::ReadAllBytes($distExe)
    $hashHex = [System.BitConverter]::ToString($sha.ComputeHash($exeBytes)).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}

$shaFile = Join-Path $DistDir 'AI-Net-Guard.exe.sha256'
Set-Content -LiteralPath $shaFile -Value ($hashHex + '  AI-Net-Guard.exe') -Encoding ASCII

$exeSizeKb = [math]::Round(($exeBytes.Length / 1KB), 1)
Write-Host ''
Write-Host '=== Build Succeeded ===' -ForegroundColor Green
Write-Host ('  Executable : ' + $distExe)
Write-Host ('  Size       : ' + $exeSizeKb + ' KB (single-file, 0 external DLLs, UAC requireAdministrator)')
Write-Host ('  SHA-256    : ' + $hashHex)

# ------------------------------------------------------------------ 5. Optional Automated UI & Payload Smoke Test
if ($RunSmokeTest) {
    Write-Host ''
    Write-BuildStep 'running automated WPF UI instantiation, toggle & payload extraction smoke test'
    if (-not $SmokeOutDir) {
        $SmokeOutDir = Join-Path $ObjDir 'smoke-out'
    }
    if (Test-Path -LiteralPath $SmokeOutDir) {
        Remove-Item -LiteralPath $SmokeOutDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $SmokeOutDir -Force | Out-Null

    $smokeBinDir = Join-Path $env:TEMP ('ai-guard-smoke-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $smokeBinDir -Force | Out-Null

    & dotnet build $csproj -c Release -p:SmokeTestBuild=true -o $smokeBinDir -nologo -v minimal
    if ($LASTEXITCODE -ne 0) {
        throw 'SmokeTest build failed'
    }

    $smokeExe = Join-Path $smokeBinDir 'AI-Net-Guard.exe'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $smokeExe
    $psi.Arguments = '--smoke-test "' + $SmokeOutDir + '"'
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()
    $code = $proc.ExitCode
    $proc.Dispose()
    Remove-Item -LiteralPath $smokeBinDir -Recurse -Force -ErrorAction SilentlyContinue

    $errPath = Join-Path $SmokeOutDir 'smoke-error.txt'
    if (Test-Path -LiteralPath $errPath) {
        Write-Host (Get-Content -LiteralPath $errPath -Raw) -ForegroundColor Red
    }
    if ($code -ne 0) {
        throw ('GUI smoke test exited with code ' + $code)
    }

    $repPath = Join-Path $SmokeOutDir 'smoke-report.txt'
    if (-not (Test-Path -LiteralPath $repPath)) {
        throw 'GUI smoke test did not produce smoke-report.txt'
    }
    Get-Content -LiteralPath $repPath | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Green }
}
