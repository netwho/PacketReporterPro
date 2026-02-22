# PacketReporter Pro - Windows Installer
# Native C/C++ Wireshark plugin installer
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
#   powershell -ExecutionPolicy Bypass -File install.ps1 -SystemWide
#   powershell -ExecutionPolicy Bypass -File install.ps1 -DllPath C:\path\to\packetreporterpro.dll
#
# Or via the launcher:
#   install.bat

param(
    [switch]$Uninstall,
    [switch]$SystemWide,
    [string]$DllPath = "",
    [string]$WiresharkDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ────────────────────────────────────────────────────

$ScriptVersion   = "0.2.5"
$PluginName      = "packetreporterpro"
$PluginDll       = "$PluginName.dll"
$LuaPluginName   = "packet_reporter.lua"
$ConfigDirName   = ".packet_reporter"
$RequiredWsMajor = 4
$RequiredWsMinor = 6

# Cairo runtime DLLs needed by the plugin for PDF rendering.
# The official Wireshark installer already ships these, so this check is
# only a safety net for custom or minimal installations.
$CairoRuntimeDlls = @(
    "cairo-2.dll",
    "pixman-1-0.dll",
    "freetype.dll",
    "fontconfig-1.dll",
    "libpng16.dll",
    "libexpat.dll"
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = (Resolve-Path "$ScriptDir\..\..").Path

# ── Output helpers ───────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "    PacketReporter Pro - Windows Installer  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "    Native Wireshark Plugin (C/C++)" -ForegroundColor Cyan
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section([string]$title) {
    Write-Host ""
    Write-Host "  --- $title ---" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Ok([string]$msg)     { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Warn([string]$msg)   { Write-Host "  [!]    $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)    { Write-Host "  [X]    $msg" -ForegroundColor Red }
function Write-Info([string]$msg)   { Write-Host "  [->]   $msg" -ForegroundColor White }
function Write-Detail([string]$msg) { Write-Host "         $msg" }

function Write-Step([int]$num, [int]$total, [string]$msg) {
    Write-Host ""
    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  [$num/$total] $msg" -ForegroundColor Cyan
    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
    Start-Sleep -Milliseconds 400
}

function Write-Pause([int]$ms = 300) { Start-Sleep -Milliseconds $ms }

# ── Wireshark detection ─────────────────────────────────────────

function Find-Wireshark {
    $result = [PSCustomObject]@{
        Found      = $false
        ExePath    = $null
        InstallDir = $null
        Version    = $null
        Major      = 0
        Minor      = 0
        Patch      = 0
    }

    # If user supplied a directory, check there first
    if ($WiresharkDir -and (Test-Path $WiresharkDir)) {
        $exe = Join-Path $WiresharkDir "Wireshark.exe"
        if (Test-Path $exe) {
            $result.Found      = $true
            $result.ExePath    = $exe
            $result.InstallDir = $WiresharkDir
            Get-WiresharkVersion $result
            return $result
        }
    }

    # Method 1: Windows Registry (most reliable for MSI/EXE installs)
    $regLocations = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{*}",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{*}",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{*}"
    )

    # Try the specific Wireshark key first (fast path)
    try {
        $wsKey = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" -ErrorAction SilentlyContinue
        if ($wsKey -and $wsKey.InstallLocation) {
            $dir = $wsKey.InstallLocation.TrimEnd('\')
            $exe = Join-Path $dir "Wireshark.exe"
            if (Test-Path $exe) {
                $result.Found      = $true
                $result.ExePath    = $exe
                $result.InstallDir = $dir
                if ($wsKey.DisplayVersion) {
                    $result.Version = $wsKey.DisplayVersion
                    Parse-Version $result $wsKey.DisplayVersion
                } else {
                    Get-WiresharkVersion $result
                }
                return $result
            }
        }
    } catch {}

    # Scan all uninstall registry keys
    foreach ($regPath in $regLocations) {
        try {
            $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                       Where-Object { $_.DisplayName -like "*Wireshark*" }
            foreach ($entry in $entries) {
                $dir = $null
                if ($entry.InstallLocation) {
                    $dir = $entry.InstallLocation.TrimEnd('\')
                } elseif ($entry.UninstallString) {
                    $dir = Split-Path ($entry.UninstallString -replace '"', '') -Parent -ErrorAction SilentlyContinue
                }
                if ($dir) {
                    $exe = Join-Path $dir "Wireshark.exe"
                    if (Test-Path $exe) {
                        $result.Found      = $true
                        $result.ExePath    = $exe
                        $result.InstallDir = $dir
                        if ($entry.DisplayVersion) {
                            $result.Version = $entry.DisplayVersion
                            Parse-Version $result $entry.DisplayVersion
                        } else {
                            Get-WiresharkVersion $result
                        }
                        return $result
                    }
                }
            }
        } catch {}
    }

    # Method 2: Well-known filesystem paths
    $progFiles   = [Environment]::GetFolderPath('ProgramFiles')
    $progFilesX86 = ${env:ProgramFiles(x86)}
    if (-not $progFilesX86) {
        $progFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    }
    $knownPaths = @(
        (Join-Path $progFiles "Wireshark"),
        (Join-Path $progFilesX86 "Wireshark"),
        "C:\Program Files\Wireshark",
        "D:\Program Files\Wireshark",
        "C:\Wireshark"
    ) | Select-Object -Unique

    foreach ($dir in $knownPaths) {
        if (-not $dir) { continue }
        $exe = Join-Path $dir "Wireshark.exe"
        if (Test-Path $exe) {
            $result.Found      = $true
            $result.ExePath    = $exe
            $result.InstallDir = $dir
            Get-WiresharkVersion $result
            return $result
        }
    }

    # Method 3: PATH lookup (wireshark or tshark)
    foreach ($cmd in @("Wireshark", "tshark")) {
        $found = Get-Command "$cmd.exe" -ErrorAction SilentlyContinue
        if ($found) {
            $dir = Split-Path $found.Source -Parent
            $exe = Join-Path $dir "Wireshark.exe"
            $result.Found      = $true
            $result.ExePath    = if (Test-Path $exe) { $exe } else { $found.Source }
            $result.InstallDir = $dir
            if ($cmd -eq "tshark") {
                try {
                    $output = & $found.Source --version 2>$null | Select-Object -First 1
                    if ($output -match '(\d+\.\d+\.\d+)') {
                        $result.Version = $Matches[1]
                        Parse-Version $result $Matches[1]
                    }
                } catch {}
            } else {
                Get-WiresharkVersion $result
            }
            return $result
        }
    }

    return $result
}

function Get-WiresharkVersion($ws) {
    if ($ws.Version) { return }
    if (-not $ws.ExePath -or -not (Test-Path $ws.ExePath)) { return }

    # Try FileVersionInfo
    try {
        $vi = (Get-Item $ws.ExePath).VersionInfo
        foreach ($prop in @('ProductVersion', 'FileVersion')) {
            $v = $vi.$prop
            if ($v -and $v -match '\d+\.\d+') {
                $ws.Version = $v.Trim()
                Parse-Version $ws $v
                return
            }
        }
    } catch {}

    # Try running tshark --version (quieter than Wireshark GUI)
    try {
        $tshark = Join-Path (Split-Path $ws.ExePath -Parent) "tshark.exe"
        if (Test-Path $tshark) {
            $output = & $tshark --version 2>$null | Select-Object -First 1
            if ($output -match '(\d+\.\d+\.\d+)') {
                $ws.Version = $Matches[1]
                Parse-Version $ws $Matches[1]
            }
        }
    } catch {}
}

function Parse-Version($ws, [string]$verStr) {
    if ($verStr -match '(\d+)\.(\d+)\.?(\d*)') {
        $ws.Major = [int]$Matches[1]
        $ws.Minor = [int]$Matches[2]
        $ws.Patch = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
    }
}

# ── Plugin version directory ─────────────────────────────────────

function Get-PluginVersionDir([int]$major, [int]$minor) {
    $dotFmt  = "$major.$minor"
    $dashFmt = "$major-$minor"

    $personalBase = Join-Path $env:APPDATA "Wireshark\plugins"

    # Wireshark uses dot format (e.g. "4.6") for version directories.
    # Check dot format first, then fall back to dash format.
    if (Test-Path (Join-Path $personalBase $dotFmt))  { return $dotFmt }
    if (Test-Path (Join-Path $personalBase $dashFmt)) { return $dashFmt }

    # Check global plugins dir
    if ($script:wsInfo -and $script:wsInfo.InstallDir) {
        $globalBase = Join-Path $script:wsInfo.InstallDir "plugins"
        if (Test-Path (Join-Path $globalBase $dotFmt))  { return $dotFmt }
        if (Test-Path (Join-Path $globalBase $dashFmt)) { return $dashFmt }
    }

    # Default: dot format (Wireshark's convention)
    return $dotFmt
}

# ── Find the plugin DLL ─────────────────────────────────────────

function Find-PluginDll {
    $searchPaths = @()

    # Explicit path from parameter
    if ($DllPath -and (Test-Path $DllPath)) {
        return $DllPath
    }

    # Alongside the installer script
    $searchPaths += Join-Path $ScriptDir $PluginDll

    # binaries\windows\ in the project tree
    $searchPaths += Join-Path $ProjectDir "binaries\windows\$PluginDll"

    # Already installed (per-user) - any version dir format
    $personalBase = Join-Path $env:APPDATA "Wireshark\plugins"
    foreach ($fmt in @("$RequiredWsMajor-$RequiredWsMinor", "$RequiredWsMajor.$RequiredWsMinor")) {
        $searchPaths += Join-Path $personalBase "$fmt\epan\$PluginDll"
    }
    $searchPaths += Join-Path $personalBase $PluginDll

    # Build output directories (common Wireshark source locations)
    foreach ($wsDir in @("C:\wireshark-4.6.3", "C:\wireshark-4.6.2", "C:\wireshark-4.6.1", "C:\wireshark-4.6.0", "D:\wireshark-4.6.3")) {
        $buildDirs = @(
            "$wsDir\build-reporter-pro",
            "$wsDir\build"
        )
        foreach ($bd in $buildDirs) {
            if (Test-Path $bd) {
                $found = Get-ChildItem -Path $bd -Recurse -Filter $PluginDll -ErrorAction SilentlyContinue |
                         Select-Object -First 1
                if ($found) { $searchPaths += $found.FullName }
            }
        }
    }

    # Return the first path that exists
    foreach ($p in $searchPaths) {
        if ($p -and (Test-Path $p)) {
            return $p
        }
    }

    return $null
}

# ── Find Cairo runtime DLLs ──────────────────────────────────────

function Find-CairoRuntimeDir {
    # Check alongside the installer (for distribution packages)
    $runtimeDir = Join-Path $ScriptDir "runtime"
    if ((Test-Path $runtimeDir) -and (Test-Path (Join-Path $runtimeDir "cairo-2.dll"))) {
        return $runtimeDir
    }
    if (Test-Path (Join-Path $ScriptDir "cairo-2.dll")) {
        return $ScriptDir
    }

    # Check binaries\windows\runtime in project tree
    $projRuntime = Join-Path $ProjectDir "binaries\windows\runtime"
    if ((Test-Path $projRuntime) -and (Test-Path (Join-Path $projRuntime "cairo-2.dll"))) {
        return $projRuntime
    }

    # Check vcpkg (build machine)
    foreach ($vcpkg in @("C:\vcpkg", "D:\vcpkg")) {
        $bin = Join-Path $vcpkg "installed\x64-windows\bin"
        if (Test-Path (Join-Path $bin "cairo-2.dll")) {
            return $bin
        }
    }

    return $null
}

# ── Find legacy Lua plugin ──────────────────────────────────────

function Find-LuaPlugin {
    $locations = @()
    $personalBase = Join-Path $env:APPDATA "Wireshark\plugins"

    if (Test-Path $personalBase) {
        # Top-level plugins dir
        $top = Join-Path $personalBase $LuaPluginName
        if (Test-Path $top) { $locations += $top }

        # Any version subdirectory
        Get-ChildItem $personalBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $luaPath = Join-Path $_.FullName $LuaPluginName
            if (Test-Path $luaPath) { $locations += $luaPath }
            $luaInEpan = Join-Path $_.FullName "epan\$LuaPluginName"
            if (Test-Path $luaInEpan) { $locations += $luaInEpan }
        }
    }

    # Also check global plugin dir
    if ($script:wsInfo -and $script:wsInfo.InstallDir) {
        $globalBase = Join-Path $script:wsInfo.InstallDir "plugins"
        if (Test-Path $globalBase) {
            $top = Join-Path $globalBase $LuaPluginName
            if (Test-Path $top) { $locations += $top }
            Get-ChildItem $globalBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $luaPath = Join-Path $_.FullName $LuaPluginName
                if (Test-Path $luaPath) { $locations += $luaPath }
            }
        }
    }

    return $locations
}

# ── Prompt helper ────────────────────────────────────────────────

function Read-YesNo([string]$prompt, [bool]$default = $true) {
    $hint = if ($default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "         $prompt $hint"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
    return $answer.Trim().ToLower().StartsWith("y")
}

function Read-Choice([string]$prompt, [int]$default, [int]$min, [int]$max) {
    $answer = Read-Host "         $prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
    $val = 0
    if ([int]::TryParse($answer.Trim(), [ref]$val) -and $val -ge $min -and $val -le $max) {
        return $val
    }
    return $default
}

# ═════════════════════════════════════════════════════════════════
#  UNINSTALL MODE
# ═════════════════════════════════════════════════════════════════

if ($Uninstall) {
    Write-Banner
    Write-Section "Uninstalling PacketReporter Pro"

    $removed = $false
    $personalBase = Join-Path $env:APPDATA "Wireshark\plugins"

    foreach ($fmt in @("$RequiredWsMajor-$RequiredWsMinor", "$RequiredWsMajor.$RequiredWsMinor")) {
        $dllPath = Join-Path $personalBase "$fmt\epan\$PluginDll"
        if (Test-Path $dllPath) {
            Remove-Item $dllPath -Force
            Write-Ok "Removed $dllPath"
            $removed = $true
        }
    }

    # Also check top-level
    $topDll = Join-Path $personalBase $PluginDll
    if (Test-Path $topDll) {
        Remove-Item $topDll -Force
        Write-Ok "Removed $topDll"
        $removed = $true
    }

    if (-not $removed) {
        Write-Warn "No plugin DLL found in personal plugins directory"
    }

    $configDir = Join-Path $env:USERPROFILE $ConfigDirName
    if (Test-Path $configDir) {
        if (Read-YesNo "Also remove configuration directory ($configDir)?" $false) {
            Remove-Item $configDir -Recurse -Force
            Write-Ok "Removed configuration directory"
        } else {
            Write-Info "Configuration directory kept"
        }
    }

    Write-Host ""
    if ($removed) {
        Write-Ok "Uninstall complete. Restart Wireshark to apply."
    } else {
        Write-Warn "Nothing to uninstall."
    }
    Write-Host ""
    exit 0
}

# ═════════════════════════════════════════════════════════════════
#  INSTALL MODE
# ═════════════════════════════════════════════════════════════════

$totalSteps = 7
Write-Banner

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# ── Step 1: Detect Wireshark ─────────────────────────────────────

Write-Step 1 $totalSteps "Detecting Wireshark installation"

Write-Info "Searching Windows Registry..."
Write-Pause 200
Write-Info "Searching standard install paths..."
Write-Pause 200
Write-Info "Searching system PATH..."
Write-Pause 300

$script:wsInfo = Find-Wireshark

if (-not $wsInfo.Found) {
    Write-Err "Wireshark not found on this system"
    Write-Host ""
    Write-Detail "The installer searched:"
    Write-Detail "  - Windows Registry (HKLM/HKCU Uninstall keys)"
    Write-Detail "  - Standard install paths (Program Files)"
    Write-Detail "  - System PATH (wireshark.exe, tshark.exe)"
    Write-Host ""
    Write-Detail "Please install Wireshark 4.6.x from:"
    Write-Detail "  https://www.wireshark.org/download.html"
    Write-Host ""
    Write-Detail "If Wireshark is installed in a custom location, re-run with:"
    Write-Detail "  .\install.ps1 -WiresharkDir ""C:\path\to\Wireshark"""
    Write-Host ""
    exit 1
}

Write-Ok "Wireshark found"
Write-Detail "Path:    $($wsInfo.InstallDir)"
if ($wsInfo.Version) {
    Write-Detail "Version: $($wsInfo.Version)"
}
Write-Pause 600

# ── Step 2: Validate Wireshark version ───────────────────────────

Write-Step 2 $totalSteps "Validating Wireshark version"

$versionOk = $false
if ($wsInfo.Major -eq 0 -and -not $wsInfo.Version) {
    Write-Warn "Could not determine Wireshark version"
    Write-Detail "PacketReporter Pro requires Wireshark 4.6.x"
    if (Read-YesNo "Continue anyway?" $false) {
        $versionOk = $true
        $wsInfo.Major = $RequiredWsMajor
        $wsInfo.Minor = $RequiredWsMinor
    } else {
        exit 1
    }
} elseif ($wsInfo.Major -ne $RequiredWsMajor -or $wsInfo.Minor -ne $RequiredWsMinor) {
    Write-Warn "Wireshark $($wsInfo.Version) detected - this plugin targets $RequiredWsMajor.$RequiredWsMinor.x"
    Write-Detail "The plugin was compiled for Wireshark $RequiredWsMajor.$RequiredWsMinor and may not"
    Write-Detail "load correctly on version $($wsInfo.Version)."
    if (Read-YesNo "Continue anyway?" $false) {
        $versionOk = $true
    } else {
        Write-Host ""
        Write-Detail "Install Wireshark 4.6.x from:"
        Write-Detail "  https://www.wireshark.org/download.html"
        Write-Host ""
        exit 1
    }
} else {
    Write-Ok "Wireshark $($wsInfo.Version) - compatible"
    $versionOk = $true
}
Write-Pause 500

# ── Step 3: Check for legacy Lua plugin ──────────────────────────

Write-Step 3 $totalSteps "Checking for legacy PacketReporter (Lua)"

Write-Info "Scanning personal plugin directory for packet_reporter.lua..."
Write-Pause 200
Write-Info "Scanning Wireshark global plugin directory..."
Write-Pause 300

$luaLocations = @(Find-LuaPlugin)
$configDir = Join-Path $env:USERPROFILE $ConfigDirName
$configExists = Test-Path $configDir

if ($luaLocations.Count -gt 0) {
    Write-Warn "Legacy Lua plugin found at:"
    foreach ($loc in $luaLocations) {
        Write-Detail $loc
    }
    Write-Host ""
    if (Read-YesNo "Remove the legacy Lua plugin? (recommended)" $true) {
        foreach ($loc in $luaLocations) {
            try {
                Remove-Item $loc -Force
                Write-Ok "Removed: $loc"
            } catch {
                Write-Warn "Could not remove: $loc (access denied?)"
            }
        }
    } else {
        Write-Info "Legacy plugin kept - both versions can coexist"
    }

    if ($configExists) {
        Write-Ok "Existing config directory found (logo/description will be reused)"
    }
} else {
    Write-Ok "No legacy Lua plugin found"
}
Write-Pause 500

# ── Step 4: Locate the plugin DLL ────────────────────────────────

Write-Step 4 $totalSteps "Locating plugin DLL"

Write-Info "Searching for $PluginDll..."
Write-Pause 200
Write-Info "  Checking installer directory..."
Write-Pause 200
Write-Info "  Checking project binaries..."
Write-Pause 200
Write-Info "  Checking installed locations..."
Write-Pause 300

$sourceDll = Find-PluginDll

if (-not $sourceDll) {
    Write-Err "Could not find $PluginDll"
    Write-Host ""
    Write-Detail "Searched in:"
    Write-Detail "  - $ScriptDir\"
    Write-Detail "  - $ProjectDir\binaries\windows\"
    Write-Detail "  - Per-user plugin directory"
    Write-Detail "  - Common build output directories"
    Write-Host ""
    Write-Detail "Options:"
    Write-Detail "  1. Place $PluginDll next to this installer script and re-run"
    Write-Detail "  2. Build the plugin first:"
    Write-Detail "       cd $ProjectDir\build\windows"
    Write-Detail "       .\build_plugin.ps1"
    Write-Detail "  3. Specify the path explicitly:"
    Write-Detail "       .\install.ps1 -DllPath ""C:\path\to\$PluginDll"""
    Write-Host ""
    exit 1
}

$dllSize = (Get-Item $sourceDll).Length
$dllSizeKB = [math]::Round($dllSize / 1024, 1)
Write-Ok "Found $PluginDll - ${dllSizeKB} KB"
Write-Detail "Source: $sourceDll"
Write-Pause 500

# ── Step 5: Choose install scope and install ─────────────────────

Write-Step 5 $totalSteps "Installing plugin"

Write-Info "Determining plugin version directory..."

$verDir = Get-PluginVersionDir $wsInfo.Major $wsInfo.Minor
Write-Info "Plugin version directory: $verDir"
$personalDir = Join-Path $env:APPDATA "Wireshark\plugins\$verDir\epan"
$systemDir   = if ($wsInfo.InstallDir) { Join-Path $wsInfo.InstallDir "plugins\$verDir\epan" } else { $null }

$installDir = $null

if ($SystemWide) {
    if (-not $isAdmin) {
        Write-Err "System-wide installation requires Administrator privileges"
        Write-Detail "Re-run this installer as Administrator, or install for current user only."
        exit 1
    }
    $installDir = $systemDir
} else {
    Write-Host ""
    Write-Detail "Install location:"
    Write-Detail "  [1] Current user: $personalDir"
    if ($systemDir) {
        Write-Detail "  [2] System-wide:  $systemDir  (requires admin)"
    }
    Write-Host ""
    $choice = Read-Choice "Choice" 1 1 $(if ($systemDir -and $isAdmin) { 2 } else { 1 })

    if ($choice -eq 2 -and $systemDir) {
        if (-not $isAdmin) {
            Write-Warn "System-wide install requires admin - falling back to per-user"
            $installDir = $personalDir
        } else {
            $installDir = $systemDir
        }
    } else {
        $installDir = $personalDir
    }
}

# Create directory and copy DLL
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Write-Ok "Created directory: $installDir"
}

$destFile = Join-Path $installDir $PluginDll

# Don't copy over itself
if ((Resolve-Path $sourceDll -ErrorAction SilentlyContinue).Path -ne (Join-Path $installDir $PluginDll)) {
    Copy-Item $sourceDll -Destination $destFile -Force
    Write-Ok "Installed $PluginDll"
} else {
    Write-Ok "Plugin already in target location"
}
Write-Detail "Location: $destFile"
Write-Pause 600

# ── Step 6: Cairo runtime dependencies ───────────────────────────

Write-Step 6 $totalSteps "Checking Cairo runtime dependencies"

Write-Info "The plugin uses Cairo for PDF rendering."
Write-Info "The official Wireshark installer ships these DLLs - verifying they are present."
Write-Host ""

$wsInstDir = $wsInfo.InstallDir
Write-Info "Wireshark directory: $wsInstDir"
Write-Host ""

$cairoDllsMissing = @()
foreach ($dll in $CairoRuntimeDlls) {
    $dllPath = Join-Path $wsInstDir $dll
    if (Test-Path $dllPath) {
        $size = [math]::Round((Get-Item $dllPath).Length / 1024, 0)
        Write-Ok "$dll  (${size} KB)"
    } else {
        Write-Warn "$dll  - NOT FOUND"
        $cairoDllsMissing += $dll
    }
    Write-Pause 150
}

Write-Host ""

if ($cairoDllsMissing.Count -eq 0) {
    Write-Ok "All Cairo runtime DLLs are present"
    Write-Pause 500
} else {
    Write-Warn "$($cairoDllsMissing.Count) of $($CairoRuntimeDlls.Count) Cairo DLLs missing (unusual for official Wireshark installs)"
    Write-Host ""

    Write-Info "Searching for Cairo runtime source..."
    Write-Info "  Checking installer directory..."
    Write-Info "  Checking project binaries..."
    Write-Info "  Checking vcpkg..."

    $cairoSrcDir = Find-CairoRuntimeDir

    if (-not $cairoSrcDir) {
        Write-Host ""
        Write-Err "Cairo runtime DLLs not found anywhere"
        Write-Host ""
        Write-Detail "The plugin needs these DLLs in the Wireshark install directory:"
        foreach ($dll in $cairoDllsMissing) { Write-Detail "  $dll" }
        Write-Host ""
        Write-Detail "Options:"
        Write-Detail "  1. Place a 'runtime' folder with the DLLs next to this installer"
        Write-Detail "  2. If you built from source, ensure vcpkg is at C:\vcpkg"
        Write-Detail "  3. Copy them manually to: $wsInstDir"
        Write-Host ""
        exit 1
    }

    Write-Ok "Found Cairo runtime source: $cairoSrcDir"
    Write-Host ""

    if ($isAdmin) {
        Write-Info "Copying Cairo DLLs to Wireshark directory..."
        foreach ($dll in $cairoDllsMissing) {
            $src = Join-Path $cairoSrcDir $dll
            if (Test-Path $src) {
                $size = [math]::Round((Get-Item $src).Length / 1024, 0)
                Copy-Item $src -Destination (Join-Path $wsInstDir $dll) -Force
                Write-Ok "Copied $dll (${size} KB) -> $wsInstDir"
            } else {
                Write-Warn "$dll not found in runtime source"
            }
        }
    } else {
        Write-Info "Copying to '$wsInstDir' requires Administrator privileges"
        Write-Info "Requesting elevation (UAC prompt)..."
        Write-Host ""

        $dllArgs = ($cairoDllsMissing | ForEach-Object {
            $src = Join-Path $cairoSrcDir $_
            $dst = Join-Path $wsInstDir $_
            "Copy-Item '$src' '$dst' -Force; Write-Host '  Copied: $_' -ForegroundColor Green"
        }) -join "; "

        $elevatedScript = "$dllArgs; Start-Sleep -Seconds 1"
        try {
            Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -Command `"$elevatedScript`"" -Wait
            Write-Host ""
            Write-Info "Verifying copies..."
            $allCopied = $true
            foreach ($dll in $cairoDllsMissing) {
                $dllPath = Join-Path $wsInstDir $dll
                if (Test-Path $dllPath) {
                    $size = [math]::Round((Get-Item $dllPath).Length / 1024, 0)
                    Write-Ok "$dll (${size} KB) - verified"
                } else {
                    $allCopied = $false
                    Write-Err "$dll - NOT copied"
                }
            }
            Write-Host ""
            if ($allCopied) {
                Write-Ok "All Cairo runtime DLLs installed successfully"
            } else {
                Write-Warn "Some DLLs may not have been copied"
                Write-Detail "You may need to copy them manually to: $wsInstDir"
            }
        } catch {
            Write-Host ""
            Write-Err "Elevation cancelled or failed"
            Write-Detail "Please copy these files manually to: $wsInstDir"
            foreach ($dll in $cairoDllsMissing) {
                $src = Join-Path $cairoSrcDir $dll
                Write-Detail "  $src"
            }
        }
    }
}

# ── Step 7: Configuration directory ──────────────────────────────

Write-Step 7 $totalSteps "Setting up configuration"

Write-Info "Config directory: $configDir"
Write-Host ""

$sampleDir = Join-Path $ProjectDir "sample-data"

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    Write-Ok "Created config directory: $configDir"
} else {
    Write-Ok "Config directory exists: $configDir"
}

# Logo
$logoInstalled = $false
if (Test-Path (Join-Path $configDir "Logo.png")) {
    Write-Ok "Logo.png already exists (keeping existing)"
    $logoInstalled = $true
} else {
    foreach ($src in @(
        (Join-Path $sampleDir "Logo.png"),
        (Join-Path $ScriptDir "Logo.png")
    )) {
        if (Test-Path $src) {
            Copy-Item $src -Destination (Join-Path $configDir "Logo.png") -Force
            Write-Ok "Installed default Logo.png"
            $logoInstalled = $true
            break
        }
    }
    if (-not $logoInstalled) {
        Write-Warn "No Logo.png found - place a 900x300 PNG in $configDir"
    }
}

# Description file
$descInstalled = $false
if (Test-Path (Join-Path $configDir "packet_reporter.txt")) {
    Write-Ok "packet_reporter.txt already exists (keeping existing)"
    $descInstalled = $true
} else {
    foreach ($src in @(
        (Join-Path $sampleDir "packet_reporter.txt"),
        (Join-Path $ScriptDir "packet_reporter.txt")
    )) {
        if (Test-Path $src) {
            Copy-Item $src -Destination (Join-Path $configDir "packet_reporter.txt") -Force
            Write-Ok "Installed default packet_reporter.txt"
            $descInstalled = $true
            break
        }
    }
    if (-not $descInstalled) {
        Write-Warn "No packet_reporter.txt found - create one in $configDir, 3 lines max"
    }
}
Write-Pause 600

# ═════════════════════════════════════════════════════════════════
#  Installation Summary
# ═════════════════════════════════════════════════════════════════

$reportDir = Join-Path $env:USERPROFILE "Documents\PacketReporter Reports"

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host "    Installation Complete!" -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Wireshark:  $($wsInfo.Version)" -ForegroundColor White
Write-Host "  Plugin:     $destFile" -ForegroundColor White
Write-Host "  Config:     $configDir" -ForegroundColor White
Write-Host "  Reports:    $reportDir" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Restart Wireshark"
Write-Host "    2. Open a capture file"
Write-Host "    3. Go to Tools -> PacketReporter Pro"
Write-Host ""
Write-Host "  Available reports:" -ForegroundColor Cyan
Write-Host "    - Executive Summary (auto-detects WiFi vs Network)"
Write-Host "    - Network Summary / Detailed Report"
Write-Host "    - WiFi Summary / Detailed Report"
Write-Host ""
Write-Host "  Customization:" -ForegroundColor Cyan
Write-Host "    Edit files in: $configDir"
Write-Host "      Logo.png           - Cover page logo (900x300 PNG)"
Write-Host "      packet_reporter.txt - Report description, 3 lines"
Write-Host ""

Write-Pause 800

# ── Uninstall instructions ───────────────────────────────────────

Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Uninstall" -ForegroundColor DarkGray
Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Run this installer with -Uninstall:" -ForegroundColor DarkGray
Write-Host "    powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Or manually remove:" -ForegroundColor DarkGray
Write-Host "    Remove-Item `"$destFile`"" -ForegroundColor DarkGray
Write-Host "    Remove-Item `"$configDir`" -Recurse -Force  # optional" -ForegroundColor DarkGray
Write-Host ""

# ── Troubleshooting ──────────────────────────────────────────────

Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Troubleshooting" -ForegroundColor DarkGray
Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Plugin not visible in Wireshark:" -ForegroundColor DarkGray
Write-Host "    1. Restart Wireshark completely" -ForegroundColor DarkGray
Write-Host "    2. Check Help -> About Wireshark -> Plugins tab" -ForegroundColor DarkGray
Write-Host "    3. Look for '$PluginName' in the list" -ForegroundColor DarkGray
Write-Host "    4. Ensure version directory ($verDir) matches your Wireshark" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  'Module could not be found' but DLL exists:" -ForegroundColor DarkGray
Write-Host "    This means a dependency DLL is missing. The plugin needs" -ForegroundColor DarkGray
Write-Host "    Cairo runtime DLLs in the Wireshark install directory." -ForegroundColor DarkGray
Write-Host "    The official Wireshark installer ships them, but custom or" -ForegroundColor DarkGray
Write-Host "    minimal installs may be missing:" -ForegroundColor DarkGray
Write-Host "      cairo-2.dll, pixman-1-0.dll, freetype.dll," -ForegroundColor DarkGray
Write-Host "      fontconfig-1.dll, libpng16.dll, libexpat.dll" -ForegroundColor DarkGray
Write-Host "    Re-run the installer to auto-detect and copy them." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Plugin loads but crashes:" -ForegroundColor DarkGray
Write-Host "    - Verify Wireshark version is 4.6.x" -ForegroundColor DarkGray
Write-Host "    - Install Visual C++ Redistributable 2022:" -ForegroundColor DarkGray
Write-Host "      https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Wrong plugin directory:" -ForegroundColor DarkGray
Write-Host "    Check Wireshark's actual plugin path:" -ForegroundColor DarkGray
Write-Host "      Help -> About Wireshark -> Folders tab -> Personal Plugins" -ForegroundColor DarkGray
Write-Host "    Then move the DLL to that location." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ========================================================" -ForegroundColor DarkGray
Write-Host ""
