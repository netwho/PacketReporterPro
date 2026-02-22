# Windows Requirements — PacketReporter Pro

This document covers prerequisites for the **native C/C++ plugin** (PacketReporter Pro).
Unlike the original Lua-based PacketReporter, the native plugin has **no external runtime
dependencies** — PDF generation is built in via Cairo.

## Quick Install

```powershell
cd installers\windows
.\install.bat
```

Or from PowerShell directly:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

The installer will automatically check all prerequisites and guide you through the process.

---

## System Requirements

| Requirement       | Details                                              |
|-------------------|------------------------------------------------------|
| **OS**            | Windows 10 or later (Windows Server 2016+)           |
| **Architecture**  | x64 (64-bit)                                         |
| **Wireshark**     | Version **4.6.x** (required — plugin is ABI-specific)|
| **Privileges**    | Standard user (Administrator for system-wide install) |

## Required: Wireshark 4.6.x

PacketReporter Pro is a compiled native plugin linked against Wireshark 4.6 headers.
It will **only load** in Wireshark 4.6.x.

**Installation:**

1. Download from [wireshark.org](https://www.wireshark.org/download.html)
2. Run the installer (accept defaults, include Npcap)
3. Restart if prompted

**Verify installation:**

```powershell
# The installer detects Wireshark automatically via:
#   1. Windows Registry (most reliable)
#   2. Standard filesystem paths (Program Files)
#   3. System PATH (wireshark.exe / tshark.exe)

# Manual check:
& "C:\Program Files\Wireshark\tshark.exe" --version
```

## No Additional Runtime Dependencies

Unlike the Lua-based PacketReporter, the native plugin **does not** require:

- ~~Lua 5.2+~~ — not needed (compiled C/C++)
- ~~rsvg-convert~~ — not needed (Cairo renders PDF directly)
- ~~pdfunite / pdftk~~ — not needed (single-pass PDF generation)
- ~~Inkscape / ImageMagick~~ — not needed
- ~~Chocolatey~~ — not needed

Everything is built into the plugin DLL.

## Plugin Directory

**Per-user (default):**

```
%APPDATA%\Wireshark\plugins\4.6\epan\packetreporterpro.dll
```

Full path example: `C:\Users\YourName\AppData\Roaming\Wireshark\plugins\4.6\epan\packetreporterpro.dll`

**System-wide (requires admin):**

```
C:\Program Files\Wireshark\plugins\4.6\epan\packetreporterpro.dll
```

## Configuration Directory

**Location:** `%USERPROFILE%\.packet_reporter\`

| File                  | Purpose                                      |
|-----------------------|----------------------------------------------|
| `Logo.png`            | Cover page logo (900x300 PNG recommended)    |
| `packet_reporter.txt` | Report description (3 lines: Customer, Segment, Notes) |

The installer copies sample files here on first install. You can also customize
these directly in the PacketReporter Pro GUI (check "Save as defaults").

## Installer Options

```powershell
# Standard install (per-user)
.\install.ps1

# System-wide install
.\install.ps1 -SystemWide

# Specify DLL path explicitly
.\install.ps1 -DllPath "C:\path\to\packetreporterpro.dll"

# Point to custom Wireshark location
.\install.ps1 -WiresharkDir "D:\Wireshark"

# Uninstall
.\install.ps1 -Uninstall
```

## Migrating from the Lua Plugin

If you previously used the Lua-based PacketReporter:

1. The installer detects the old `packet_reporter.lua` and offers to remove it
2. Your existing `Logo.png` and `packet_reporter.txt` in `~/.packet_reporter/`
   are preserved and reused by the native plugin
3. Both versions can coexist if you prefer to keep the Lua plugin

Key differences in the native version:

| Feature               | Lua Plugin             | Native Plugin (Pro)     |
|-----------------------|------------------------|-------------------------|
| PDF generation        | Requires external tools| Built-in (Cairo)        |
| Report quality        | SVG → PNG → PDF        | Direct vector PDF       |
| WiFi reports          | Basic                  | Full 10-section         |
| Settings UI           | None                   | Integrated Qt6 window   |
| Performance           | Interpreted            | Compiled C/C++          |

## Troubleshooting

### Wireshark Not Detected by Installer

The installer uses multiple detection methods (Registry, filesystem, PATH).
If detection fails:

```powershell
# Check if Wireshark is in the registry
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" -ErrorAction SilentlyContinue

# Specify the path manually
.\install.ps1 -WiresharkDir "C:\Program Files\Wireshark"
```

### Plugin Not Showing in Wireshark

1. **Restart Wireshark** completely (close all windows)
2. Go to **Help → About Wireshark → Plugins** tab
3. Look for `packetreporterpro` in the list
4. If missing, check **Help → About Wireshark → Folders** tab for the correct personal plugins path
5. Verify the DLL is in the right version directory (`4.6\epan\`)

### DLL Load Error / Crash on Startup

- **Version mismatch:** Ensure Wireshark is version 4.6.x (not 4.4, 4.2, etc.)
- **Missing VC++ Runtime:** Install [Visual C++ Redistributable 2022](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- **32/64 bit mismatch:** The plugin is built for 64-bit Wireshark

### Permission Denied

```powershell
# Fix plugin directory permissions
$pluginDir = "$env:APPDATA\Wireshark\plugins"
New-Item -ItemType Directory -Force -Path $pluginDir
icacls $pluginDir /grant "${env:USERNAME}:(OI)(CI)F" /T
```

### Antivirus Blocking

Some antivirus programs may flag the plugin DLL:

- Add `%APPDATA%\Wireshark\plugins\` to your AV exceptions
- Add the Wireshark install directory to exceptions

## Uninstallation

**Automated:**

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
```

**Manual:**

```powershell
# Remove the plugin
Remove-Item "$env:APPDATA\Wireshark\plugins\4.6\epan\packetreporterpro.dll"

# Optionally remove configuration
Remove-Item "$env:USERPROFILE\.packet_reporter" -Recurse -Force
```

## Building from Source

If you need to build the plugin yourself (e.g., for a different Wireshark version):

```powershell
# One-time setup
cd build\windows
.\setup_windows_build.ps1

# Build and auto-install
.\build_plugin.ps1
```

Build requirements: Visual Studio 2022, CMake, Qt6 (MSVC 2022 64-bit), vcpkg (Cairo, GLib).
See `build\windows\setup_windows_build.ps1` for details.
