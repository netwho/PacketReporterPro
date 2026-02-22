#!/usr/bin/env bash
#
# PacketReporter Pro — macOS Installer
# Installs a pre-built universal binary or builds from source.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SAMPLE_DIR="$PROJECT_DIR/sample-data"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}PacketReporter Pro — macOS Installation${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# ── Detect Wireshark ─────────────────────────────────────────────

WS_APP="/Applications/Wireshark.app"
if [ ! -d "$WS_APP" ]; then
    echo -e "${RED}Error: Wireshark not found at $WS_APP${NC}"
    echo "Please install Wireshark first: https://www.wireshark.org/download.html"
    exit 1
fi

WS_VERSION=$("$WS_APP/Contents/MacOS/Wireshark" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [ -z "$WS_VERSION" ]; then
    WS_VERSION=$(defaults read "$WS_APP/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
fi

echo -e "${GREEN}✓${NC} Wireshark version: $WS_VERSION"

WS_MAJOR=$(echo "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(echo "$WS_VERSION" | cut -d. -f2)

case "${WS_MAJOR}.${WS_MINOR}" in
    4.2*|4.3*|4.4*|4.5*|4.6*)
        echo -e "${GREEN}✓${NC} Wireshark version supported"
        ;;
    *)
        echo -e "${YELLOW}Warning: Wireshark $WS_VERSION may not be supported.${NC}"
        echo "PacketReporter Pro is tested with Wireshark 4.2.x - 4.6.x."
        ;;
esac

# ── Determine version-specific plugin path ────────────────────────

case "${WS_MAJOR}.${WS_MINOR}" in
    4.2*) VER_SUBDIR="4.2" ;;
    4.3*|4.4*) VER_SUBDIR="4.4" ;;
    4.5*|4.6*) VER_SUBDIR="4.6" ;;
    *) VER_SUBDIR="4.6" ;;
esac

# ── Find the binary (same folder as this script) ─────────────────

PLUGIN_SO=""
BUILD_SCRIPT="$PROJECT_DIR/build/macos/build_plugin.sh"

if [ -f "$SCRIPT_DIR/packetreporterpro.so" ]; then
    PLUGIN_SO="$SCRIPT_DIR/packetreporterpro.so"
    ARCH_INFO=$(lipo -info "$PLUGIN_SO" 2>/dev/null || true)
    echo -e "${GREEN}✓${NC} Found pre-built binary"
    if echo "$ARCH_INFO" | grep -q "x86_64.*arm64\|arm64.*x86_64"; then
        echo -e "${GREEN}✓${NC} Universal binary (arm64 + x86_64)"
    else
        echo -e "${YELLOW}→${NC} Architecture: $ARCH_INFO"
    fi
elif [ -f "$BUILD_SCRIPT" ]; then
    echo -e "${YELLOW}→${NC} No pre-built binary found. Building from source..."
    echo ""

    SETUP_SCRIPT="$PROJECT_DIR/build/macos/setup_mac_build.sh"
    if ! command -v cmake &>/dev/null || ! brew list cairo &>/dev/null 2>&1; then
        echo -e "${YELLOW}→${NC} Running build setup first..."
        bash "$SETUP_SCRIPT"
    fi

    bash "$BUILD_SCRIPT"
    PLUGIN_SO="ALREADY_INSTALLED"
else
    echo -e "${RED}Error: No binary and no build script found.${NC}"
    exit 1
fi

# ── Install plugin ───────────────────────────────────────────────

if [ "$PLUGIN_SO" != "ALREADY_INSTALLED" ]; then
    WS_PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    WS_PLUGIN_VER_DIR="$WS_PLUGIN_DIR/$VER_SUBDIR/epan"

    mkdir -p "$WS_PLUGIN_DIR" "$WS_PLUGIN_VER_DIR"
    cp "$PLUGIN_SO" "$WS_PLUGIN_DIR/packetreporterpro.so"
    cp "$PLUGIN_SO" "$WS_PLUGIN_VER_DIR/packetreporterpro.so"

    echo -e "${GREEN}✓${NC} Plugin installed to:"
    echo "    $WS_PLUGIN_DIR/packetreporterpro.so"
    echo "    $WS_PLUGIN_VER_DIR/packetreporterpro.so"
fi

# ── Set up config directory ──────────────────────────────────────

CONFIG_DIR="$HOME/.packet_reporter"
echo -e "${YELLOW}→${NC} Setting up configuration..."

mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/Logo.png" ]; then
    if [ -f "$SAMPLE_DIR/Logo.png" ]; then
        cp "$SAMPLE_DIR/Logo.png" "$CONFIG_DIR/"
        echo -e "${GREEN}✓${NC} Installed default logo"
    fi
else
    echo -e "${GREEN}✓${NC} Logo already exists"
fi

if [ ! -f "$CONFIG_DIR/packet_reporter.txt" ]; then
    if [ -f "$SAMPLE_DIR/packet_reporter.txt" ]; then
        cp "$SAMPLE_DIR/packet_reporter.txt" "$CONFIG_DIR/"
        echo -e "${GREEN}✓${NC} Installed default config"
    fi
else
    echo -e "${GREEN}✓${NC} Config already exists"
fi

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Restart Wireshark"
echo "  2. Go to Tools → PacketReporter Pro"
echo "  3. Reports available:"
echo "     • Executive Summary — auto-detects WiFi vs Network"
echo "     • Network Summary / Detailed Report"
echo "     • WiFi Summary / Detailed Report"
echo ""
echo -e "${GREEN}Reports are saved to ~/Documents/PacketReporter Reports/${NC}"
echo ""
