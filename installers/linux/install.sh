#!/usr/bin/env bash
#
# PacketReporter Pro — Linux Installer
# Detects the installed Wireshark version and installs the matching binary.
# Binaries are expected in the same directory as this script.
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
echo -e "${BLUE}PacketReporter Pro — Linux Installation${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# ── Detect Wireshark version ─────────────────────────────────────

WS_VERSION=""
if command -v wireshark &>/dev/null; then
    WS_VERSION=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
elif command -v tshark &>/dev/null; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

if [ -z "$WS_VERSION" ]; then
    echo -e "${RED}Error: Wireshark not found.${NC}"
    echo "Please install Wireshark first and ensure 'wireshark' or 'tshark' is in your PATH."
    exit 1
fi

WS_MAJOR=$(echo "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(echo "$WS_VERSION" | cut -d. -f2)

echo -e "${GREEN}✓${NC} Wireshark version detected: $WS_VERSION"

# ── Determine the right binary and plugin path ──────────────────

PLUGIN_SO=""
PLUGIN_VER_DIR=""

case "${WS_MAJOR}.${WS_MINOR}" in
    4.2*)
        PLUGIN_SO="$SCRIPT_DIR/packetreporterpro-ws42.so"
        PLUGIN_VER_DIR="4.2/epan"
        ;;
    4.3*|4.4*)
        PLUGIN_SO="$SCRIPT_DIR/packetreporterpro-ws44.so"
        PLUGIN_VER_DIR="4.4/epan"
        ;;
    4.5*|4.6*)
        PLUGIN_SO="$SCRIPT_DIR/packetreporterpro-ws46.so"
        PLUGIN_VER_DIR="4.6/epan"
        ;;
    *)
        echo -e "${RED}Error: Unsupported Wireshark version $WS_VERSION${NC}"
        echo "PacketReporter Pro supports Wireshark 4.2.x, 4.4.x, and 4.6.x."
        echo ""
        echo "Available binaries in $SCRIPT_DIR:"
        ls -1 "$SCRIPT_DIR"/packetreporterpro-ws*.so 2>/dev/null || echo "  (none found)"
        exit 1
        ;;
esac

if [ ! -f "$PLUGIN_SO" ]; then
    echo -e "${RED}Error: Binary not found: $(basename "$PLUGIN_SO")${NC}"
    echo "You may need to build it first:"
    echo "  cd $PROJECT_DIR/docker && ./build_all.sh"
    exit 1
fi

echo -e "${GREEN}✓${NC} Using binary: $(basename "$PLUGIN_SO")"

# ── Install the plugin ───────────────────────────────────────────

PLUGIN_BASE_DIR="$HOME/.local/lib/wireshark/plugins"
PLUGIN_DEST_DIR="$PLUGIN_BASE_DIR/$PLUGIN_VER_DIR"

echo -e "${YELLOW}→${NC} Installing plugin..."

mkdir -p "$PLUGIN_BASE_DIR" "$PLUGIN_DEST_DIR"
cp "$PLUGIN_SO" "$PLUGIN_DEST_DIR/packetreporterpro.so"
chmod 755 "$PLUGIN_DEST_DIR/packetreporterpro.so"

cp "$PLUGIN_SO" "$PLUGIN_BASE_DIR/packetreporterpro.so"
chmod 755 "$PLUGIN_BASE_DIR/packetreporterpro.so"

echo -e "${GREEN}✓${NC} Plugin installed to:"
echo "    $PLUGIN_DEST_DIR/packetreporterpro.so"
echo "    $PLUGIN_BASE_DIR/packetreporterpro.so"

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
echo "  Wireshark version:  $WS_VERSION"
echo "  Plugin binary:      $(basename "$PLUGIN_SO")"
echo "  Plugin location:    $PLUGIN_DEST_DIR/packetreporterpro.so"
echo "  Config directory:   $CONFIG_DIR"
echo ""
echo "Next steps:"
echo "  1. Restart Wireshark"
echo "  2. Go to Tools → PacketReporter Pro"
echo "  3. Reports available:"
echo "     • Network Analysis: Summary, Detailed, Annotated"
echo "     • WiFi / 802.11: Summary, Detailed, Annotated"
echo ""
echo -e "${GREEN}Reports are saved to ~/Documents/PacketReporter Reports/${NC}"
echo ""
