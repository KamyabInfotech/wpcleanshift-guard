#!/bin/bash
# CleanShift Guard Installer
# Installs the mu-plugin into a WordPress site.
#
# Usage: ./install-guard.sh /path/to/wordpress
#
# This copies the guard files into wp-content/mu-plugins/ and
# sets proper file permissions.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

WP_PATH="${1:-}"

if [ -z "$WP_PATH" ]; then
    echo -e "${RED}Usage: $0 /path/to/wordpress${NC}"
    exit 1
fi

# Verify WordPress installation.
if [ ! -f "$WP_PATH/wp-config.php" ]; then
    echo -e "${RED}Error: wp-config.php not found at $WP_PATH${NC}"
    echo "This doesn't look like a WordPress installation."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD_SRC="$SCRIPT_DIR"
MU_PLUGINS="$WP_PATH/wp-content/mu-plugins"
GUARD_DIR="$MU_PLUGINS/cleanshift-guard"

echo -e "${GREEN}CleanShift Guard Installer${NC}"
echo "=========================="
echo "WordPress: $WP_PATH"
echo "Target:    $MU_PLUGINS"
echo ""

# Create mu-plugins directory if needed.
if [ ! -d "$MU_PLUGINS" ]; then
    echo -e "${YELLOW}Creating mu-plugins directory...${NC}"
    mkdir -p "$MU_PLUGINS"
fi

# Create guard subdirectory.
echo "Creating guard directory..."
mkdir -p "$GUARD_DIR"

# Copy bootstrap file.
echo "Installing wpcleanshift-guard.php..."
cp "$GUARD_SRC/wpcleanshift-guard.php" "$MU_PLUGINS/wpcleanshift-guard.php"

# Copy all class files.
echo "Installing guard components..."
for f in "$GUARD_SRC/cleanshift-guard/"class-*.php; do
    if [ -f "$f" ]; then
        filename=$(basename "$f")
        cp "$f" "$GUARD_DIR/$filename"
        echo "  ✓ $filename"
    fi
done

# Set permissions.
echo ""
echo "Setting file permissions..."
chmod 755 "$MU_PLUGINS"
chmod 755 "$GUARD_DIR"
chmod 644 "$MU_PLUGINS/wpcleanshift-guard.php"
find "$GUARD_DIR" -name "*.php" -exec chmod 644 {} \;

# Set ownership to match WordPress.
WP_OWNER=$(stat -c '%U:%G' "$WP_PATH/wp-config.php" 2>/dev/null || stat -f '%Su:%Sg' "$WP_PATH/wp-config.php" 2>/dev/null)
if [ -n "$WP_OWNER" ]; then
    echo "Setting ownership to $WP_OWNER..."
    chown -R "$WP_OWNER" "$MU_PLUGINS/wpcleanshift-guard.php" "$GUARD_DIR" 2>/dev/null || true
fi

# Verify installation.
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Files installed:"
find "$MU_PLUGINS" -name "*cleanshift*" -type f | sort | while read f; do
    echo "  $(wc -l < "$f") lines  $f"
done

echo ""
echo "Guard will activate on next page load."
echo "View status: WordPress Admin → Settings → CleanShift Guard"
