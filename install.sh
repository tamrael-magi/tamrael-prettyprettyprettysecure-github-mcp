#!/usr/bin/env bash
set -euo pipefail

REPO="tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp"
BRANCH="main"

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}🔐 Tamrael's PPPS GitHub MCP — Installer${NC}"
echo -e "${DIM}Pretty, pretty, pretty secure.${NC}"
echo ""

# -- Check Python --
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}ERROR: python3 not found. Install Python 3.9+ first.${NC}"
    exit 1
fi

py_ver=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if awk "BEGIN {exit !($py_ver < 3.9)}"; then
    echo -e "${RED}ERROR: Python $py_ver detected. Python 3.9+ required.${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python $py_ver"

# -- Determine install dir --
INSTALL_DIR="${HOME}/.ppps-github-mcp"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}⚠ Directory $INSTALL_DIR exists. Updating...${NC}"
else
    mkdir -p "$INSTALL_DIR"
fi

# -- Download files --
echo "Downloading..."
DOWNLOAD_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
for f in tamrael_github_general.py secure_config.py security_validators.py overkill_audit_logger.py; do
    curl -sSL "${DOWNLOAD_URL}/${f}" -o "${INSTALL_DIR}/${f}"
    echo -e "${GREEN}✓${NC} ${f}"
done

cd "$INSTALL_DIR"

# -- Install deps --
echo ""
echo "Installing Python dependencies..."
pip3 install httpx mcp keyring --quiet
echo -e "${GREEN}✓${NC} Dependencies installed"

# -- Setup token --
echo ""
echo -e "${BOLD}GitHub Token Setup${NC}"
echo -e "${DIM}Your token will be stored in your OS keyring (encrypted).${NC}"
echo ""
python3 secure_config.py setup

echo ""
echo -e "${GREEN}${BOLD}✅ Installation complete!${NC}"
echo ""
echo -e "Add this to your Claude Desktop config (${DIM}claude_desktop_config.json${NC}):"
echo ""
echo -e "  ${DIM}{${NC}"
echo -e "    ${DIM}\"mcpServers\": {${NC}"
echo -e "      ${DIM}\"ppps-github\": {${NC}"
echo -e "        ${DIM}\"command\": \"python3\",${NC}"
echo -e "        ${DIM}\"args\": [\"${INSTALL_DIR}/tamrael_github_general.py\"]${NC}"
echo -e "      ${DIM}}${NC}"
echo -e "    ${DIM}}${NC}"
echo -e "  ${DIM}}${NC}"
echo ""
echo -e "Or run directly:  ${BOLD}python3 ${INSTALL_DIR}/tamrael_github_general.py${NC}"
echo ""