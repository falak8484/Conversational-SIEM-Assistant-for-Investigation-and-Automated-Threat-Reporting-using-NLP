#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
#  SIEM Assistant — One-command launcher
#  Usage:  ./run.sh
# ──────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}  ███████╗██╗███████╗███╗   ███╗     █████╗ ██╗${NC}"
  echo -e "${CYAN}  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██║${NC}"
  echo -e "${CYAN}  ███████╗██║█████╗  ██╔████╔██║    ███████║██║${NC}"
  echo -e "${CYAN}  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██║${NC}"
  echo -e "${CYAN}  ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║${NC}"
  echo -e "${CYAN}  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝${NC}"
  echo ""
  echo -e "  ${YELLOW}Conversational SIEM Assistant — Threat Intelligence Console${NC}"
  echo ""
}

banner

# ── Check Python ──────────────────────────────────────────
echo -e "${CYAN}[1/4]${NC} Checking Python…"
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}ERROR: python3 not found. Install Python 3.9+ first.${NC}"
  exit 1
fi
PY=$(python3 --version)
echo -e "      ${GREEN}Found: $PY${NC}"

# ── Create data dir ───────────────────────────────────────
echo -e "${CYAN}[2/4]${NC} Preparing directories…"
mkdir -p "$SCRIPT_DIR/data"
echo -e "      ${GREEN}data/ ready${NC}"

# ── Create virtualenv if needed ───────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo -e "${CYAN}[3/4]${NC} Creating virtual environment…"
  python3 -m venv "$VENV_DIR"
  echo -e "      ${GREEN}Virtual environment created${NC}"
else
  echo -e "${CYAN}[3/4]${NC} Virtual environment found."
fi

source "$VENV_DIR/bin/activate"

# ── Install dependencies ──────────────────────────────────
echo -e "${CYAN}[4/4]${NC} Installing dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
echo -e "      ${GREEN}Dependencies installed${NC}"

# ── Launch ────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}✔ SIEM Assistant starting…${NC}"
echo ""
echo -e "  ${YELLOW}▶ Open in browser:${NC}  ${CYAN}http://127.0.0.1:8000${NC}"
echo ""
echo -e "  Press ${RED}Ctrl+C${NC} to stop."
echo ""

cd "$SCRIPT_DIR/backend"
python3 -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload \
  --log-level info
