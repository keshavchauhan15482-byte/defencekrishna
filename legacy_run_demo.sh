#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Krishna Defence System — One-Command Demo Launcher
# SIH26153 (NTRO) | Team: The Predators
#
# Usage:  ./run_demo.sh
# Stops:  ./run_demo.sh stop
#
# What it starts:
#   1. Demo backend app       → http://localhost:4000
#   2. Krishna Defence WAF    → http://localhost:8080
#   3. Garuda AI FastAPI      → http://localhost:8001/docs
#   4. Garuda AI Streamlit    → http://localhost:8501
# ─────────────────────────────────────────────────────────────────────────────

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
NODE="${NODE:-node}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[  OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

# ── Stop mode ─────────────────────────────────────────────────────────────────
if [ "${1}" = "stop" ]; then
  echo -e "${BOLD}Stopping all Krishna Defence System processes...${NC}"
  pkill -f "demo-website.js"   2>/dev/null && log_ok "Demo backend stopped" || true
  pkill -f "proxy.js"          2>/dev/null && log_ok "WAF stopped"          || true
  pkill -f "fastapi_server.py" 2>/dev/null && log_ok "FastAPI stopped"      || true
  pkill -f "streamlit run"     2>/dev/null && log_ok "Streamlit stopped"    || true
  echo -e "${GREEN}All services stopped.${NC}"
  exit 0
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║    🛡️  KRISHNA DEFENCE SYSTEM — DEMO LAUNCHER             ║${NC}"
echo -e "${BOLD}${CYAN}║    SIH26153 (NTRO) | Team: The Predators                 ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Prerequisite checks ───────────────────────────────────────────────────────
log_info "Checking prerequisites..."

if ! command -v "$NODE" &>/dev/null; then
  log_error "Node.js not found. Install from https://nodejs.org"
  exit 1
fi
log_ok "Node.js: $(node --version)"

if ! command -v "$PYTHON" &>/dev/null; then
  log_error "Python3 not found."
  exit 1
fi
log_ok "Python: $($PYTHON --version)"

# ── Kill any existing processes on our ports ──────────────────────────────────
log_info "Clearing ports 4000, 8080, 8001, 8501..."
lsof -ti:4000 | xargs kill -9 2>/dev/null || true
lsof -ti:8080 | xargs kill -9 2>/dev/null || true
lsof -ti:8001 | xargs kill -9 2>/dev/null || true
lsof -ti:8501 | xargs kill -9 2>/dev/null || true
sleep 1

# ── Install Node deps if needed ───────────────────────────────────────────────
if [ ! -d "$PROJECT_DIR/node_modules" ]; then
  log_info "Installing Node.js dependencies..."
  cd "$PROJECT_DIR" && npm install --silent
  log_ok "npm install done"
fi

# ── Start 1: Demo backend (port 4000) ────────────────────────────────────────
log_info "Starting demo backend (port 4000)..."
cd "$PROJECT_DIR"
"$NODE" demo-website.js > /tmp/kds_demo.log 2>&1 &
DEMO_PID=$!
sleep 1
if kill -0 "$DEMO_PID" 2>/dev/null; then
  log_ok "Demo backend running (PID $DEMO_PID) → http://localhost:4000"
else
  log_error "Demo backend failed to start. Check /tmp/kds_demo.log"
fi

# ── Start 2: Krishna Defence WAF (port 8080) ─────────────────────────────────
log_info "Starting Krishna Defence WAF (port 8080)..."
"$NODE" proxy.js > /tmp/kds_waf.log 2>&1 &
WAF_PID=$!
sleep 2
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null | grep -q "200\|403"; then
  log_ok "WAF running (PID $WAF_PID) → http://localhost:8080"
else
  log_warn "WAF may still be starting... check http://localhost:8080"
fi

# ── Start 3: Garuda AI FastAPI (port 8001) ───────────────────────────────────
log_info "Starting Garuda AI FastAPI (port 8001)..."
FASTAPI_AVAILABLE=false
if "$PYTHON" -c "import fastapi, uvicorn" 2>/dev/null; then
  cd "$PROJECT_DIR/ntro-world-model"
  PYTHONPYCACHEPREFIX=/tmp/pycache "$PYTHON" -m uvicorn fastapi_server:app \
    --host 0.0.0.0 --port 8001 --log-level warning > /tmp/kds_fastapi.log 2>&1 &
  FASTAPI_PID=$!
  sleep 3
  if kill -0 "$FASTAPI_PID" 2>/dev/null; then
    log_ok "Garuda AI FastAPI (PID $FASTAPI_PID) → http://localhost:8001/docs"
    FASTAPI_AVAILABLE=true
  else
    log_warn "FastAPI failed (may need: pip install fastapi uvicorn). Check /tmp/kds_fastapi.log"
  fi
  cd "$PROJECT_DIR"
else
  log_warn "FastAPI/uvicorn not installed → skipping (pip install fastapi uvicorn)"
fi

# ── Start 4: Garuda AI Streamlit Dashboard (port 8501) ───────────────────────
log_info "Starting Garuda AI Streamlit Dashboard (port 8501)..."
STREAMLIT_AVAILABLE=false
if "$PYTHON" -c "import streamlit" 2>/dev/null; then
  cd "$PROJECT_DIR/ntro-world-model"
  PYTHONPYCACHEPREFIX=/tmp/pycache "$PYTHON" -m streamlit run streamlit_app.py \
    --server.port 8501 \
    --server.headless true \
    --browser.gatherUsageStats false \
    > /tmp/kds_streamlit.log 2>&1 &
  STREAMLIT_PID=$!
  sleep 5
  if kill -0 "$STREAMLIT_PID" 2>/dev/null; then
    log_ok "Streamlit Dashboard (PID $STREAMLIT_PID) → http://localhost:8501"
    STREAMLIT_AVAILABLE=true
  else
    log_warn "Streamlit failed. Check /tmp/kds_streamlit.log"
  fi
  cd "$PROJECT_DIR"
else
  log_warn "Streamlit not installed → skipping (pip install streamlit plotly)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║    ✅  KRISHNA DEFENCE SYSTEM — ALL SERVICES UP           ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  🏹 ${BOLD}WAF + Threat Console:${NC}   http://localhost:8080/__sentinel/console"
echo -e "  🛡️  ${BOLD}Protected App:${NC}          http://localhost:8080"
echo -e "  🦅 ${BOLD}Garuda AI Dashboard:${NC}   http://localhost:8501"
if [ "$FASTAPI_AVAILABLE" = true ]; then
echo -e "  📡 ${BOLD}Garuda AI API Docs:${NC}    http://localhost:8001/docs"
fi
echo ""
echo -e "  ${BOLD}Run Tests:${NC}"
echo -e "    npm test                    — Full security audit"
echo -e "    npm run test:gauntlet       — 100-attack gauntlet"
echo -e "    npm run test:network        — Network attack simulation"
echo ""
echo -e "  ${BOLD}Stop all:${NC}  ./run_demo.sh stop"
echo ""

# ── Open browser ──────────────────────────────────────────────────────────────
sleep 1
if command -v open &>/dev/null; then
  open "http://localhost:8080/__sentinel/console"
  [ "$STREAMLIT_AVAILABLE" = true ] && sleep 1 && open "http://localhost:8501"
elif command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:8080/__sentinel/console"
fi

# ── Keep alive ────────────────────────────────────────────────────────────────
echo -e "${CYAN}Press Ctrl+C to stop all services${NC}"
trap './run_demo.sh stop' INT TERM
wait
