#!/bin/bash

# SECUREVAULT (ELITE EDITION) - Linux Startup Script
# Created by MANORANJAN2050

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

clear
echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}#                                                               #${NC}"
echo -e "${BLUE}#   ${NC}${BOLD}SECUREVAULT (ELITE EDITION) v2.2.0${NC}${BLUE}                       #${NC}"
echo -e "${BLUE}#   ${NC}Advanced Local Encryption & Digital Asset Management       ${BLUE}#${NC}"
echo -e "${BLUE}#                                                               #${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo

# 1. Detect Python
echo -e "${CYAN}[1/3] Detecting Python environment...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
    echo -e "${GREEN}-- Found Python 3 executable${NC}"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
    echo -e "${GREEN}-- Found Python executable${NC}"
else
    echo -e "${RED}[X] CRITICAL: Python not found. Please install Python 3.${NC}"
    exit 1
fi

echo

# 2. Virtual Environment
echo -e "${CYAN}[2/3] Validating Virtual Environment...${NC}"
if [ ! -d ".venv" ] || [ ! -f ".venv/bin/activate" ]; then
    echo -e "${YELLOW}[!] Virtual environment missing or corrupted. Rebuilding...${NC}"
    rm -rf .venv
    $PYTHON_CMD -m venv .venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}[X] Failed to create virtual environment. Ensure 'python3-venv' is installed.${NC}"
        exit 1
    fi
    echo -e "${GREEN}-- Virtual environment created successfully.${NC}"
else
    echo -e "${GREEN}-- Virtual environment verified.${NC}"
fi

echo

# 3. Requirements
echo -e "${CYAN}[3/3] Processing requirements and system checks...${NC}"
source .venv/bin/activate

echo -e "${BLUE}-- Upgrading Package Manager...${NC}"
pip install --upgrade pip -q

echo -e "${BLUE}-- Verifying system dependencies...${NC}"
pip install -r requirements.txt --progress-bar off

echo
echo -e "${GREEN}${BOLD}SUCCESS: System is now ARMED and SECURE.${NC}"
echo -e "${CYAN}-- Decryption Gateway: http://127.0.0.1:5000${NC}"
echo

# Attempt to open browser
if command -v xdg-open &>/dev/null; then
    xdg-open "http://127.0.0.1:5000" &>/dev/null &
elif command -v open &>/dev/null; then
    open "http://127.0.0.1:5000" &>/dev/null &
fi

echo -e "${BOLD}Server Status: ${GREEN}RUNNING${NC}"
echo -e "${BLUE}[Press CTRL+C to Shutdown Vault]${NC}"
echo

python app.py
