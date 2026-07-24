#!/usr/bin/env bash
#
# Detection Engineering Assistant — one-command setup script.
set -euo pipefail

VENV_DIR=".venv"
REQUIRED_MAJOR=3
REQUIRED_MINOR=10
OLLAMA_MODELS=("qwen2.5-coder:14b" "llama3.3:70b")

info()  { echo -e "\033[1;34m[setup]\033[0m $1"; }
warn()  { echo -e "\033[1;33m[setup]\033[0m $1"; }
error() { echo -e "\033[1;31m[setup]\033[0m $1" >&2; }

# 1. Check Python version is 3.10 or higher
info "Checking Python version..."
if ! command -v python3 >/dev/null 2>&1; then
    error "python3 not found. Please install Python ${REQUIRED_MAJOR}.${REQUIRED_MINOR}+ and re-run."
    exit 1
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')

if [ "$PY_MAJOR" -lt "$REQUIRED_MAJOR" ] || { [ "$PY_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$PY_MINOR" -lt "$REQUIRED_MINOR" ]; }; then
    error "Python ${REQUIRED_MAJOR}.${REQUIRED_MINOR}+ is required (found $(python3 --version 2>&1))."
    exit 1
fi
info "Python $(python3 --version 2>&1) OK"

# 2. Create a virtual environment named .venv
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment '$VENV_DIR' already exists, skipping creation."
else
    info "Creating virtual environment in '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
fi

# 3. Activate it and install requirements.txt
info "Activating virtual environment and installing dependencies..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r requirements.txt

# 4. Check if Ollama is installed, print install instructions if missing
info "Checking for Ollama..."
if ! command -v ollama >/dev/null 2>&1; then
    warn "Ollama not found."
    warn "Install it from: https://ollama.com/download"
    warn "Linux quick install: curl -fsSL https://ollama.com/install.sh | sh"
    warn "After installing, re-run this script to pull the required models."
else
    info "Ollama found: $(ollama --version 2>&1 | head -n1)"

    # 5. Pull required Ollama models
    for model in "${OLLAMA_MODELS[@]}"; do
        info "Pulling Ollama model '$model' (this may take a while)..."
        ollama pull "$model" || warn "Failed to pull '$model'. You can retry later with: ollama pull $model"
    done
fi

# 6. Create data/ and output/ directories if they don't exist
info "Ensuring data/ and output/ directories exist..."
mkdir -p data output

# 7. Download MITRE ATT&CK data and build the ChromaDB vector DB
info "Downloading MITRE ATT&CK Enterprise data..."
python -c "from src.mitre.downloader import download_mitre_data; download_mitre_data()" \
    || warn "MITRE data download failed. You can retry later with: python -c \"from src.mitre.downloader import download_mitre_data; download_mitre_data()\""

info "Building MITRE ATT&CK vector DB (this may take a while on first run)..."
python -c "from src.mitre.vector_db import build_vector_db; build_vector_db()" \
    || warn "Vector DB build failed. You can retry later with: python -c \"from src.mitre.vector_db import build_vector_db; build_vector_db()\""

# 8. Copy .env.example to .env if .env does not already exist
if [ -f ".env" ]; then
    info ".env already exists, leaving it untouched."
else
    info "Creating .env from .env.example..."
    cp .env.example .env
fi

# 9. Success message with next steps
echo
info "Setup complete!"
echo
echo "Next steps:"
echo "  1. Edit .env and set LLM_PROVIDER (ollama or groq) and GROQ_API_KEY if needed."
echo "  2. Activate the virtual environment: source ${VENV_DIR}/bin/activate"
echo "  3. Run the assistant: python main.py"
echo
