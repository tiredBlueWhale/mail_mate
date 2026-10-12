#!/bin/bash
set -e

cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}

echo ">>> Using $($PYTHON --version)"
$PYTHON -m venv .venv
source .venv/bin/activate

echo ">>> Upgrading pip..."
pip install --upgrade pip

echo ">>> Installing dependencies..."
if [ -f requirements.lock.txt ]; then
    pip install -r code/requirements.lock.txt
else
    pip install -r code/requirements.txt
asdf
echo ""
echo ">>> Setup complete."
echo ">>> Activate with: source .venv/bin/activate"
echo ">>> Then run:      aider --model deepseek/deepseek-chat"
