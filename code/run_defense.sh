#!/usr/bin/env bash
# =============================================================================
# Defense Terminal Script — MailMate Personal Email Assistant Attack-Defense Benchmark (Baseline: Recipient Source Guard)
#
# Interactive configuration: Real large model Agent API (input y) / Offline deterministic rule Agent simulator (input N, default)
#
# Run with default parameters on a new machine:
#     pip install -r requirements.txt
#     bash run_defense.sh
#
# Output: RecipientSourceGuard defense win rate, false positive rate, and qualification threshold against all official attacks
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# Specify interpreter: default python, can be overridden with PYTHON environment variable
PY="${PYTHON:-python}"
USE_API="${USE_API:-N}"
LANG_CODE="${LANG_CODE:-en}"

if [[ "${LANG_CODE}" == "en" ]]; then
    echo ">>> [run_defense] Defense Baseline Evaluation (RecipientSourceGuard)"
else
    echo ">>> [run_defense] 防守方 Baseline 评测（RecipientSourceGuard）"
fi
#read -rp "Use real large model Agent API for evaluation? [y/N] " USE_API
if [[ "${USE_API}" =~ ^[Yy] ]]; then
    if [[ "${LANG_CODE}" == "en" ]]; then
        echo ">>> Interactive configuration for OpenAI compatible Agent API (can pre-fill with env vars: AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL)"
    else
        echo ">>> 交互式配置 OpenAI 兼容 Agent API（可先用环境变量预填：AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL）"
    fi
    if [[ "${LANG_CODE}" == "en" ]]; then
        read -rp "Agent Base URL (default https://api.openai.com/v1): " AGENT_BASE_URL
    else
        read -rp "Agent Base URL (默认 https://api.openai.com/v1): " AGENT_BASE_URL
    fi
    AGENT_BASE_URL="${AGENT_BASE_URL:-https://api.openai.com/v1}"
    if [[ "${LANG_CODE}" == "en" ]]; then
        read -rp "API Key (press enter to use AGENT_API_KEY env var): " AGENT_API_KEY
    else
        read -rp "API Key (回车则使用环境变量 AGENT_API_KEY): " AGENT_API_KEY
    fi
    if [[ "${LANG_CODE}" == "en" ]]; then
        read -rp "Model ID (default gpt-4o-mini): " AGENT_MODEL
    else
        read -rp "Model ID (默认 gpt-4o-mini): " AGENT_MODEL
    fi
    AGENT_MODEL="${AGENT_MODEL:-gpt-4o-mini}"
    export AGENT_BASE_URL AGENT_API_KEY AGENT_MODEL
    "$PY" test.py --stage defense --judge api
else
    if [[ "${LANG_CODE}" == "en" ]]; then
        echo ">>> Offline simulated Agent (no API required, runs in seconds; choose y for real model)"
    else
        echo ">>> 离线模拟 Agent（无需 API，秒级跑通；真实模型请选择 y）"
    fi
    "$PY" test.py --stage defense --judge mock --lang "$LANG_CODE"
fi
