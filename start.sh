#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "[Trocar] 检查环境..."

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "[错误] 未找到 Python，请安装 Python 3.10+"
    exit 1
fi

PY=$(command -v python3 || command -v python)

if [ ! -d "venv" ]; then
    echo "[Trocar] 创建虚拟环境..."
    $PY -m venv venv
fi

source venv/bin/activate

echo "[Trocar] 安装依赖..."
pip install -r requirements.txt -q 2>/dev/null

echo "[Trocar] 正在启动 http://127.0.0.1:9899"
echo "[Trocar] 首次访问请在浏览器完成 API Key 配置"
python app.py
