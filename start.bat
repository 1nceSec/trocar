@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo [Trocar] 检查环境...

where python >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请安装 Python 3.10+
    pause
    exit /b 1
)

echo [Trocar] 安装依赖...
python -m pip install -r requirements.txt -q 2>nul

echo [Trocar] 正在启动 http://127.0.0.1:9899
echo [Trocar] 首次访问请在浏览器完成 API Key 配置
python app.py
pause
