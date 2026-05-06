@echo off
setlocal enabledelayedexpansion

set "REPO=tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp"
set "BRANCH=main"
set "INSTALL_DIR=%USERPROFILE%\.ppps-github-mcp"
set "DOWNLOAD_URL=https://raw.githubusercontent.com/%REPO%/%BRANCH%"

echo ============================================
echo ^| Tamrael's PPPS GitHub MCP - Installer    ^|
echo ^| Pretty, pretty, pretty secure.           ^|
echo ============================================
echo.

REM -- Check Python --
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Install Python 3.9+ first.
    exit /b 1
)

python --version 2>&1 | findstr /R "3\.9\.[0-9] 3\.1[0-9]\.[0-9]" >nul
if %ERRORLEVEL% neq 0 (
    python --version 2>&1 | findstr /R "3\.[0-9]+\.[0-9]+" >nul
    if !ERRORLEVEL! equ 0 (
        for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do (
            for /f "tokens=1,2 delims=." %%a in ("%%v") do (
                if %%a LSS 3 (
                    echo ERROR: Python 3.9+ required. Found %%a.%%b
                    exit /b 1
                )
                if %%a EQU 3 if %%b LSS 9 (
                    echo ERROR: Python 3.9+ required. Found %%a.%%b
                    exit /b 1
                )
            )
        )
    ) else (
        echo ERROR: Could not determine Python version.
        exit /b 1
    )
)
echo [OK] Python found

REM -- Create install dir --
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM -- Download files --
echo Downloading...
for %%f in (tamrael_github_general.py secure_config.py security_validators.py overkill_audit_logger.py) do (
    echo Downloading %%f...
    powershell -Command "Invoke-WebRequest -Uri '%DOWNLOAD_URL%/%%f' -OutFile '%INSTALL_DIR%\%%f'" >nul 2>nul
    if !ERRORLEVEL! equ 0 (echo [OK] %%f) else (echo [FAIL] %%f)
)

cd /d "%INSTALL_DIR%"

REM -- Install deps --
echo.
echo Installing Python dependencies...
pip install httpx mcp keyring --quiet
echo [OK] Dependencies installed

REM -- Setup token --
echo.
echo === GitHub Token Setup ===
echo Your token will be stored in your OS keyring (encrypted).
echo.
python secure_config.py setup

echo.
echo ============================================
echo ^| Installation complete!                    ^|
echo ============================================
echo.
echo Add this to your Claude Desktop config (claude_desktop_config.json):
echo.
echo   {
echo     "mcpServers": {
echo       "ppps-github": {
echo         "command": "python",
echo         "args": ["%INSTALL_DIR:\=\\%\\tamrael_github_general.py"]
echo       }
echo     }
echo   }
echo.
echo Or run directly:  python %INSTALL_DIR%\tamrael_github_general.py
echo.

pause