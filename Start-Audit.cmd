@echo off
chcp 65001 >nul
setlocal
set "PYTHONUTF8=1"
cd /d "%~dp0"
python audit.py --lang ru --output reports
set "audit_exit=%errorlevel%"
echo.
echo Код / Exit code: %audit_exit%  [0=нет совпадений / no matches, 1=есть находки / findings, 2=неполная проверка / incomplete]
pause
exit /b %audit_exit%
