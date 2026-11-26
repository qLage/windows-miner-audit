@echo off
cd /d "%~dp0"
python audit.py --lang ru --output reports
set "audit_exit=%errorlevel%"
echo.
echo Exit code: %audit_exit%  [0=no rule matches, 1=review findings, 2=incomplete]
pause
exit /b %audit_exit%
