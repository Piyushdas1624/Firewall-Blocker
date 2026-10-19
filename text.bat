@echo off
:: Forwarding launcher for backward compatibility with text.bat
setlocal
cd /d "%~dp0"
call "%~dp0FirewallBlocker.bat" %*
exit /b %errorlevel%