@echo off
cd /d %~dp0
:loop
"C:\Program Files\nodejs\node.exe" socks5.js >> proxy.log 2>&1
echo [%date% %time%] node exited, restarting in 3s >> proxy.log
timeout /t 3 /nobreak >nul
goto loop
