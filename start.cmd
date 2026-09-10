@echo off
cd /d C:\office-proxy
:loop
"C:\Program Files\nodejs\node.exe" office-socks.js >> C:\office-proxy\proxy.log 2>&1
echo [%date% %time%] node exited, restarting in 3s >> C:\office-proxy\proxy.log
timeout /t 3 /nobreak >nul
goto loop
