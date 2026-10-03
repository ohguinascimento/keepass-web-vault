@echo off
title KeePass Web Vault
echo ========================================================
echo   Iniciando KeePass Web Vault (Leitor Seguro de Senhas)
echo ========================================================
echo.
echo Abrindo servidor local em http://localhost:5173 ...
echo.
start http://localhost:5173
call npm.cmd run dev
pause
