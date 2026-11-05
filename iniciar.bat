@echo off
chcp 65001 >nul
echo ===============================================================
echo   SecuraPy Platform - Inicializacao Automatica (Docker)
echo ===============================================================
echo.
echo [1/3] Subindo conteineres (securapy_app, securapy_mongo, securapy_mysql)...
docker compose up -d
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO] Falha ao iniciar o Docker Compose. Verifique se o Docker Desktop esta aberto!
    pause
    exit /b 1
)
echo.
echo [2/3] Aguardando servicos ficarem prontos...
timeout /t 4 /nobreak >nul
echo.
echo [3/3] Abrindo Dashboard Web em http://localhost:5000 ...
start http://localhost:5000
echo.
echo Plataforma ativa! Para encerrar depois, execute: docker compose down
