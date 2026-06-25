# Скрипт сборки L2TP VPN Web Manager под все целевые платформы
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   Сборка L2TP VPN Web Manager под Keenetic" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Сборка для Windows (локальное тестирование)
Write-Host "[+] Сборка для Windows amd64..." -ForegroundColor Green
$env:CGO_ENABLED="0"
$env:GOOS="windows"
$env:GOARCH="amd64"
$env:GOMIPS=""
$env:GOARM=""
go build -buildvcs=false -o l2tp-web.exe

# 2. Сборка для Linux mipsle (основная масса Keenetic на MT7621)
Write-Host "[+] Сборка для Linux mipsle (softfloat)..." -ForegroundColor Green
$env:CGO_ENABLED="0"
$env:GOOS="linux"
$env:GOARCH="mipsle"
$env:GOMIPS="softfloat"
go build -buildvcs=false -ldflags="-s -w" -o l2tp-web-mipsle

# 3. Сборка для Linux arm (32-bit Keenetic)
Write-Host "[+] Сборка для Linux arm (GOARM=7)..." -ForegroundColor Green
$env:CGO_ENABLED="0"
$env:GOOS="linux"
$env:GOARCH="arm"
$env:GOARM="7"
$env:GOMIPS=""
go build -buildvcs=false -ldflags="-s -w" -o l2tp-web-arm

# 4. Сборка для Linux arm64 (мощные Keenetic)
Write-Host "[+] Сборка для Linux arm64..." -ForegroundColor Green
$env:CGO_ENABLED="0"
$env:GOOS="linux"
$env:GOARCH="arm64"
$env:GOARM=""
go build -buildvcs=false -ldflags="-s -w" -o l2tp-web-arm64

# 5. Сборка для стандартного Linux amd64
Write-Host "[+] Сборка для Linux amd64..." -ForegroundColor Green
$env:CGO_ENABLED="0"
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -buildvcs=false -ldflags="-s -w" -o l2tp-web-linux

# Сброс переменных окружения
$env:GOOS=""
$env:GOARCH=""
$env:GOMIPS=""
$env:GOARM=""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   Сборка успешно завершена!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Get-ChildItem l2tp-web* | Select-Object Name, @{Name="Size (MB)"; Expression={[math]::round($_.Length / 1MB, 2)}}
