# Gera o arquivo .env com segredos aleatórios a partir do .env.example.
# Uso: powershell -ExecutionPolicy Bypass -File .\setup.ps1   (use -Force para recriar)
param([switch]$Force)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$example = Join-Path $root ".env.example"
$envFile = Join-Path $root ".env"

if ((Test-Path $envFile) -and -not $Force) {
    Write-Host ".env já existe. Nada foi alterado (use -Force para recriar e perder os segredos atuais)." -ForegroundColor Yellow
    exit 0
}
if (-not (Test-Path $example)) { throw "Arquivo .env.example não encontrado em $root" }

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function New-RandomBytes([int]$n) { $b = New-Object byte[] $n; $rng.GetBytes($b); return $b }

# Base64 URL-safe (sem caracteres problemáticos para URL de conexão do banco)
function New-Secret([int]$bytes) {
    return ([Convert]::ToBase64String((New-RandomBytes $bytes))).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
}

# Senha legível que atende à política (>= 12 caracteres, minúsculas, maiúsculas, números, símbolo)
function New-Password {
    $lower = 'abcdefghijkmnopqrstuvwxyz'; $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $digits = '23456789'
    $all = $lower + $upper + $digits
    $chars = @()
    $bytes = New-RandomBytes 16
    for ($i = 0; $i -lt 13; $i++) { $chars += $all[$bytes[$i] % $all.Length] }
    $chars += $lower[$bytes[13] % $lower.Length]
    $chars += $upper[$bytes[14] % $upper.Length]
    $chars += $digits[$bytes[15] % $digits.Length]
    return (-join $chars) + '!'
}

$values = @{
    "POSTGRES_PASSWORD" = New-Secret 24
    "JWT_SECRET"        = New-Secret 48
    "MASTER_KEY"        = [Convert]::ToBase64String((New-RandomBytes 32))
    "ADMIN_PASSWORD"    = New-Password
    "DEMO_PASSWORD"     = New-Password
}

$lines = Get-Content -Path $example -Encoding UTF8 | ForEach-Object {
    if ($_ -match '^([A-Z_]+)=TROCAR\s*$' -and $values.ContainsKey($Matches[1])) {
        "$($Matches[1])=$($values[$Matches[1]])"
    } else { $_ }
}

# UTF-8 sem BOM e com LF (lido pelo docker compose)
[System.IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "Arquivo .env criado com segredos aleatórios." -ForegroundColor Green
Write-Host "Guarde as senhas abaixo (também estão no .env):"
Write-Host ""
Write-Host ("  admin                      : {0}" -f $values["ADMIN_PASSWORD"]) -ForegroundColor Cyan
Write-Host ("  auditor / gestor / leitura : {0}" -f $values["DEMO_PASSWORD"]) -ForegroundColor Cyan
Write-Host ""
Write-Host "Próximo passo:  docker compose up -d --build   e acesse https://localhost:8443"
