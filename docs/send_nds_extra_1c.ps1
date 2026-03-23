<#
.SYNOPSIS
  Отправка НДС-отчёта в СБИС через API send-nds-extra-1c.
  Кладите в папку docs: главный XML и книги (продажи/покупки) — скрипт сам определит main и book_xml_b64_list.

.PARAMETER DocsPath
  Папка с XML (по умолчанию — docs рядом со скриптом).

.PARAMETER Inn
  ИНН организации (по умолчанию 7751224222).

.PARAMETER BaseUrl
  Базовый URL API (по умолчанию http://localhost:8000).

.PARAMETER DryRun
  Если указан — dry_run=true (проверка без отправки в СБИС).

.PARAMETER NoSend
  Не отправлять запрос. Собрать curl в формате с \ и многострочным -d, сохранить в файл (вывод).

.PARAMETER OutRequest
  Файл, в который сохранить готовую команду curl (при NoSend; по умолчанию — вывод в папке docs).

.EXAMPLE
  .\send_nds_extra_1c.ps1 -NoSend
  .\send_nds_extra_1c.ps1 -Inn 9721146348 -DryRun
  .\send_nds_extra_1c.ps1 -NoSend -OutRequest my_request.json
#>
param(
    [string] $DocsPath = "",
    [string] $Inn = "7751224222",
    [string] $BaseUrl = "http://localhost:8000",
    [switch] $DryRun,
    [switch] $NoSend,
    [string] $OutRequest = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DocsPath) { $DocsPath = Join-Path $ScriptDir "." }

# Все XML в папке
$allXml = Get-ChildItem -Path $DocsPath -Filter "*.xml" -File | Sort-Object Name
if ($allXml.Count -eq 0) {
    Write-Error "В папке '$DocsPath' нет файлов *.xml"
}

# Главный файл: имя БЕЗ паттерна NO_NDS_8_ или NO_NDS_9_ (титульный отчёт)
# Книги: NO_NDS_8_* (покупки), NO_NDS_9_* (продажи) — сортируем по имени
$mainFile = $null
$bookFiles = @()
foreach ($f in $allXml) {
    $name = $f.Name
    if ($name -match "NO_NDS_[89]_") {
        $bookFiles += $f
    } else {
        if ($null -eq $mainFile) { $mainFile = $f }
    }
}
# Если главный не найден по правилу — берём первый как main, остальные как books
if ($null -eq $mainFile) {
    $mainFile = $allXml[0]
    $bookFiles = @($allXml[1..($allXml.Count - 1)])
} else {
    $bookFiles = $bookFiles | Sort-Object Name
}

function Get-FileBase64 {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    [Convert]::ToBase64String($bytes)
}

$mainB64 = Get-FileBase64 -Path $mainFile.FullName
$bookB64List = @()
foreach ($b in $bookFiles) {
    $bookB64List += Get-FileBase64 -Path $b.FullName
}

Write-Host "Main: $($mainFile.Name)"
foreach ($b in $bookFiles) { Write-Host "Book: $($b.Name)" }

$bodyObj = @{
    inn                 = $Inn
    main_xml_b64        = $mainB64
    book_xml_b64_list   = $bookB64List
}
if ($DryRun) { $bodyObj["dry_run"] = $true }
$body = $bodyObj | ConvertTo-Json -Compress

$url = $BaseUrl.TrimEnd("/") + "/api/sbis/send-nds-extra-1c/"
$doNotSend = $NoSend -or $OutRequest
if ($doNotSend) {
    # Книги: каждая строка "      \"base64\"," кроме последней — без запятой
    $bookLines = @()
    for ($i = 0; $i -lt $bookB64List.Count; $i++) {
        $comma = if ($i -lt $bookB64List.Count - 1) { "," } else { "" }
        $bookLines += "      `"$($bookB64List[$i])`"$comma"
    }
    $bookBlock = $bookLines -join "`n"
    # Строгий порядок строк, как в примере
    $curlContent = @"
curl -i -X POST "$url" \
  -H "Content-Type: application/json" \
  -d '{
    "inn": "$Inn",
    "main_xml_b64": "$mainB64",
    "book_xml_b64_list": [
$bookBlock
    ]
  }'
"@
    $outFile = if ($OutRequest) { $OutRequest } else { Join-Path $ScriptDir "вывод" }
    $outDir = Split-Path -Parent $outFile
    if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $curlContent | Set-Content -Path $outFile -Encoding UTF8 -NoNewline
    Write-Host ""
    Write-Host "Запрос не отправлен. curl сохранён в: $outFile"
    Write-Host ""
    exit 0
}

$resp = Invoke-RestMethod -Uri $url -Method POST -ContentType "application/json; charset=utf-8" -Body $body
$resp | ConvertTo-Json -Depth 10
