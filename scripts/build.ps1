param(
    [ValidateSet("windows")]
    [string]$Target = "windows",
    [switch]$Release,
    [string]$CertificateThumbprint,
    [string]$SignToolPath,
    [ValidatePattern('^https://')]
    [string]$TimestampUrl = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = Join-Path $ProjectRoot ".codex-temp\go-cache"
$TempDir = Join-Path $ProjectRoot ".codex-temp\go-tmp"
$OutputDir = Join-Path $ProjectRoot "build\windows-amd64"
$Output = Join-Path $OutputDir "v-local-key-provider.exe"

function Resolve-SignTool([string]$ExplicitPath) {
    if ($ExplicitPath) {
        return (Resolve-Path -LiteralPath $ExplicitPath -ErrorAction Stop).Path
    }
    $Command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($Command) {
        return $Command.Source
    }
    throw "未找到 SignTool；请安装 Windows SDK 或传入 -SignToolPath"
}

New-Item -ItemType Directory -Force $CacheDir, $TempDir, $OutputDir | Out-Null
$env:GOCACHE = $CacheDir
$env:GOTMPDIR = $TempDir
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

Push-Location $ProjectRoot
try {
    & go test ./...
    if ($LASTEXITCODE -ne 0) {
        throw "密钥 Provider 测试失败"
    }
    & go build -trimpath -ldflags "-s -w" -o $Output .
    if ($LASTEXITCODE -ne 0) {
        throw "密钥 Provider 构建失败"
    }
}
finally {
    Pop-Location
}

$Signed = $false
$Timestamped = $false
if ($Release) {
    if (-not $CertificateThumbprint) {
        throw "-Release 必须同时提供 -CertificateThumbprint"
    }
    $ResolvedSignTool = Resolve-SignTool $SignToolPath
    & $ResolvedSignTool sign /fd SHA256 /sha1 $CertificateThumbprint `
        /tr $TimestampUrl /td SHA256 $Output
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode 签名失败"
    }
    & $ResolvedSignTool verify /pa /all $Output
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode 验证失败"
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Output
    if ($Signature.Status -ne "Valid" -or -not $Signature.TimeStamperCertificate) {
        throw "发布件缺少有效签名或可信时间戳"
    }
    $Signed = $true
    $Timestamped = $true
}

$Digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash.ToLowerInvariant()
$Manifest = [ordered]@{
    protocol = "v-local-key-provider/v2"
    platform = "windows"
    arch = "amd64"
    sha256 = $Digest
    signed = $Signed
    build = if ($Release) { "release" } else { "development" }
    signature = if ($Signed) { "authenticode" } else { "none" }
    timestamped = $Timestamped
} | ConvertTo-Json
[System.IO.File]::WriteAllText(
    (Join-Path $OutputDir "manifest.json"),
    $Manifest,
    [System.Text.UTF8Encoding]::new($false)
)

[ordered]@{
    target = "windows/amd64"
    output = $Output
    sha256 = $Digest
    signed = $Signed
    timestamped = $Timestamped
} | ConvertTo-Json
