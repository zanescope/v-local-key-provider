param(
    [ValidateSet("windows")]
    [string]$Target = "windows",
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [switch]$Release,
    [switch]$Candidate,
    [string]$CertificateThumbprint,
    [string]$PromotionPath,
    [string]$SignToolPath,
    [ValidatePattern('^https://')]
    [string]$TimestampUrl = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = Join-Path $ProjectRoot ".codex-temp\go-cache"
$TempDir = Join-Path $ProjectRoot ".codex-temp\go-tmp"
$OutputDir = Join-Path $ProjectRoot "build\windows-$Arch"
$Output = Join-Path $OutputDir "v-local-key-provider.exe"
$ReleaseSignerSHA256 = ""
$ReleasePromotionSHA256 = ""

if ($Release) {
	if ($Candidate) {
		throw "-Release 与 -Candidate 不能同时使用"
	}
    if (-not $CertificateThumbprint) {
        throw "-Release 必须同时提供 -CertificateThumbprint"
    }
	if ([string]::IsNullOrWhiteSpace($PromotionPath)) {
		throw "-Release 必须提供外部两阶段验收生成的 -PromotionPath"
    }
	$PromotionPath = (Resolve-Path -LiteralPath $PromotionPath -ErrorAction Stop).Path
	$PromotionRoot = [IO.Path]::GetFullPath((Join-Path $ProjectRoot "compatibility-evidence\promotions"))
	if (-not $PromotionPath.StartsWith($PromotionRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
		throw "promotion manifest 必须位于 compatibility-evidence/promotions"
	}
	$ReleasePromotionSHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PromotionPath).Hash.ToLowerInvariant()
    $SigningCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
    if (-not $SigningCertificate.RawData) {
        throw "无法读取 Authenticode 签名证书"
    }
    $ReleaseSignerSHA256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($SigningCertificate.RawData)
    ).ToLowerInvariant()
}

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
Push-Location $ProjectRoot
try {
    if ($Release) {
        $env:V_LOCAL_KEY_PROVIDER_REQUIRE_RELEASE_EVIDENCE = "1"
        $env:V_LOCAL_KEY_PROVIDER_RELEASE_TARGET = "windows"
        $env:V_LOCAL_KEY_PROVIDER_RELEASE_ARCH = $Arch
        $env:V_LOCAL_KEY_PROVIDER_RELEASE_EVIDENCE_DIR = Join-Path $ProjectRoot "compatibility-evidence"
        $env:V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH = $PromotionPath
        try {
            & go test -count=1 -run '^TestReleaseCompatibilityEvidenceGate$' .
            if ($LASTEXITCODE -ne 0) {
                throw "Windows 发布目标缺少候选绑定的真机兼容证据"
            }
        }
        finally {
            Remove-Item Env:V_LOCAL_KEY_PROVIDER_REQUIRE_RELEASE_EVIDENCE -ErrorAction SilentlyContinue
            Remove-Item Env:V_LOCAL_KEY_PROVIDER_RELEASE_TARGET -ErrorAction SilentlyContinue
            Remove-Item Env:V_LOCAL_KEY_PROVIDER_RELEASE_ARCH -ErrorAction SilentlyContinue
            Remove-Item Env:V_LOCAL_KEY_PROVIDER_RELEASE_EVIDENCE_DIR -ErrorAction SilentlyContinue
            Remove-Item Env:V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH -ErrorAction SilentlyContinue
        }
    }
    & go test ./...
    if ($LASTEXITCODE -ne 0) {
        throw "密钥 Provider 测试失败"
    }
    $env:GOOS = "windows"
    $env:GOARCH = $Arch
    $env:CGO_ENABLED = "0"
    $LdFlags = "-s -w"
    if ($Release) {
		$LdFlags += " -X main.buildMode=release -X main.releaseSignerSHA256=$ReleaseSignerSHA256 -X main.releasePromotionSHA256=$ReleasePromotionSHA256"
	} elseif ($Candidate) {
		$LdFlags += " -X main.buildMode=candidate"
    }
    & go build -trimpath -ldflags $LdFlags -o $Output ./cmd/v-local-key-provider
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
    $ActualSignerSHA256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Signature.SignerCertificate.RawData)
    ).ToLowerInvariant()
    if ($ActualSignerSHA256 -ne $ReleaseSignerSHA256) {
        throw "发布件签名者与编译期绑定证书不匹配"
    }
    $Signed = $true
    $Timestamped = $true
}

$Digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash.ToLowerInvariant()
$SignerThumbprint = if ($Signed) { $Signature.SignerCertificate.Thumbprint.ToLowerInvariant() } else { "" }
$TimestampSignerThumbprint = if ($Timestamped) { $Signature.TimeStamperCertificate.Thumbprint.ToLowerInvariant() } else { "" }
$Manifest = [ordered]@{
    schema_version = 1
    protocol = "v-local-key-provider/v1"
    platform = "windows"
    arch = $Arch
    sha256 = $Digest
    signed = $Signed
	build = if ($Release) { "release" } elseif ($Candidate) { "candidate" } else { "development" }
	build_mode = if ($Release) { "release" } elseif ($Candidate) { "candidate" } else { "development" }
    runtime_authenticode_required = [bool]$Release
    fixed_install_required = [bool]$Release
    compatibility_evidence_required = [bool]$Release
    compatibility_evidence_ready = [bool]$Release
	compatibility_promotion_sha256 = if ($Release) { $ReleasePromotionSHA256 } else { "" }
    signature = if ($Signed) { "authenticode" } else { "none" }
    signer_thumbprint = $SignerThumbprint
    signer_certificate_sha256 = if ($Signed) { $ReleaseSignerSHA256 } else { "" }
    timestamp_signer_thumbprint = $TimestampSignerThumbprint
    timestamped = $Timestamped
} | ConvertTo-Json
[System.IO.File]::WriteAllText(
    (Join-Path $OutputDir "manifest.json"),
    $Manifest,
    [System.Text.UTF8Encoding]::new($false)
)

[ordered]@{
    target = "windows/$Arch"
    output = $Output
    sha256 = $Digest
    signed = $Signed
    timestamped = $Timestamped
} | ConvertTo-Json
