[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [ValidateSet("targeted", "full", "none")]
    [string]$Enrichment = "targeted"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

function Get-PythonInvocation {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.12 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{
                Command = "py"
                Prefix = @("-3.12")
            }
        }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        & python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
        if ($LASTEXITCODE -eq 0) {
            return @{
                Command = "python"
                Prefix = @()
            }
        }
    }
    throw "Python 3.12 or newer is required. Install it from https://www.python.org/downloads/windows/."
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$requiredFiles = @(
    (Join-Path $repoRoot "pyproject.toml"),
    (Join-Path $repoRoot "config\sla-policies.json"),
    (Join-Path $repoRoot "src\vulnerability_view")
)
foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile)) {
        throw "Required collector content is missing: $requiredFile"
    }
}

try {
    $tenantGuid = [Guid]$TenantId
}
catch {
    throw "TenantId must be a valid Microsoft Entra tenant GUID."
}
$TenantId = $tenantGuid.ToString()

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (
    $outputRoot.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $outputRoot.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)
) {
    throw "OutputDirectory must be outside the source repository so sensitive source data cannot be committed accidentally."
}
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI is required. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli-windows."
}
$accountJson = & az account show --output json 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI is not signed in. Run: az login --tenant $TenantId"
}
$account = $accountJson | ConvertFrom-Json
if ([string]$account.tenantId -ne $TenantId) {
    throw "Azure CLI is signed in to tenant $($account.tenantId). Run: az login --tenant $TenantId"
}

$python = Get-PythonInvocation
$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("dvm-sample-data-" + [Guid]::NewGuid().ToString("N"))
$venvRoot = Join-Path $workRoot ".venv"
$collectionRoot = Join-Path $workRoot "collection"
$packageRoot = Join-Path $workRoot "package"
$previousEnvironment = @{}
$environmentOverrides = [ordered]@{
    AUTH_MODE = "local"
    AZURE_TENANT_ID = $TenantId
    APP_MODE = "live"
    STORAGE_ACCOUNT_NAME = ""
    STORAGE_CONTAINER_NAME = ""
    STORAGE_CURRENT_CONTAINER_NAME = ""
    RECOMMENDATION_ENRICHMENT_MODE = $Enrichment
    ENABLE_EXPERIMENTAL_ENDPOINTS = "false"
}

try {
    [IO.Directory]::CreateDirectory((Join-Path $collectionRoot "config")) | Out-Null
    [IO.Directory]::CreateDirectory($packageRoot) | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot "config\sla-policies.json") -Destination (Join-Path $collectionRoot "config\sla-policies.json")

    Invoke-Checked -Command $python.Command -Arguments ($python.Prefix + @("-m", "venv", $venvRoot))
    $venvPython = Join-Path $venvRoot "Scripts\python.exe"
    $collector = Join-Path $venvRoot "Scripts\vulnerability-view.exe"
    Invoke-Checked -Command $venvPython -Arguments @("-m", "pip", "install", "--disable-pip-version-check", $repoRoot)

    foreach ($name in $environmentOverrides.Keys) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $environmentOverrides[$name], "Process")
    }

    Push-Location $collectionRoot
    try {
        Write-Host "Running read-only Defender and Microsoft Graph preflight..."
        Invoke-Checked -Command $collector -Arguments @("preflight")

        Write-Host "Collecting one local-only raw snapshot..."
        Invoke-Checked -Command $collector -Arguments @("collect-live", "--local-only", "--enrichment", $Enrichment)
        Invoke-Checked -Command $collector -Arguments @("validate")

        $runFolders = @(Get-ChildItem -LiteralPath (Join-Path $collectionRoot "output\raw") -Directory -Filter "live-*")
        if ($runFolders.Count -ne 1) {
            throw "Expected exactly one raw run, found $($runFolders.Count)."
        }
        $runId = $runFolders[0].Name
        Invoke-Checked -Command $collector -Arguments @("verify-history", $runId)
    }
    finally {
        Pop-Location
    }

    $packagedRunRoot = Join-Path $packageRoot "output\raw\$runId"
    [IO.Directory]::CreateDirectory((Split-Path $packagedRunRoot -Parent)) | Out-Null
    Copy-Item -LiteralPath $runFolders[0].FullName -Destination $packagedRunRoot -Recurse

    $notice = @"
SENSITIVE SECURITY DATA

This package contains unmodified Defender Vulnerability Management and Microsoft
Graph response pages. It can contain device names and identifiers, Azure
subscription and resource identifiers, machine tags, security findings,
recommendations, software inventory details, and other tenant metadata.

The ZIP is checksum-protected but is NOT encrypted. Transfer it only through a
encrypted channel defined by organizational policy. Do not send it by ordinary email, commit it
to source control, or place it in a public or broadly shared location.

No credentials, access tokens, or client secrets are intentionally included.
"@
    [IO.File]::WriteAllText(
        (Join-Path $packageRoot "SENSITIVE-DATA.txt"),
        $notice,
        [Text.UTF8Encoding]::new($false)
    )

    $rawFiles = @(Get-ChildItem -LiteralPath $packagedRunRoot -File -Recurse | Sort-Object FullName)
    $manifestFiles = @(
        foreach ($file in $rawFiles) {
            $relativePath = $file.FullName.Substring($packageRoot.Length).TrimStart("\", "/").Replace("\", "/")
            [ordered]@{
                path = $relativePath
                bytes = $file.Length
                sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
    $manifest = [ordered]@{
        formatVersion = 1
        classification = "Sensitive security data - full raw API responses"
        createdUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        tenantId = $TenantId
        runId = $runId
        enrichmentMode = $Enrichment
        rawFileCount = $manifestFiles.Count
        rawBytes = ($rawFiles | Measure-Object -Property Length -Sum).Sum
        hashAlgorithm = "SHA256"
        files = $manifestFiles
    }
    [IO.File]::WriteAllText(
        (Join-Path $packageRoot "sample-manifest.json"),
        ($manifest | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false)
    )

    $packagePath = Join-Path $outputRoot ("dvm-sample-data-" + $runId + ".zip")
    if (Test-Path -LiteralPath $packagePath) {
        throw "The destination package already exists: $packagePath"
    }
    Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $packagePath -CompressionLevel Optimal
    $packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        "$packagePath.sha256.txt",
        "$packageHash  $([IO.Path]::GetFileName($packagePath))`n",
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host ""
    Write-Host "Sample data package created successfully."
    Write-Host "Run ID: $runId"
    Write-Host "Raw files: $($manifestFiles.Count)"
    Write-Host "Package: $packagePath"
    Write-Host "SHA-256: $packageHash"
    Write-Warning "The ZIP is not encrypted. Use only an encrypted transfer channel defined by organizational policy."
}
finally {
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
    }
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}
