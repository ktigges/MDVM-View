# Purpose: Run reviewed deployment and verification workflows from an interactive menu.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RootDirectory = Split-Path -Parent $PSScriptRoot
$RequiredAzureCliExtensions = @("log-analytics")

function Test-PythonCommand {
    param([Parameter(Mandatory)]$Command)

    $prefix = @($Command.Prefix)
    & $Command.Executable @prefix -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

function Resolve-SystemPythonCommand {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        foreach ($version in @("-3.14", "-3.12", "-3")) {
            $command = [pscustomobject]@{ Executable = $py.Source; Prefix = @($version) }
            if (Test-PythonCommand -Command $command) {
                return $command
            }
        }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $command = [pscustomobject]@{ Executable = $python.Source; Prefix = @() }
        if (Test-PythonCommand -Command $command) {
            return $command
        }
    }

    throw "A working Python 3.12 or newer interpreter was not found. Install Python 3.14 x64, close and reopen PowerShell, and try again."
}

function Test-OperationsCliImport {
    param([Parameter(Mandatory)]$Command)

    $prefix = @($Command.Prefix)
    & $Command.Executable @prefix -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('vulnerability_view') and importlib.util.find_spec('vulnerability_view.operations_cli') else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

function Initialize-PythonCommand {
    $isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $virtualEnvironmentName = if ($isWindowsHost) { ".venv-win" } else { ".venv" }
    $virtualPythonPath = if ($isWindowsHost) { "Scripts\python.exe" } else { "bin/python" }
    $virtualEnvironment = Join-Path $RootDirectory $virtualEnvironmentName
    $virtualPython = Join-Path $virtualEnvironment $virtualPythonPath

    if ($env:PYTHON) {
        $command = [pscustomobject]@{ Executable = $env:PYTHON; Prefix = @() }
    }
    elseif (Test-Path -LiteralPath $virtualPython -PathType Leaf) {
        $command = [pscustomobject]@{ Executable = $virtualPython; Prefix = @() }
    }
    else {
        $bootstrap = Resolve-SystemPythonCommand
        $bootstrapPrefix = @($bootstrap.Prefix)
        Write-Host "Creating the deployment environment at $virtualEnvironment."
        & $bootstrap.Executable @bootstrapPrefix -m venv $virtualEnvironment | Out-Host
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $virtualPython -PathType Leaf)) {
            $bootstrapDisplay = (@($bootstrap.Executable) + $bootstrapPrefix) -join " "
            throw "Failed to create the deployment environment at $virtualEnvironment using '$bootstrapDisplay'. Review the Python error shown above."
        }
        $command = [pscustomobject]@{ Executable = $virtualPython; Prefix = @() }
    }

    if (-not (Test-OperationsCliImport -Command $command)) {
        $prefix = @($command.Prefix)
        Write-Host "Installing Vulnerability View and its deployment dependencies."
        & $command.Executable @prefix -m pip install --disable-pip-version-check -e "${RootDirectory}[dev]" | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install Vulnerability View into $($command.Executable)."
        }
    }

    if (-not (Test-OperationsCliImport -Command $command)) {
        throw "Vulnerability View is not importable from $($command.Executable) after installation."
    }

    Write-Host "Deployment Python: $($command.Executable)"
    return $command
}

function Initialize-AzureCliExtensions {
    $azureCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azureCli) {
        throw "Azure CLI was not found. Install Azure CLI, close and reopen PowerShell, and try again."
    }

    foreach ($extension in $RequiredAzureCliExtensions) {
        & $azureCli.Source extension show --name $extension --output none *> $null
        if ($LASTEXITCODE -eq 0) {
            continue
        }

        Write-Host "Installing required Azure CLI extension '$extension'."
        & $azureCli.Source extension add --name $extension --allow-preview true --yes | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install required Azure CLI extension '$extension'. Review the Azure CLI error shown above."
        }

        & $azureCli.Source extension show --name $extension --output none *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Azure CLI extension '$extension' is not available after installation."
        }
    }
}

$PythonCommand = Initialize-PythonCommand
Initialize-AzureCliExtensions

function Invoke-OperationsCli {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$CliArguments)

    Push-Location $RootDirectory
    try {
        $executable = $PythonCommand.Executable
        $prefix = @($PythonCommand.Prefix)
        & $executable @prefix -m vulnerability_view.operations_cli @CliArguments | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Pause-Menu {
    [void](Read-Host "Press Enter to return to the menu")
}

function Confirm-Value {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Prompt
    )

    Write-Host $Prompt
    return (Read-Host "Type $Expected to continue") -ceq $Expected
}

function Invoke-WebAppPlanApply {
    Write-Host "Checking Azure identity, scope, and deployment permissions."
    Invoke-OperationsCli deployment-preflight
    Write-Host "Checking regional App Service plan quota."
    Invoke-OperationsCli configure-webapp-sku
    Write-Host "Planning the cumulative Web App stage: foundation, Function, and Web App infrastructure."
    Invoke-OperationsCli plan webapp
    Invoke-OperationsCli show webapp
    if (-not (Confirm-Value -Expected "APPLY" -Prompt "Apply only if the reviewed plan has no protected-storage deletion or replacement.")) {
        Write-Host "Web App apply canceled."
        return $false
    }
    Invoke-OperationsCli apply webapp
    return $true
}

function Invoke-DeployVerify {
    param([Parameter(Mandatory)][ValidateSet("function", "webapp")][string]$Stage)

    Invoke-OperationsCli deploy $Stage
    Invoke-OperationsCli verify $Stage
}

function Invoke-LiveCollection {
    param([switch]$Full)

    Invoke-OperationsCli check-function-logs --hours 1 --limit 3 --status-only
    $expected = if ($Full) { "FULL" } else { "COLLECT" }
    $prompt = if ($Full) {
        "This forces a full vulnerability baseline and complete recommendation-machine reconciliation."
    } else {
        "This starts a live collection and publishes a new immutable run if successful."
    }
    if (-not (Confirm-Value -Expected $expected -Prompt $prompt)) {
        Write-Host "Live collection canceled."
        return
    }
    if ($Full) {
        Invoke-OperationsCli invoke function --confirm --full
    } else {
        Invoke-OperationsCli invoke function --confirm
    }
    Invoke-OperationsCli verify function
}

function Invoke-CompleteUpdate {
    if (-not (Invoke-WebAppPlanApply)) {
        return
    }
    Invoke-DeployVerify -Stage function
    Invoke-DeployVerify -Stage webapp
    Write-Host "`nComplete infrastructure and code deployment finished."
    if ((Read-Host "Run an initial/live collection now? [y/N]") -match "^[Yy]$") {
        Invoke-LiveCollection
    }
}

function Invoke-VerifyAll {
    Invoke-OperationsCli verify function
    Invoke-OperationsCli verify webapp
}

function Invoke-OperationsMenu {
    while ($true) {
        Write-Host @"

Operations and diagnostics
  1) Show current collector activity
  2) Show active progress and latest 5 published runs
  3) Show latest 10 published runs
  4) Show detailed Function diagnostics for the last 24 hours
  5) Show extended Function diagnostics for the last 72 hours
  6) Pull sanitized collector logs for the last 24 hours
  7) Verify Function and Web App
  8) Force full vulnerability and relationship reconciliation
  9) Return to deployment menu
"@
        switch (Read-Host "Select an option") {
            "1" { Invoke-OperationsCli check-function-logs --hours 1 --limit 3 --status-only; Pause-Menu }
            "2" { Invoke-OperationsCli check-runs --limit 5 --progress; Pause-Menu }
            "3" { Invoke-OperationsCli check-runs --limit 10; Pause-Menu }
            "4" { Invoke-OperationsCli check-function-logs --hours 24 --limit 10; Pause-Menu }
            "5" { Invoke-OperationsCli check-function-logs --hours 72 --limit 25; Pause-Menu }
            "6" { Invoke-OperationsCli export-function-logs --hours 24; Pause-Menu }
            "7" { Invoke-VerifyAll; Pause-Menu }
            "8" { Invoke-LiveCollection -Full; Pause-Menu }
            "9" { return }
            default { Write-Host "Select a number from 1 through 9." }
        }
    }
}

if (-not [Console]::IsOutputRedirected) {
    Clear-Host
}

Write-Host @"

Deployment identity notice
  - Deployment, update, and verification commands run as the identity currently signed in to Azure CLI.
  - That identity must have the customer tenant, subscription, resource, RBAC, and Entra permissions required by the operation.
  - The scripts and deployed application do not store the signed-in user's credentials.
  - Runtime authentication and resource access use the deployed Entra application/service principal and managed identities.
  - Run "az account show --output table" to confirm the active Azure context before continuing.
"@

while ($true) {
    Write-Host @"

Vulnerability View deployment menu
  1) Complete initial deployment or update: infrastructure, Function, and Web App
  2) Plan, review, and apply Web App infrastructure
  3) Deploy and verify Function code
  4) Deploy and verify Web App code
  5) Invoke a live collection and verify Function
  6) Verify Function and Web App
  7) Operations and diagnostics
  8) Show saved Web App plan
  9) Exit
"@
    switch (Read-Host "Select an option") {
        "1" { Invoke-CompleteUpdate; Pause-Menu }
        "2" { [void](Invoke-WebAppPlanApply); Pause-Menu }
        "3" { Invoke-DeployVerify -Stage function; Pause-Menu }
        "4" { Invoke-DeployVerify -Stage webapp; Pause-Menu }
        "5" { Invoke-LiveCollection; Pause-Menu }
        "6" { Invoke-VerifyAll; Pause-Menu }
        "7" { Invoke-OperationsMenu }
        "8" { Invoke-OperationsCli show webapp; Pause-Menu }
        "9" { return }
        default { Write-Host "Select a number from 1 through 9." }
    }
}
