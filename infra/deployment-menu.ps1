# Purpose: Run reviewed deployment and verification workflows from an interactive menu.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RootDirectory = Split-Path -Parent $PSScriptRoot

function Resolve-PythonCommand {
    if ($env:PYTHON) {
        return @($env:PYTHON)
    }

    $candidates = @(
        (Join-Path $RootDirectory ".venv-win\Scripts\python.exe"),
        (Join-Path $RootDirectory ".venv\Scripts\python.exe"),
        (Join-Path $RootDirectory ".venv/bin/python")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return @($candidate)
        }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @($python.Source)
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return @($py.Source, "-3")
    }

    throw "Python was not found. Create .venv-win or set PYTHON to the interpreter path."
}

$PythonCommand = Resolve-PythonCommand

function Invoke-OperationsCli {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$CliArguments)

    Push-Location $RootDirectory
    try {
        $executable = $PythonCommand[0]
        $prefix = @($PythonCommand | Select-Object -Skip 1)
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
  6) Verify Function and Web App
  7) Force full vulnerability and relationship reconciliation
  8) Return to deployment menu
"@
        switch (Read-Host "Select an option") {
            "1" { Invoke-OperationsCli check-function-logs --hours 1 --limit 3 --status-only; Pause-Menu }
            "2" { Invoke-OperationsCli check-runs --limit 5 --progress; Pause-Menu }
            "3" { Invoke-OperationsCli check-runs --limit 10; Pause-Menu }
            "4" { Invoke-OperationsCli check-function-logs --hours 24 --limit 10; Pause-Menu }
            "5" { Invoke-OperationsCli check-function-logs --hours 72 --limit 25; Pause-Menu }
            "6" { Invoke-VerifyAll; Pause-Menu }
            "7" { Invoke-LiveCollection -Full; Pause-Menu }
            "8" { return }
            default { Write-Host "Select a number from 1 through 8." }
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
