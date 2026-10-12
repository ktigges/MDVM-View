# Purpose: Remove replaceable application resources while preserving protected history.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RootDirectory = Split-Path -Parent $PSScriptRoot
$WindowsPython = Join-Path $RootDirectory ".venv-win\Scripts\python.exe"
$MacPython = Join-Path $RootDirectory ".venv\bin\python"

if ($env:PYTHON) {
    $Python = $env:PYTHON
}
elseif (Test-Path -LiteralPath $WindowsPython -PathType Leaf) {
    $Python = $WindowsPython
}
elseif (Test-Path -LiteralPath $MacPython -PathType Leaf) {
    $Python = $MacPython
}
else {
    throw "The deployment Python environment was not found. Run infra\deployment-menu.ps1 once to create .venv-win."
}

function Invoke-OperationsCli {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$CliArguments)

    Push-Location $RootDirectory
    try {
        & $Python -m vulnerability_view.operations_cli @CliArguments | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Read-Output {
    param([Parameter(Mandatory)][string]$Name)

    Push-Location $RootDirectory
    try {
        $value = (& $Python -m vulnerability_view.operations_cli output $Name)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read Terraform output $Name."
        }
        return ($value | Out-String).Trim()
    }
    finally {
        Pop-Location
    }
}

function Confirm-Exact {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Prompt
    )

    Write-Host $Prompt
    return (Read-Host "Type $Expected to continue") -ceq $Expected
}

Write-Host "Checking Azure identity, scope, and teardown permissions."
Invoke-OperationsCli deployment-preflight

$ResourceGroup = Read-Output resource_group_name
$FunctionApp = Read-Output function_app_name
$WebApp = Read-Output web_app_name
$HistoryAccount = Read-Output history_storage_account_name
$HistoryContainer = Read-Output history_container_name
$CurrentContainer = Read-Output current_container_name
$WorkflowContainer = Read-Output dashboard_recommendation_tracking_container

Write-Host @"

SAFE APPLICATION TEARDOWN

Replaceable resources selected for removal include:
  - Function App: $FunctionApp
  - Web App: $WebApp
  - Function runtime Storage
  - Application identities, monitoring resources, and related assignments
  - Dashboard Microsoft Entra application and Enterprise Application

Resources that must remain:
  - Resource group: $ResourceGroup
  - Protected history account: $HistoryAccount
  - History container: $HistoryContainer
  - Current-pointer container: $CurrentContainer
  - Protected workflow container: $WorkflowContainer
  - Network perimeter foundation and local Terraform state
"@

Write-Host "Creating and validating the application teardown plan."
Invoke-OperationsCli teardown-plan
Invoke-OperationsCli teardown-show

if (-not (Confirm-Exact -Expected "REVIEWED PLAN" -Prompt "Confirmation 1 of 4: Confirm that the displayed plan removes only replaceable application resources.")) {
    throw "Application teardown canceled at confirmation 1."
}
if (-not (Confirm-Exact -Expected $ResourceGroup -Prompt "Confirmation 2 of 4: Confirm the resource group whose protected foundation will remain.")) {
    throw "Application teardown canceled at confirmation 2."
}
if (-not (Confirm-Exact -Expected $WebApp -Prompt "Confirmation 3 of 4: Confirm the Web App selected for removal.")) {
    throw "Application teardown canceled at confirmation 3."
}
if (-not (Confirm-Exact -Expected "REMOVE REPLACEABLE APPLICATION" -Prompt "Confirmation 4 of 4: This removes the Function, Web App, identities, directory application, and related assignments.")) {
    throw "Application teardown canceled at confirmation 4."
}

Invoke-OperationsCli teardown-apply
Write-Host "Application teardown completed. Protected history and foundation resources remain."
