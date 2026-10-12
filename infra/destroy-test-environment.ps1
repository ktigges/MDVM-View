# Purpose: Permanently delete one explicitly confirmed disposable test environment.

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

function Read-ConfigValue {
    param([Parameter(Mandatory)][string]$Name)

    Push-Location $RootDirectory
    try {
        $value = (& $Python -m vulnerability_view.operations_cli config-value $Name)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read configured value $Name."
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

Invoke-OperationsCli deployment-preflight

$SubscriptionId = Read-ConfigValue subscription_id
$ResourceGroup = Read-ConfigValue resource_group_name
$HistoryAccount = Read-ConfigValue history_storage_account_name
$ActiveSubscriptionId = (az account show --query id --output tsv).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Could not read the active Azure CLI subscription."
}
if ($ActiveSubscriptionId -cne $SubscriptionId) {
    throw "Azure CLI is using subscription $ActiveSubscriptionId, but this deployment uses $SubscriptionId. Run az account set --subscription $SubscriptionId and retry."
}

Write-Host @"

PERMANENT TEST-ENVIRONMENT DELETION

This operation permanently deletes:
  - Subscription target: $SubscriptionId
  - Resource group: $ResourceGroup
  - Protected history account: $HistoryAccount
  - All immutable and current history
  - Every container and resource remaining in the resource group
  - Terraform-managed application identities, directory objects, and assignments

This operation is only for a disposable test environment. It cannot be undone.
"@

Invoke-OperationsCli teardown-plan --allow-empty
Invoke-OperationsCli teardown-show --allow-empty
az resource list --subscription $SubscriptionId --resource-group $ResourceGroup --output table
if ($LASTEXITCODE -ne 0) {
    throw "Could not enumerate the exact resource group selected for deletion."
}

if (-not (Confirm-Exact -Expected "DELETE TEST ENVIRONMENT" -Prompt "Confirmation 1 of 4: Confirm this is a disposable test environment with no history that must be retained.")) {
    throw "Full test-environment deletion canceled at confirmation 1."
}
if (-not (Confirm-Exact -Expected $SubscriptionId -Prompt "Confirmation 2 of 4: Confirm the exact Azure subscription.")) {
    throw "Full test-environment deletion canceled at confirmation 2."
}
if (-not (Confirm-Exact -Expected $ResourceGroup -Prompt "Confirmation 3 of 4: Confirm the exact resource group and every resource inside it.")) {
    throw "Full test-environment deletion canceled at confirmation 3."
}
$FinalConfirmation = "PERMANENTLY DELETE $ResourceGroup"
if (-not (Confirm-Exact -Expected $FinalConfirmation -Prompt "Confirmation 4 of 4: Permanently delete all application resources and retained history.")) {
    throw "Full test-environment deletion canceled at confirmation 4."
}

Invoke-OperationsCli teardown-apply --allow-empty
az group delete --subscription $SubscriptionId --name $ResourceGroup --yes
if ($LASTEXITCODE -ne 0) {
    throw "Azure failed to delete resource group $ResourceGroup."
}
$StillExists = (az group exists --subscription $SubscriptionId --name $ResourceGroup --output tsv).Trim()
if ($LASTEXITCODE -ne 0 -or $StillExists -ne "false") {
    throw "Deletion did not complete: resource group $ResourceGroup still exists."
}

Write-Host "Confirmed deleted: resource group $ResourceGroup and all resources and history inside it."
