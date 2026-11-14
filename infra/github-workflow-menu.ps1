# Purpose: Publish tested development work and promote customer-ready releases.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RootDirectory = Split-Path -Parent $PSScriptRoot

function Resolve-PythonCommand {
    if ($env:PYTHON) {
        return [pscustomobject]@{ Executable = $env:PYTHON; Prefix = @() }
    }
    foreach ($candidate in @(
        (Join-Path $RootDirectory ".venv-win\Scripts\python.exe"),
        (Join-Path $RootDirectory ".venv\Scripts\python.exe"),
        (Join-Path $RootDirectory ".venv/bin/python")
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ Executable = $candidate; Prefix = @() }
        }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return [pscustomobject]@{ Executable = $python.Source; Prefix = @() }
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return [pscustomobject]@{ Executable = $py.Source; Prefix = @("-3") }
    }
    throw "Python was not found. Create .venv-win or set PYTHON to the interpreter path."
}

$PythonCommand = Resolve-PythonCommand

function Invoke-GitHubWorkflow {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$WorkflowArguments)

    Push-Location $RootDirectory
    try {
        $executable = $PythonCommand.Executable
        $prefix = @($PythonCommand.Prefix)
        & $executable @prefix -m vulnerability_view.github_workflow_cli @WorkflowArguments | Out-Host
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

while ($true) {
    Clear-Host
    Write-Host @"
GitHub development and customer release workflow

  main      = active development and testing
  latest    = customer-ready stable release
  archive/* = read-only snapshots (never pushed or merged from here)
  other     = work branches (for example refactor/sla-simplification)

  Options 1-4 run on main; options 5-6 run on a work branch.

  1) Test, commit, and publish current work to main
  2) Test and promote origin/main to latest for customers
  3) Test once, publish main, and promote latest
  4) Validate customer release readiness
  5) Test, commit, and push the current work branch
  6) Merge the pushed work branch into main (fast-forward; no push)
  7) Exit
"@
    $choice = Read-Host "Select an option"
    switch ($choice) {
        "1" {
            Invoke-GitHubWorkflow status
            $commitMessage = Read-Host "Commit message (required only when changes are uncommitted)"
            Write-Host "This stages all current worktree changes, runs tests, commits if needed, and pushes main."
            $confirmation = Read-Host "Type PUBLISH to continue"
            Invoke-GitHubWorkflow publish-main --message $commitMessage --confirm $confirmation
            Pause-Menu
        }
        "2" {
            Invoke-GitHubWorkflow status
            Write-Host "This promotes the exact tested origin/main commit to the customer-facing latest branch."
            $confirmation = Read-Host "Type PROMOTE to continue"
            Invoke-GitHubWorkflow promote-latest --confirm $confirmation
            Pause-Menu
        }
        "3" {
            Invoke-GitHubWorkflow status
            $commitMessage = Read-Host "Commit message (required only when changes are uncommitted)"
            Write-Host "This runs tests once, publishes main, and promotes the same tested commit to latest."
            Invoke-GitHubWorkflow publish-and-promote --message $commitMessage
            Pause-Menu
        }
        "4" {
            Invoke-GitHubWorkflow validate-release
            Pause-Menu
        }
        "5" {
            Invoke-GitHubWorkflow status
            $commitMessage = Read-Host "Commit message (required only when changes are uncommitted)"
            $allowFailing = Read-Host "Work branches normally require passing tests. Type ALLOW-FAILING to push even if tests fail, or press Enter"
            Write-Host "This stages all current worktree changes, runs tests, commits if needed, and pushes this work branch only."
            $confirmation = Read-Host "Type PUSH to continue"
            $branchArguments = @("publish-branch", "--message", $commitMessage, "--confirm", $confirmation)
            if ($allowFailing -eq "ALLOW-FAILING") {
                $branchArguments += "--allow-failing-tests"
            }
            try { Invoke-GitHubWorkflow @branchArguments } catch { Write-Host $_ }
            Pause-Menu
        }
        "6" {
            Invoke-GitHubWorkflow status
            Write-Host "This fast-forwards local main to the pushed work branch and switches to main. Nothing is pushed."
            $confirmation = Read-Host "Type MERGE to continue"
            try { Invoke-GitHubWorkflow merge-into-main --confirm $confirmation } catch { Write-Host $_ }
            Pause-Menu
        }
        "7" {
            return
        }
        default {
            Write-Host "Invalid selection."
            Pause-Menu
        }
    }
}
