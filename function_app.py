"""Author: Kevin Tigges
Last modified: 2026-10-08
Purpose: Run and identify scheduled vulnerability data preparation as an Azure Function.
"""

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path

import azure.functions as func
from azure.core.exceptions import ResourceNotFoundError

from vulnerability_view.config import Settings
from vulnerability_view.credentials import create_credential
from vulnerability_view.dataprep_cli import main
from vulnerability_view.storage_writer import download_current_manifest


app = func.FunctionApp()
COLLECTOR_VERSION = os.getenv("COLLECTOR_VERSION", "not-stamped")


def _run_dataprep(collection_mode: str = "auto", enrichment_mode: str = "auto") -> int:
    """Run the data-preparation CLI in the function's temporary workspace."""
    application_root = Path(__file__).resolve().parent
    policy_source = application_root / "config/sla-policies.json"
    if not policy_source.is_file():
        raise FileNotFoundError(f"Packaged SLA policy is missing: {policy_source}")

    previous_directory = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="vulnerability-view-", dir="/tmp") as temporary_directory:
        work_root = Path(temporary_directory)
        policy_target = work_root / "config/sla-policies.json"
        policy_target.parent.mkdir(parents=True)
        shutil.copy2(policy_source, policy_target)
        try:
            os.chdir(work_root)
            return main([
                "collect-live",
                "--skip-local-exports",
                "--collection",
                collection_mode,
                "--enrichment",
                enrichment_mode,
            ])
        finally:
            os.chdir(previous_directory)


def _current_run_status() -> dict:
    settings = Settings.load()
    if not settings.storage_account_name:
        raise RuntimeError("Protected history Storage is not configured")
    manifest = download_current_manifest(
        settings.storage_account_name,
        settings.storage_current_container_name,
        create_credential(settings.auth_mode, settings.client_id),
    )
    failures = [
        row for row in manifest.get("endpointStatuses", [])
        if row.get("Status") != "Success"
    ]
    findings = next(
        (
            row.get("rowCount", 0)
            for row in manifest.get("files", [])
            if row.get("dataset") == "findings"
        ),
        0,
    )
    return {
        "published": True,
        "runId": manifest.get("runId"),
        "snapshotTimeUtc": manifest.get("snapshotTimeUtc"),
        "status": "PartialSuccess" if failures else "Success",
        "findings": findings,
        "publishedFiles": len(manifest.get("files", [])),
        "reportedIssues": len(failures),
    }


@app.route(route="status", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def dataprep_status(req: func.HttpRequest) -> func.HttpResponse:
    """Return current publication status using the collector managed identity."""
    del req
    try:
        status = _current_run_status()
    except ResourceNotFoundError:
        status = {"published": False, "reason": "No current manifest has been published"}
        return func.HttpResponse(
            json.dumps(status),
            status_code=404,
            mimetype="application/json",
        )
    except Exception:
        logging.exception("Failed to read current publication status")
        return func.HttpResponse(
            json.dumps({"published": False, "reason": "Status lookup failed"}),
            status_code=500,
            mimetype="application/json",
        )
    return func.HttpResponse(json.dumps(status), mimetype="application/json")


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
def dataprep_snapshot(timer: func.TimerRequest) -> None:
    """Handle the scheduled timer invocation for a data snapshot."""
    del timer
    logging.info("Starting vulnerability dataprep collector version %s", COLLECTOR_VERSION)
    exit_code = _run_dataprep()
    if exit_code:
        raise RuntimeError(f"Scheduled vulnerability dataprep failed with exit code {exit_code}")
    logging.info("Scheduled vulnerability dataprep collector version %s completed", COLLECTOR_VERSION)


@app.generic_trigger(arg_name="input", type="manualTrigger", data_type=func.DataType.STRING)
def dataprep_manual_snapshot(input: str) -> None:
    """Run an operator-requested collection using scheduled collection policy."""
    del input
    logging.info("Starting manual vulnerability dataprep collector version %s", COLLECTOR_VERSION)
    exit_code = _run_dataprep()
    if exit_code:
        raise RuntimeError(f"Manual vulnerability dataprep failed with exit code {exit_code}")
    logging.info("Manual vulnerability dataprep collector version %s completed", COLLECTOR_VERSION)


@app.generic_trigger(arg_name="input", type="manualTrigger", data_type=func.DataType.STRING)
def dataprep_full_snapshot(input: str) -> None:
    """Run an operator-requested full vulnerability and relationship reconciliation."""
    del input
    logging.info("Starting manual full vulnerability collector version %s", COLLECTOR_VERSION)
    exit_code = _run_dataprep("full", "full")
    if exit_code:
        raise RuntimeError(f"Manual full vulnerability dataprep failed with exit code {exit_code}")
    logging.info("Manual full vulnerability collector version %s completed", COLLECTOR_VERSION)