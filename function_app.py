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
import azure.durable_functions as df
from azure.durable_functions.models.DurableOrchestrationStatus import DurableOrchestrationStatus
import requests
from azure.core.exceptions import AzureError, ResourceNotFoundError

from vulnerability_view.config import Settings, load_function_version
from vulnerability_view.credentials import create_credential
from vulnerability_view.dataprep_cli import main
from vulnerability_view.defender_client import COLLECTION_PAGE_SIZE, MACHINE_FINDINGS_PAGE_SIZE, DefenderApiError, collection_page_size, probe_defender_page
from vulnerability_view.storage_writer import download_current_manifest
from vulnerability_view.collection_workflow import (
    INSTANCE_ID, RunStore, execute_worker, orchestrate, prepare_run, publish_run, start_collection, verify_file,
)


app = df.DFApp()
COLLECTOR_VERSION = load_function_version(Path(__file__).resolve().with_name("function-version.json"))


def _run_dataprep(collection_mode: str = "auto", enrichment_mode: str = "auto", *, page_size: int = MACHINE_FINDINGS_PAGE_SIZE, debug: bool = False, debug_endpoint: str = "machine_vulnerabilities") -> int:
    """Run the data-preparation CLI in the function's temporary workspace."""
    if debug:
        return main(["probe-live", "--page-size", str(collection_page_size(page_size, maximum=COLLECTION_PAGE_SIZE)), "--endpoint", debug_endpoint])
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
                "--page-size",
                str(collection_page_size(page_size)),
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
@app.durable_client_input(client_name="client")
async def dataprep_status(req: func.HttpRequest, client: df.DurableOrchestrationClient) -> func.HttpResponse:
    """Return current publication status using the collector managed identity."""
    del req
    workflow = None
    try:
        workflow = await client.get_status(INSTANCE_ID)
        status = _current_run_status()
    except ResourceNotFoundError:
        status = {"published": False, "reason": "No current manifest has been published"}
        if workflow is not None:
            status["workflow"] = _workflow_status(workflow)
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
    if workflow is not None:
        status["workflow"] = _workflow_status(workflow)
    return func.HttpResponse(json.dumps(status), mimetype="application/json")


def _workflow_status(workflow: DurableOrchestrationStatus) -> dict:
    return {
        "instanceId": workflow.instance_id,
        "state": workflow.runtime_status.value,
        "createdUtc": workflow.created_time.isoformat(),
        "updatedUtc": workflow.last_updated_time.isoformat(),
        "progress": workflow.custom_status,
    }


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
@app.durable_client_input(client_name="client")
async def dataprep_snapshot(timer: func.TimerRequest, client: df.DurableOrchestrationClient) -> None:
    """Handle the scheduled timer invocation for a data snapshot."""
    del timer
    await start_collection(client, {"collection": "auto", "enrichment": "auto", "pageSize": MACHINE_FINDINGS_PAGE_SIZE})


@app.route(route="debug-page", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def dataprep_debug_http(req: func.HttpRequest) -> func.HttpResponse:
    """Return the actual one-page API result without waiting for telemetry."""
    try:
        options = req.get_json()
        if not isinstance(options, dict):
            raise ValueError("Debug request must be a JSON object")
        endpoint = options.get("endpoint", "machine_vulnerabilities")
        if endpoint not in ("machine_vulnerabilities", "vulnerabilities"):
            raise ValueError("Debug endpoint must be machine_vulnerabilities or vulnerabilities")
        page_size = collection_page_size(options.get("pageSize", COLLECTION_PAGE_SIZE if endpoint == "vulnerabilities" else 1), maximum=COLLECTION_PAGE_SIZE)
    except ValueError as error:
        logging.warning("[debug] FAILED: Invalid debug request: %s", error)
        return func.HttpResponse(
            json.dumps({"Status": "FAILED", "Error": str(error), "CollectorVersion": COLLECTOR_VERSION}),
            status_code=400, mimetype="application/json",
        )
    logging.info(
        "Starting synchronous Defender page debug version %s; endpoint %s; page size %s; no publication",
        COLLECTOR_VERSION, endpoint, page_size,
    )
    try:
        settings = Settings.load()
        credential = create_credential(
            settings.auth_mode, settings.client_id, settings.tenant_id,
            settings.client_secret, settings.allow_local_client_secret,
        )
        result = probe_defender_page(settings.defender_api_base_url, credential, page_size, endpoint=endpoint)
    except (requests.RequestException, DefenderApiError, AzureError, RuntimeError, ValueError) as error:
        logging.exception("[debug] FAILED: Synchronous debug request failed")
        return func.HttpResponse(
            json.dumps({
                "Status": "FAILED", "Endpoint": endpoint, "ErrorType": type(error).__name__,
                "Error": str(error), "CollectorVersion": COLLECTOR_VERSION,
            }),
            status_code=504 if isinstance(error, requests.Timeout) else 502,
            mimetype="application/json",
        )
    return func.HttpResponse(
        json.dumps({**result, "CollectorVersion": COLLECTOR_VERSION}),
        status_code=200, mimetype="application/json",
    )


def _manual_options(input: str) -> dict:
    if not input or input == "full":
        return {}
    options = json.loads(input)
    if not isinstance(options, dict):
        raise ValueError("Manual collection input must be a JSON object with pageSize.")
    return options


def _manual_page_size(input: str, default: int = MACHINE_FINDINGS_PAGE_SIZE) -> int:
    options = _manual_options(input)
    return collection_page_size(options.get("pageSize", default))


@app.generic_trigger(arg_name="input", type="manualTrigger", data_type=func.DataType.STRING)
def dataprep_debug_page(input: str) -> None:
    """Probe one Defender page without changing any published data."""
    endpoint = _manual_options(input).get("endpoint", "machine_vulnerabilities")
    if endpoint not in ("machine_vulnerabilities", "vulnerabilities"):
        raise ValueError("Debug endpoint must be machine_vulnerabilities or vulnerabilities.")
    page_size = collection_page_size(_manual_options(input).get("pageSize", COLLECTION_PAGE_SIZE if endpoint == "vulnerabilities" else 1), maximum=COLLECTION_PAGE_SIZE)
    logging.info("Starting Defender page debug version %s; endpoint %s; page size %s; no publication", COLLECTOR_VERSION, endpoint, page_size)
    exit_code = _run_dataprep(page_size=page_size, debug=True, debug_endpoint=endpoint)
    if exit_code:
        raise RuntimeError(f"Defender page debug failed with exit code {exit_code}")
    logging.info("Defender page debug completed; no data published")


@app.generic_trigger(arg_name="input", type="manualTrigger", data_type=func.DataType.STRING)
@app.durable_client_input(client_name="client")
async def dataprep_manual_snapshot(input: str, context: func.Context, client: df.DurableOrchestrationClient) -> None:
    """Run an operator-requested collection using scheduled collection policy."""
    del context
    page_size = _manual_page_size(input)
    await start_collection(client, {
        **_manual_options(input), "collection": "auto", "enrichment": "auto", "pageSize": page_size,
    })


@app.generic_trigger(arg_name="input", type="manualTrigger", data_type=func.DataType.STRING)
@app.durable_client_input(client_name="client")
async def dataprep_full_snapshot(input: str, context: func.Context, client: df.DurableOrchestrationClient) -> None:
    """Run an operator-requested full vulnerability and relationship reconciliation."""
    del context
    page_size = _manual_page_size(input)
    await start_collection(client, {
        **_manual_options(input), "collection": "full", "enrichment": "full", "pageSize": page_size,
    })


@app.orchestration_trigger(context_name="context")
def dataprep_orchestrator(context):
    return (yield from orchestrate(context))


@app.activity_trigger(input_name="request")
def dataprep_prepare(request: dict) -> dict:
    store = RunStore(Settings.load())
    try:
        policy = json.loads((Path(__file__).resolve().parent / "config/sla-policies.json").read_text())
        return prepare_run(request, store, policy)
    finally:
        store.close()


@app.activity_trigger(input_name="reference")
def dataprep_collect_batch(reference: dict) -> dict:
    return execute_worker({**reference, "stage": "collect"})


@app.activity_trigger(input_name="reference")
def dataprep_process(reference: dict) -> dict:
    return execute_worker({**reference, "stage": "process"})


@app.activity_trigger(input_name="reference")
def dataprep_publish(reference: dict) -> dict:
    store = RunStore(Settings.load())
    try:
        return publish_run(reference, store)
    finally:
        store.close()


@app.activity_trigger(input_name="reference")
def dataprep_verify_file(reference: dict) -> dict:
    store = RunStore(Settings.load())
    try:
        return verify_file(reference, store)
    finally:
        store.close()