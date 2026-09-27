"""Author: Kevin Tigges
Last modified: 2026-09-27
Purpose: Run scheduled vulnerability data preparation as an Azure Function.
"""

import logging
import os
import shutil
import tempfile
from pathlib import Path

import azure.functions as func

from vulnerability_view.dataprep_cli import main


app = func.FunctionApp()


def _run_dataprep() -> int:
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
            return main(["collect-live"])
        finally:
            os.chdir(previous_directory)


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
def dataprep_snapshot(timer: func.TimerRequest) -> None:
    """Handle the scheduled timer invocation for a data snapshot."""
    del timer
    exit_code = _run_dataprep()
    if exit_code:
        raise RuntimeError(f"Scheduled vulnerability dataprep failed with exit code {exit_code}")
    logging.info("Scheduled vulnerability dataprep completed")