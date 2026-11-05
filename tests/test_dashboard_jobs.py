import json
import sqlite3
import time
from threading import Event

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from vulnerability_view.dashboard_jobs import DashboardQueryJobs
from vulnerability_view.dashboard_control import current_query_control
from vulnerability_view.dashboard_startup import startup_rows, startup_stage


def completed(jobs, key, execute):
    for _ in range(200):
        response = jobs.poll(key, "snapshot", execute)
        if response.status_code != 202:
            return response
        time.sleep(0.005)
    pytest.fail("Query preparation did not complete")


def test_polling_reuses_one_query_without_holding_http_request():
    jobs = DashboardQueryJobs()
    release = Event()
    calls = []

    def execute():
        calls.append(True)
        assert release.wait(5)
        return JSONResponse({"total": 2_000_000})

    try:
        start = time.monotonic()
        assert jobs.poll("query", "snapshot", execute).status_code == 202
        assert time.monotonic() - start < 1
        assert jobs.poll("query", "snapshot", execute).status_code == 202
        release.set()
        response = completed(jobs, "query", execute)
        assert response.status_code == 200
        assert response.body == b'{"total":2000000}'
        assert calls == [True]
    finally:
        release.set()
        jobs.close()


def test_query_errors_keep_their_status_and_are_not_success_payloads():
    jobs = DashboardQueryJobs()

    def execute():
        raise HTTPException(status_code=409, detail="Reload the dashboard")

    try:
        response = completed(jobs, "query", execute)
        assert response.status_code == 409
        assert response.body == b'{"detail":"Reload the dashboard"}'
    finally:
        jobs.close()


def test_pending_job_exposes_real_index_progress():
    jobs = DashboardQueryJobs()
    entered, release = Event(), Event()

    def execute():
        with startup_stage("load-rows:finding-events"):
            startup_rows(12000)
            entered.set()
            assert release.wait(5)
        return JSONResponse({"ready": True})

    try:
        jobs.poll("query", "snapshot", execute)
        assert entered.wait(5)
        response = jobs.poll("query", "snapshot", execute)
        progress = json.loads(response.body)["progress"]
        assert progress["stage"] == "load-rows:finding-events"
        assert progress["rows"] == 12000
        assert progress["elapsedSeconds"] >= 0
    finally:
        release.set()
        jobs.close()


def test_slow_report_does_not_block_workspace_queries():
    jobs = DashboardQueryJobs()
    release = Event()

    def report():
        assert release.wait(5)
        return JSONResponse({"report": True})

    try:
        assert jobs.poll("report", "snapshot", report, heavy=True).status_code == 202
        response = completed(jobs, "workspace", lambda: JSONResponse({"ready": True}))
        assert response.status_code == 200
        assert not release.is_set()
    finally:
        release.set()
        jobs.close()


def test_diagnostics_identify_occupied_workers_without_query_content():
    jobs = DashboardQueryJobs()
    entered, release = Event(), Event()

    def execute():
        with startup_stage("query:recommendations:recommendation-details"):
            entered.set()
            assert release.wait(5)
        return JSONResponse({"ready": True})

    try:
        jobs.poll("private-request-key", "snapshot", execute, heavy=True, view="recommendations")
        assert entered.wait(5)
        diagnostics = jobs.diagnostics()
        assert diagnostics["ordinaryWorkers"] == 2
        assert diagnostics["expensiveWorkers"] == 1
        assert diagnostics["pending"][0]["view"] == "recommendations"
        assert diagnostics["pending"][0]["executor"] == "expensive"
        assert diagnostics["pending"][0]["progress"]["stage"] == "query:recommendations:recommendation-details"
        assert "private-request-key" not in json.dumps(diagnostics)
        release.set()
        assert completed(jobs, "private-request-key", execute).status_code == 200
        assert jobs.diagnostics()["pending"] == []
    finally:
        release.set()
        jobs.close()


def test_unexpected_query_error_is_logged_and_returned_as_unavailable(caplog):
    jobs = DashboardQueryJobs()

    def execute():
        raise RuntimeError("source unavailable")

    try:
        response = completed(jobs, "query", execute)
        assert response.status_code == 503
        assert "source unavailable" in caplog.text
    finally:
        jobs.close()


def test_pending_work_and_response_cache_are_bounded():
    jobs = DashboardQueryJobs()
    release = Event()

    def execute():
        assert release.wait(5)
        return JSONResponse({"ready": True})

    try:
        for index in range(16):
            assert jobs.poll(str(index), "snapshot", execute).status_code == 202
        with pytest.raises(HTTPException) as error:
            jobs.poll("overflow", "snapshot", execute)
        assert error.value.status_code == 503
        assert len(jobs._jobs) == 16
    finally:
        release.set()
        jobs.close()


def test_oversized_result_is_rejected_instead_of_retained(caplog):
    jobs = DashboardQueryJobs()

    def execute():
        return JSONResponse({"data": "x" * (2 * 1024**2)})

    try:
        assert completed(jobs, "query", execute).status_code == 503
        assert "result-cache budget" in caplog.text
    finally:
        jobs.close()


def test_equivalent_requests_share_work_and_cancellation_only_releases_its_subscriber():
    jobs = DashboardQueryJobs()
    entered, release = Event(), Event()
    calls = []

    def execute():
        calls.append(True)
        entered.set()
        assert release.wait(5)
        return JSONResponse({"ready": True})

    try:
        jobs.poll("scope", "snapshot", execute, request_id="first", owner="alice", fingerprint="body")
        assert entered.wait(1)
        jobs.poll("scope", "snapshot", execute, request_id="second", owner="bob", fingerprint="body")
        assert jobs.cancel("first", "bob") is False
        assert jobs.cancel("first", "alice") is True
        assert not jobs._jobs["scope"].control.cancelled.is_set()
        release.set()
        assert jobs._jobs["scope"].completed.wait(1)
        response = jobs.response_for("second", "bob", "body")
        assert response is not None and response.status_code == 200
        assert calls == [True]
        with pytest.raises(HTTPException) as error:
            jobs.response_for("second", "bob", "different-body")
        assert error.value.status_code == 422
    finally:
        release.set()
        jobs.close()


def test_cancel_before_admission_prevents_late_creation_of_abandoned_work():
    jobs = DashboardQueryJobs()
    calls = []

    def execute():
        calls.append(True)
        return JSONResponse({"ready": True})

    try:
        assert jobs.cancel("request", "alice") is False
        response = jobs.poll(
            "scope", "snapshot", execute,
            request_id="request", owner="alice",
        )
        assert response.status_code == 499
        assert calls == []
        assert jobs.diagnostics()["pending"] == []
    finally:
        jobs.close()


def test_cancelling_queued_work_prevents_execution():
    jobs = DashboardQueryJobs()
    entered, release = Event(), Event()
    calls = []

    def execute():
        entered.set()
        assert release.wait(5)
        return JSONResponse({"ready": True})

    def queued():
        calls.append(True)
        return JSONResponse({"ready": True})

    try:
        jobs.poll("busy", "snapshot", execute, heavy=True)
        assert entered.wait(1)
        jobs.poll(
            "queued", "snapshot", queued, heavy=True,
            request_id="queued-request", owner="alice",
        )
        assert jobs.cancel("queued-request", "alice")
        assert jobs._jobs["queued"].completed.wait(1)
        assert jobs._jobs["queued"].status == 499
        assert calls == []
    finally:
        release.set()
        jobs.close()


def test_cancellation_interrupts_running_sql_and_releases_worker():
    jobs = DashboardQueryJobs()
    entered = Event()

    def execute():
        control = current_query_control()
        assert control is not None
        with sqlite3.connect(":memory:") as db:
            def progress():
                entered.set()
                return control.sqlite_progress()

            db.set_progress_handler(progress, 100)
            try:
                db.execute("""
                    WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000)
                    SELECT sum(a.x+b.x+c.x) FROM n a,n b,n c
                """).fetchone()
            except sqlite3.OperationalError:
                control.check()
                raise
        return JSONResponse({"ready": True})

    try:
        jobs.poll("scope", "snapshot", execute, request_id="request", owner="alice", heavy=True)
        assert entered.wait(1)
        start = time.monotonic()
        assert jobs.cancel("request", "alice")
        assert jobs._jobs["scope"].completed.wait(1)
        assert jobs._jobs["scope"].status == 499
        assert time.monotonic() - start < 1
    finally:
        jobs.close()


def test_execution_deadline_is_an_explicit_failure():
    jobs = DashboardQueryJobs()
    entered, release = Event(), Event()

    def execute():
        entered.set()
        assert release.wait(5)
        return JSONResponse({"ready": True})

    try:
        jobs.poll("scope", "snapshot", execute)
        assert entered.wait(1)
        jobs._jobs["scope"].control.deadline = time.monotonic() - 1
        release.set()
        assert jobs._jobs["scope"].completed.wait(1)
        assert jobs._jobs["scope"].status == 504
        assert b"execution time limit" in jobs._jobs["scope"].body
    finally:
        release.set()
        jobs.close()


def test_export_and_reports_share_heavy_budget_without_blocking_navigation():
    jobs = DashboardQueryJobs()
    entered = Event()

    def execute():
        entered.set()
        return JSONResponse({"ready": True})

    try:
        with jobs.export_slot():
            jobs.poll("report", "snapshot", execute, heavy=True)
            assert completed(jobs, "navigation", lambda: JSONResponse({"ready": True})).status_code == 200
            assert not entered.is_set()
        assert entered.wait(1)
    finally:
        jobs.close()
