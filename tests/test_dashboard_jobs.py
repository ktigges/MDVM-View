import time
from threading import Event

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from vulnerability_view.dashboard_jobs import DashboardQueryJobs


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
