import json
from copy import deepcopy
import gzip
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests
import pytest

from vulnerability_view import live_collector
from vulnerability_view.config import Settings
from vulnerability_view.defender_client import ENDPOINTS, DefenderApiError, DefenderClient, Endpoint, collection_endpoints, collection_page_size, probe_defender_page
from vulnerability_view.live_collector import apply_vulnerability_delta, collect_live, merge_vulnerability_delta, normalize_live, recommendation_requires_api_enrichment, reconcile_live_findings, replay_raw_snapshot


class Credential:
    def get_token(self, scope):
        return type("Token", (), {"token": "not-a-real-token"})()


def test_experimental_endpoints_are_disabled_by_default():
    assert {endpoint.name for endpoint in collection_endpoints()} == {
        "machine_vulnerabilities",
        "machines",
        "vulnerabilities",
        "recommendations",
        "vulnerability_changes",
    }
    assert {endpoint.name for endpoint in collection_endpoints(True)} == {endpoint.name for endpoint in ENDPOINTS}


def response(payload, url="https://example.test/page"):
    value = requests.Response()
    value.status_code = 200
    value.url = url
    value._content = json.dumps(payload).encode()
    value.headers["Content-Type"] = "application/json"
    return value


@pytest.mark.parametrize("timeout_type", [requests.ReadTimeout, requests.ConnectTimeout])
def test_defender_request_retries_timeout_before_success(monkeypatch, timeout_type):
    progress = []
    calls = []
    sleeps = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)
    expected = response({"value": []})

    def get(url, **kwargs):
        calls.append((url, kwargs["timeout"]))
        if len(calls) == 1:
            raise timeout_type("request timed out")
        return expected

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", sleeps.append)
    monkeypatch.setattr("vulnerability_view.defender_client.random.random", lambda: 0.5)

    assert client.request("https://example.test/page") is expected
    assert calls == [("https://example.test/page", (10, 90))] * 2
    assert sleeps == [1.5]
    assert any(f"{timeout_type.__name__}" in message and "attempt 2/5" in message for message in progress)


def test_defender_timeouts_exhaust_shared_attempt_budget(monkeypatch):
    progress = []
    sleeps = []
    client = DefenderClient("https://example.test", Credential(), max_attempts=3, progress_callback=progress.append)
    throttled = response({})
    throttled.status_code = 429
    throttled.headers["Retry-After"] = "2"
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return throttled
        raise requests.ReadTimeout("request timed out")

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", sleeps.append)

    with pytest.raises(requests.ReadTimeout):
        client.request("https://example.test/page")

    assert len(calls) == 3
    assert len(sleeps) == 2
    assert sleeps[0] == 2
    assert any("3 attempts" in message and "ReadTimeout" in message for message in progress)


def test_defender_page_timeout_does_not_duplicate_archived_pages(monkeypatch):
    archived = []
    client = DefenderClient(
        "https://example.test", Credential(),
        lambda name, page, content: archived.append((page, json.loads(content))),
    )
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"})
        if len(calls) == 2:
            raise requests.ReadTimeout("request timed out")
        return response({"value": [{"id": 2}]})

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", lambda delay: None)

    rows, status = client.collect(ENDPOINTS[0])

    assert [row["id"] for row in rows] == [1, 2]
    assert status["PageCount"] == 2
    assert [page for page, _ in archived] == [1, 2]
    assert calls == [
        "https://example.test/api/vulnerabilities/machinesVulnerabilities?%24top=1000",
        "https://example.test/page2",
        "https://example.test/page2",
    ]


@pytest.mark.parametrize("status", [401, 403])
def test_defender_permission_errors_are_not_retried(monkeypatch, status):
    client = DefenderClient("https://example.test", Credential())
    result = response({})
    result.status_code = status
    calls = []

    def get(*args, **kwargs):
        calls.append(args)
        return result

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", lambda delay: pytest.fail("Must not retry permission errors"))

    with pytest.raises(DefenderApiError, match=str(status)):
        client.request("https://example.test/page")
    assert len(calls) == 1


@pytest.mark.parametrize("path", [
    "/api/vulnerabilities/machinesVulnerabilities",
    "/api/machines",
    "/api/vulnerabilities",
    "/api/recommendations",
])
@pytest.mark.parametrize("retain_rows", [True, False])
def test_bounded_inventory_paging_collects_all_rows_without_next_links(monkeypatch, path, retain_rows):
    archived = []
    queries = []
    progress = []
    client = DefenderClient(
        "https://example.test", Credential(),
        lambda name, page, content: archived.append((page, json.loads(content))),
        progress_callback=progress.append,
    )

    def request(url):
        query = parse_qs(urlsplit(url).query)
        queries.append(query)
        assert query["$top"] == ["1000"]
        offset = int(query.get("$skip", ["0"])[0])
        return response({"value": [{"id": index} for index in range(offset, min(offset + 1000, 2057))]})

    monkeypatch.setattr(client, "request", request)
    endpoint = Endpoint("inventory", path, "permission", True, "documentation")

    rows, status = client.collect(endpoint, retain_rows=retain_rows)

    assert [query.get("$skip", ["0"]) for query in queries] == [["0"], ["1000"], ["2000"]]
    assert status["RowCount"] == 2057
    assert status["PageCount"] == 3
    assert [page for page, _ in archived] == [1, 2, 3]
    assert [row["id"] for _, payload in archived for row in payload["value"]] == list(range(2057))
    assert [row["id"] for row in rows] == (list(range(2057)) if retain_rows else [])
    assert any("page size" in message and "1,000" in message for message in progress)


@pytest.mark.parametrize("count, expected_pages", [(0, 1), (999, 1), (1000, 2), (2000, 3)])
def test_bounded_paging_checks_empty_terminal_page_at_exact_boundary(monkeypatch, count, expected_pages):
    client = DefenderClient("https://example.test", Credential())

    def request(url):
        query = parse_qs(urlsplit(url).query)
        offset = int(query.get("$skip", ["0"])[0])
        return response({"value": [{"id": index} for index in range(offset, min(offset + 1000, count))]})

    monkeypatch.setattr(client, "request", request)

    rows, status = client.collect(ENDPOINTS[0])

    assert [row["id"] for row in rows] == list(range(count))
    assert status["PageCount"] == expected_pages


def test_bounded_paging_preserves_filters_offsets_and_smaller_pages(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    original = {"$filter": "severity eq 'High'", "$skip": "5", "$top": "2"}
    queries = []

    def request(url):
        query = parse_qs(urlsplit(url).query)
        queries.append(query)
        offset = int(query["$skip"][0])
        assert query["$filter"] == [original["$filter"]]
        assert query["$top"] == ["2"]
        return response({"value": [{"id": index} for index in range(offset, min(offset + 2, 10))]})

    monkeypatch.setattr(client, "request", request)

    rows, _ = client.collect(ENDPOINTS[2], original)

    assert [row["id"] for row in rows] == [5, 6, 7, 8, 9]
    assert [query["$skip"] for query in queries] == [["5"], ["7"], ["9"]]
    assert original == {"$filter": "severity eq 'High'", "$skip": "5", "$top": "2"}


def test_filtered_dynamic_catalog_requests_also_bound_page_size(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    urls = []
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or response({"value": []}))
    endpoint = Endpoint("vulnerability_delta_details--1", "/api/vulnerabilities", "permission", True, "documentation")

    client.collect(endpoint, {"$filter": "id eq 'CVE-1'", "$top": "99999"})

    assert parse_qs(urlsplit(urls[0]).query) == {"$filter": ["id eq 'CVE-1'"], "$top": ["1000"]}


def test_delta_uses_page_size_and_follows_opaque_continuation(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    urls = []
    next_link = "https://example.test/api/machines/SoftwareVulnerabilityChangesByMachine?pageSize=1000&$skiptoken=opaque"
    pages = iter([
        response({"value": [{"id": 1}], "@odata.nextLink": next_link}),
        response({"value": [{"id": 2}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or next(pages))

    rows, status = client.collect(ENDPOINTS[5], {"sinceTime": "2026-10-19T00:00:00Z"})

    assert parse_qs(urlsplit(urls[0]).query) == {
        "sinceTime": ["2026-10-19T00:00:00Z"], "pageSize": ["1000"],
    }
    assert urls[1] == next_link
    assert [row["id"] for row in rows] == [1, 2]
    assert status["PageCount"] == 2


def test_server_continuation_takes_priority_over_offset_fallback(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    urls = []
    next_link = "https://example.test/api/machines?$top=1000&$skiptoken=opaque"
    pages = iter([
        response({"value": [{"id": index} for index in range(1000)], "@odata.nextLink": next_link}),
        response({"value": [{"id": 1000}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or next(pages))

    rows, _ = client.collect(ENDPOINTS[1])

    assert urls[1] == next_link
    assert len(rows) == 1001


@pytest.mark.parametrize("payload", [{}, {"value": None}, {"value": {}}, {"value": [None]}, {"value": [], "@odata.nextLink": 123}])
def test_paging_rejects_malformed_pages_instead_of_claiming_completion(monkeypatch, payload):
    client = DefenderClient("https://example.test", Credential())
    monkeypatch.setattr(client, "request", lambda url: response(payload))

    with pytest.raises(DefenderApiError):
        client.collect(ENDPOINTS[0])


def test_paging_rejects_a_repeated_continuation_link(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    monkeypatch.setattr(client, "request", lambda url: response({"value": [{"id": 1}], "@odata.nextLink": url}))

    with pytest.raises(DefenderApiError, match="repeated"):
        client.collect(ENDPOINTS[0])


def test_paging_rejects_a_server_ignoring_skip(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    monkeypatch.setattr(client, "request", lambda url: response({"value": [{"id": index} for index in range(1000)]}))

    with pytest.raises(DefenderApiError, match="repeated"):
        client.collect(ENDPOINTS[0])


@pytest.mark.parametrize("query", [{"$top": "0"}, {"$top": "-1"}, {"$top": "abc"}, {"$skip": "-1"}, {"$skip": "abc"}])
def test_paging_rejects_invalid_bounds_before_requesting(monkeypatch, query):
    client = DefenderClient("https://example.test", Credential())
    monkeypatch.setattr(client, "request", lambda url: pytest.fail("Invalid paging must fail before a request"))

    with pytest.raises(ValueError):
        client.collect(ENDPOINTS[0], query)


def test_delta_rejects_top_that_would_disable_continuation(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    monkeypatch.setattr(client, "request", lambda url: pytest.fail("Do not truncate delta history"))

    with pytest.raises(ValueError, match=r"\$top"):
        client.collect(ENDPOINTS[5], {"sinceTime": "2026-10-19T00:00:00Z", "$top": "1000"})


def test_relationships_do_not_send_undocumented_paging_parameters(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    urls = []
    endpoint = Endpoint("recommendation_machines--id", "/api/recommendations/id/machineReferences", "permission", False, "documentation")
    pages = iter([
        response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/next"}),
        response({"value": [{"id": 2}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or next(pages))

    rows, _ = client.collect(endpoint)

    assert urls == ["https://example.test/api/recommendations/id/machineReferences", "https://example.test/next"]
    assert [row["id"] for row in rows] == [1, 2]


def test_later_page_failure_never_reports_a_completed_partial_inventory(monkeypatch):
    archived = []
    progress = []
    client = DefenderClient(
        "https://example.test", Credential(),
        lambda name, page, content: archived.append((page, json.loads(content))),
        progress_callback=progress.append,
    )

    def request(url):
        if "$skip" in parse_qs(urlsplit(url).query):
            raise requests.ReadTimeout("later page timed out")
        return response({"value": [{"id": index} for index in range(1000)]})

    monkeypatch.setattr(client, "request", request)

    with pytest.raises(requests.ReadTimeout):
        client.collect(ENDPOINTS[0], retain_rows=False)

    assert [page for page, _ in archived] == [1]
    assert not any("complete:" in message for message in progress)


def test_delta_caps_explicit_page_size_without_mutating_query(monkeypatch):
    client = DefenderClient("https://example.test", Credential())
    urls = []
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or response({"value": []}))
    query = {"sinceTime": "2026-10-19T00:00:00Z", "pageSize": "50000"}

    client.collect(ENDPOINTS[5], query)

    assert parse_qs(urlsplit(urls[0]).query)["pageSize"] == ["1000"]
    assert query["pageSize"] == "50000"


@pytest.mark.parametrize("value", [0, -1, 1001, True, None, 1.5, "1.5", "abc", ""])
def test_run_page_size_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="1 to 1000"):
        collection_page_size(value)


@pytest.mark.parametrize("page_size", [1, 100, 1000])
def test_custom_client_page_size_bounds_all_inventory_and_delta_requests(monkeypatch, page_size):
    client = DefenderClient("https://example.test", Credential(), page_size=page_size)
    urls = []
    monkeypatch.setattr(client, "request", lambda url: urls.append(url) or response({"value": []}))

    for endpoint in collection_endpoints():
        client.collect(endpoint)

    for url in urls:
        query = parse_qs(urlsplit(url).query)
        key = "pageSize" if "SoftwareVulnerabilityChangesByMachine" in url else "$top"
        assert query[key] == [str(page_size)]


def test_debug_probe_requests_once_and_ignores_continuation(monkeypatch):
    calls = []
    progress = []
    result = response({"value": [{"id": "one"}], "@odata.nextLink": "https://example.test/never-follow"})
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: calls.append(url) or result)

    report = probe_defender_page("https://example.test", Credential(), 1, progress.append)

    assert calls == ["https://example.test/api/vulnerabilities/machinesVulnerabilities?%24top=1"]
    assert report["RequestedRows"] == report["RowCount"] == 1
    assert report["HttpStatus"] == 200
    assert "no data published" in progress[-1]
    assert "one" not in report.values()


@pytest.mark.parametrize("failure", ["timeout", 400, 401, 429, 503, 403])
def test_debug_probe_never_retries_failures(monkeypatch, failure, caplog):
    calls = []
    progress = []

    def get(self, url, **kwargs):
        calls.append(url)
        if failure == "timeout":
            raise requests.ReadTimeout("timed out")
        result = response({})
        result.status_code = failure
        return result

    monkeypatch.setattr(requests.Session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", lambda delay: pytest.fail("Debug must never retry"))

    with pytest.raises((requests.RequestException, DefenderApiError)):
        probe_defender_page("https://example.test", Credential(), 1, progress.append)

    assert len(calls) == 1
    assert "[debug] FAILED: API test did not succeed" in progress[-1]
    assert "[debug] FAILED:" in caplog.text
    assert "[debug] PASSED:" not in caplog.text
    assert "not-a-real-token" not in caplog.text


@pytest.mark.parametrize("endpoint", ["machine_vulnerabilities", "vulnerabilities"])
@pytest.mark.parametrize("rows", [[], [{"id": "finding"}]])
def test_debug_pass_is_explicit_and_logged_only_after_http_and_body_validation(monkeypatch, caplog, endpoint, rows):
    caplog.set_level("INFO")
    progress = []
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: response({"value": rows}))

    report = probe_defender_page("https://example.test", Credential(), 1, progress.append, endpoint=endpoint)

    assert report["Status"] == "PASSED"
    assert report["HttpStatus"] == 200
    assert report["RowCount"] == len(rows)
    assert report["RequestUrl"] in progress[-1]
    assert "[debug] PASSED: API call returned HTTP 200" in progress[-1]
    assert f"{len(rows)} rows received (requested up to 1)" in progress[-1]
    assert f"endpoint={endpoint}" in progress[-1]
    assert "valid JSON response" in progress[-1]
    assert ("EMPTY RESULT" in progress[-1]) == (not rows)
    assert progress[-1] in caplog.text
    assert "not-a-real-token" not in caplog.text
    assert "[debug] FAILED:" not in caplog.text


@pytest.mark.parametrize("payload", [{}, {"value": "invalid"}, {"value": [1]}, {"value": [{}, {}]}, []])
def test_debug_invalid_body_reports_failed_and_never_passes(monkeypatch, caplog, payload):
    caplog.set_level("INFO")
    progress = []
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: response(payload))

    with pytest.raises(DefenderApiError, match="invalid"):
        probe_defender_page("https://example.test", Credential(), 1, progress.append)

    assert "[debug] FAILED:" in progress[-1]
    assert "[debug] FAILED:" in caplog.text
    assert "[debug] PASSED:" not in caplog.text


def test_debug_invalid_json_reports_failed_and_propagates_exception(monkeypatch, caplog):
    result = response({})
    result._content = b"not JSON"
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: result)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        probe_defender_page("https://example.test", Credential(), 1)

    assert "[debug] FAILED:" in caplog.text
    assert "[debug] PASSED:" not in caplog.text


def test_debug_accepted_response_is_not_reported_as_a_completed_api_test(monkeypatch, caplog):
    result = response({"value": []})
    result.status_code = 202
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: result)

    with pytest.raises(DefenderApiError, match="unexpected HTTP 202"):
        probe_defender_page("https://example.test", Credential(), 1)

    assert "[debug] FAILED:" in caplog.text
    assert "[debug] PASSED:" not in caplog.text


def test_debug_authentication_failure_is_explicit_without_an_http_request(monkeypatch, caplog):
    from azure.core.exceptions import ClientAuthenticationError

    class FailedCredential:
        def get_token(self, scope):
            raise ClientAuthenticationError("Managed identity token unavailable")

    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: pytest.fail("No request without authentication"))

    with pytest.raises(ClientAuthenticationError):
        probe_defender_page("https://example.test", FailedCredential(), 1)

    assert "[debug] FAILED:" in caplog.text
    assert "ClientAuthenticationError" in caplog.text
    assert "[debug] PASSED:" not in caplog.text


@pytest.mark.parametrize("endpoint,path", [
    ("machine_vulnerabilities", "/api/vulnerabilities/machinesVulnerabilities"),
    ("vulnerabilities", "/api/vulnerabilities"),
])
@pytest.mark.parametrize("count", [1, 10, 100, 1000])
@pytest.mark.parametrize("trailing_slash", ["", "/"])
def test_debug_calls_requested_regional_host_and_selected_dataset(monkeypatch, endpoint, path, count, trailing_slash):
    calls = []
    progress = []
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: calls.append(url) or response({"value": []}))

    report = probe_defender_page(
        Settings().defender_api_base_url + trailing_slash, Credential(), count,
        progress.append, endpoint=endpoint,
    )

    assert calls == [f"https://api-us3.securitycenter.microsoft.com{path}?%24top={count}"]
    assert requests.Request("GET", calls[0]).prepare().url == calls[0]
    assert report["Endpoint"] == endpoint
    assert calls[0] in progress[0]


@pytest.mark.parametrize("endpoint_name,path", [
    ("machine_vulnerabilities", "/api/vulnerabilities/machinesVulnerabilities"),
    ("vulnerabilities", "/api/vulnerabilities"),
])
@pytest.mark.parametrize("count", [1, 100, 1000])
def test_complete_collection_uses_exact_regional_dataset_uri(monkeypatch, endpoint_name, path, count):
    calls = []
    client = DefenderClient(Settings().defender_api_base_url, Credential(), page_size=count)
    monkeypatch.setattr(client.session, "get", lambda url, **kwargs: calls.append(url) or response({"value": []}))
    endpoint = next(item for item in ENDPOINTS if item.name == endpoint_name)

    _, report = client.collect(endpoint)

    assert calls == [f"https://api-us3.securitycenter.microsoft.com{path}?%24top={count}"]
    assert requests.Request("GET", calls[0]).prepare().url == calls[0]
    assert report["Status"] == "Success"


@pytest.fixture
def device_scoped_run(monkeypatch, tmp_path):
    policy_source = Path(live_collector.__file__).resolve().parents[2] / "config/sla-policies.json"
    policy_target = tmp_path / "config/sla-policies.json"
    policy_target.parent.mkdir()
    policy_target.write_bytes(policy_source.read_bytes())
    monkeypatch.chdir(tmp_path)
    machines = [
        {"id": "device-1", "computerDnsName": "standalone", "osPlatform": "Windows11"},
        {"id": "device-2", "computerDnsName": "scale-set-instance", "vmMetadata": {"resourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/pool/virtualMachines/1"}},
        {"id": "device-3", "computerDnsName": "no-findings"},
    ]
    findings = {
        machine["id"]: [
            {"id": f"{machine['id']}-finding-{index}", "machineId": machine["id"], "cveId": "CVE-2026-0001", "productName": "Product", "severity": "High"}
            for index in range(count)
        ]
        for machine, count in zip(machines, [3, 2, 0])
    }
    payloads = {
        "machines": machines,
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High", "cvssV3": 8.2}],
        "recommendations": [{"id": "va-_-Product", "productName": "Product", "exposedMachinesCount": 2}],
    }
    calls = []
    failures = {}

    def get(self, url, **kwargs):
        calls.append(url)
        parsed = urlsplit(url)
        assert parsed.netloc == "api-us3.securitycenter.microsoft.com"
        query = parse_qs(parsed.query)
        limit = int(query.get("$top", query.get("pageSize", ["2"]))[0])
        offset = int(query.get("$skip", ["0"])[0])
        if parsed.path == "/api/vulnerabilities/machinesVulnerabilities":
            assert "$filter" in query, "Full collection must never use the tenant-wide findings query"
            machine_id = next(key for key in findings if query["$filter"] == [f"machineId eq '{key}'"])
            if machine_id in failures:
                raise failures[machine_id]
            rows = findings[machine_id]
        else:
            name = next(item.name for item in ENDPOINTS if item.path == parsed.path)
            rows = payloads[name]
        return response({"value": rows[offset:offset + limit]}, url)

    monkeypatch.setattr(requests.Session, "get", get)
    monkeypatch.setattr(live_collector, "collect_secure_scores", lambda *args: ([], {"Endpoint": "secure_scores", "Status": "Success", "DurationSeconds": 0}))
    monkeypatch.setattr(live_collector, "collect_azure_subscriptions", lambda *args: ([], {"Endpoint": "azure_subscriptions", "Status": "Success", "DurationSeconds": 0}))
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", lambda delay: None)
    return payloads, findings, calls, failures


def test_full_collection_pages_every_device_and_preserves_normalization_and_replay(device_scoped_run, tmp_path):
    payloads, findings, calls, _ = device_scoped_run
    progress = []

    actual, statuses = collect_live(Settings().defender_api_base_url, Credential(), progress.append, page_size=2)

    expected_payloads = deepcopy(payloads)
    expected_payloads["machine_vulnerabilities"] = [row for rows in findings.values() for row in rows]
    expected_payloads["recommendation_machines"] = [
        {**machine, "_recommendationId": "va-_-Product", "_relationshipSource": "machine_vulnerabilities"}
        for machine in payloads["machines"][:2]
    ]
    run_folder = next((tmp_path / "output/raw").iterdir())
    snapshot = datetime.strptime(run_folder.name, "live-%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    expected = normalize_live(expected_payloads, snapshot, run_folder.name)
    assert actual == expected
    assert len(actual["findings"]) == 5
    assert {row["DeviceName"] for row in actual["findings"]} == {"standalone", "scale-set-instance"}
    paths = [urlsplit(url).path for url in calls]
    assert paths[:4] == ["/api/machines", "/api/machines", "/api/vulnerabilities", "/api/recommendations"]
    finding_calls = [url for url in calls if urlsplit(url).path.endswith("/machinesVulnerabilities")]
    assert len(finding_calls) == 5
    pages = sorted(run_folder.glob("machine_vulnerabilities-page-*.json.gz"))
    assert [page.name for page in pages] == [f"machine_vulnerabilities-page-{page:04d}.json.gz" for page in range(1, 6)]
    retained = []
    for page in pages:
        with gzip.open(page, "rt", encoding="utf-8") as handle:
            retained.extend(json.load(handle)["value"])
    assert retained == expected_payloads["machine_vulnerabilities"]
    status = next(row for row in statuses if row["Endpoint"] == "machine_vulnerabilities")
    assert status["RowCount"] == 5
    assert status["PageCount"] == 5
    assert status["MachineCount"] == 3
    assert status["CollectionMethod"] == "PerMachine"
    assert any('machine 2/3: "scale-set-instance" (machineId=device-2)' in message for message in progress)
    assert any("machines complete: 3/3; 5 total rows" in message for message in progress)
    replayed, _ = replay_raw_snapshot(run_folder)
    for dataset in ("findings", "devices", "vulnerabilities", "recommendations"):
        assert replayed[dataset] == actual[dataset]


def test_device_query_failure_prevents_normalization_and_publication(device_scoped_run, monkeypatch):
    from vulnerability_view import dataprep_cli

    _, _, calls, failures = device_scoped_run
    failures["device-2"] = requests.ReadTimeout("Device-scoped request timed out")
    monkeypatch.setattr(dataprep_cli.Settings, "load", lambda *args: Settings(auth_mode="managed_identity"))
    monkeypatch.setattr(dataprep_cli, "_create_credential", lambda settings: Credential())
    monkeypatch.setattr(dataprep_cli, "_read_existing", lambda *args: {})
    monkeypatch.setattr(dataprep_cli, "_resolve_collection_mode", lambda *args: ("full", None))
    monkeypatch.setattr(live_collector, "normalize_live", lambda *args, **kwargs: pytest.fail("Incomplete collection must not normalize"))
    monkeypatch.setattr(dataprep_cli, "_persist_live_run", lambda *args, **kwargs: pytest.fail("Incomplete collection must not publish"))

    with pytest.raises(requests.ReadTimeout, match="Device-scoped request timed out"):
        dataprep_cli.main(["collect-live", "--page-size", "2"])

    queries = [parse_qs(urlsplit(url).query) for url in calls if urlsplit(url).path.endswith("/machinesVulnerabilities")]
    assert sum(query["$filter"] == ["machineId eq 'device-2'"] for query in queries) == 5
    assert all(query["$filter"] != ["machineId eq 'device-3'"] for query in queries)


def test_delta_collection_keeps_existing_delta_api_and_does_not_query_per_device(device_scoped_run, monkeypatch):
    payloads, _, calls, _ = device_scoped_run
    payloads["vulnerability_changes"] = []
    previous = [{"FindingKey": "baseline", "DeviceId": "device-1", "CveId": "CVE-2026-0001", "SoftwareName": "Product", "SoftwareVersion": "1", "FindingStatus": "Open", "DataOrigin": "Live"}]
    monkeypatch.setattr(DefenderClient, "collect_machine_vulnerabilities", lambda *args: pytest.fail("Delta runs must not recollect findings by machine"))

    actual, statuses = collect_live(
        Settings().defender_api_base_url, Credential(),
        vulnerability_collection_mode="delta",
        previous_findings=previous, previous_snapshot=datetime(2026, 10, 18, tzinfo=timezone.utc),
        page_size=2,
    )

    assert [row["FindingKey"] for row in actual["findings"]] == ["baseline"]
    assert all(not urlsplit(url).path.endswith("/machinesVulnerabilities") for url in calls)
    delta_url = next(url for url in calls if "/SoftwareVulnerabilityChangesByMachine?" in url)
    query = parse_qs(urlsplit(delta_url).query)
    assert query["pageSize"] == ["2"]
    assert "$top" not in query
    assert query["sinceTime"] == ["2026-10-18T00:00:00Z"]
    assert all(row["VulnerabilityCollectionMode"] == "delta" for row in statuses)


def test_device_scoped_collection_follows_next_links_and_retries_without_archive_collisions(monkeypatch):
    archived = []
    calls = []
    next_link = "https://api-us3.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?cursor=opaque"
    client = DefenderClient(
        Settings().defender_api_base_url, Credential(),
        lambda name, page, content: archived.append((name, page, json.loads(content))),
        page_size=2,
    )

    def get(url, **kwargs):
        calls.append(url)
        if url == next_link:
            if calls.count(next_link) == 1:
                raise requests.ReadTimeout("Retry this page only")
            return response({"value": [{"id": "third", "machineId": "device-1"}]})
        query = parse_qs(urlsplit(url).query)
        if query["$filter"] == ["machineId eq 'device-1'"]:
            return response({"value": [{"id": "first", "machineId": "device-1"}, {"id": "second", "machineId": "device-1"}], "@odata.nextLink": next_link})
        assert query["$filter"] == ["machineId eq 'device-2'"]
        return response({"value": []})

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", lambda delay: None)

    rows, status = client.collect_machine_vulnerabilities([{"id": "device-1"}, {"id": "device-2"}])

    assert rows == []
    assert status["RowCount"] == 3
    assert status["PageCount"] == 3
    assert calls[1:3] == [next_link, next_link]
    assert [(name, page) for name, page, _ in archived] == [("machine_vulnerabilities", 1), ("machine_vulnerabilities", 2), ("machine_vulnerabilities", 3)]
    assert [row["id"] for _, _, payload in archived for row in payload["value"]] == ["first", "second", "third"]


@pytest.mark.parametrize("invalid_id", [None, "", 123, True, " device-1", "device-1 "])
def test_device_scoped_collection_rejects_invalid_inventory_ids_before_any_query(monkeypatch, invalid_id):
    client = DefenderClient(Settings().defender_api_base_url, Credential(), lambda *args: None)
    monkeypatch.setattr(client.session, "get", lambda *args, **kwargs: pytest.fail("Invalid inventory must not be queried"))

    with pytest.raises(DefenderApiError, match="invalid Defender machine ID"):
        client.collect_machine_vulnerabilities([{"id": "valid"}, {"id": invalid_id}])


def test_device_scoped_collection_deduplicates_ids_and_escapes_filters(monkeypatch):
    calls = []
    archived = []
    progress = []
    client = DefenderClient(
        Settings().defender_api_base_url, Credential(),
        lambda name, page, content: archived.append((name, page)),
        progress_callback=progress.append,
    )
    monkeypatch.setattr(client.session, "get", lambda url, **kwargs: calls.append(url) or response({"value": []}))

    _, status = client.collect_machine_vulnerabilities([{"id": "device'1"}, {"id": "device'1"}])

    assert len(calls) == 1
    assert parse_qs(urlsplit(calls[0]).query)["$filter"] == ["machineId eq 'device''1'"]
    assert status["MachineCount"] == 1
    assert archived == [("machine_vulnerabilities", 1)]
    assert any("deduplicated 1 repeated inventory machine IDs" in message for message in progress)


def test_device_scoped_collection_rejects_findings_for_another_device(monkeypatch):
    client = DefenderClient(Settings().defender_api_base_url, Credential(), lambda *args: None)
    monkeypatch.setattr(client.session, "get", lambda *args, **kwargs: response({"value": [{"machineId": "different-device"}]}))

    with pytest.raises(DefenderApiError, match="different machine"):
        client.collect_machine_vulnerabilities([{"id": "requested-device"}])


def test_device_scoped_collection_requires_archiving_to_avoid_discarding_findings(monkeypatch):
    client = DefenderClient(Settings().defender_api_base_url, Credential())
    monkeypatch.setattr(client.session, "get", lambda *args, **kwargs: pytest.fail("No query without an archive"))

    with pytest.raises(ValueError, match="requires a raw-page archive callback"):
        client.collect_machine_vulnerabilities([{"id": "device-1"}])


def test_empty_inventory_produces_a_replayable_empty_snapshot(device_scoped_run, tmp_path):
    payloads, _, calls, _ = device_scoped_run
    payloads["machines"].clear()
    payloads["recommendations"].clear()

    actual, statuses = collect_live(Settings().defender_api_base_url, Credential(), page_size=2)

    assert actual["findings"] == []
    assert all(not urlsplit(url).path.endswith("/machinesVulnerabilities") for url in calls)
    run_folder = next((tmp_path / "output/raw").iterdir())
    assert (run_folder / "derived_machine_vulnerabilities-page-0001.json.gz").is_file()
    replayed, _ = replay_raw_snapshot(run_folder)
    assert replayed == actual
    status = next(row for row in statuses if row["Endpoint"] == "machine_vulnerabilities")
    assert status["RowCount"] == 0
    assert status["PageCount"] == 0
    assert status["MachineCount"] == 0


def test_retained_machine_pages_are_read_in_numeric_collection_order(tmp_path):
    from vulnerability_view.live_collector import _iter_archived_endpoint_rows

    for number in [9999, 10000, 10001]:
        with gzip.open(tmp_path / f"machine_vulnerabilities-page-{number:04d}.json.gz", "wt") as handle:
            json.dump({"value": [{"id": number}]}, handle)

    assert [row["id"] for row in _iter_archived_endpoint_rows(tmp_path, "machine_vulnerabilities")] == [9999, 10000, 10001]


def test_debug_cli_does_not_collect_or_access_storage(monkeypatch, capsys):
    from vulnerability_view import dataprep_cli
    from vulnerability_view.config import Settings

    monkeypatch.setattr(dataprep_cli.Settings, "load", lambda *args: Settings(auth_mode="managed_identity", defender_api_base_url="https://example.test"))
    monkeypatch.setattr(dataprep_cli, "_create_credential", lambda settings: Credential())
    for name in ("_read_existing", "_read_outputs", "collect_live", "upload_run_bundle", "write_outputs"):
        monkeypatch.setattr(dataprep_cli, name, lambda *args, **kwargs: pytest.fail("Debug must not collect or touch storage"))
    calls = []
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: calls.append(url) or response({"value": [{"id": 1}]}))

    assert dataprep_cli.main(["probe-live", "--page-size", "1"]) == 0

    assert len(calls) == 1
    assert '"RowCount": 1' in capsys.readouterr().out


def test_catalog_debug_cli_uses_catalog_route_and_default_limit(monkeypatch):
    from vulnerability_view import dataprep_cli
    from vulnerability_view.config import Settings

    monkeypatch.setattr(dataprep_cli.Settings, "load", lambda *args: Settings(auth_mode="managed_identity"))
    monkeypatch.setattr(dataprep_cli, "_create_credential", lambda settings: Credential())
    calls = []
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: calls.append(url) or response({"value": []}))

    assert dataprep_cli.main(["probe-live", "--endpoint", "vulnerabilities"]) == 0
    assert calls == ["https://api-us3.securitycenter.microsoft.com/api/vulnerabilities?%24top=1000"]


def test_collect_cli_forwards_page_size(monkeypatch):
    from vulnerability_view import dataprep_cli
    from vulnerability_view.config import Settings

    monkeypatch.setattr(dataprep_cli.Settings, "load", lambda *args: Settings(auth_mode="managed_identity", tenant_id="tenant", defender_api_base_url="https://example.test"))
    monkeypatch.setattr(dataprep_cli, "_create_credential", lambda settings: Credential())
    monkeypatch.setattr(dataprep_cli, "_read_existing", lambda *args: {})
    monkeypatch.setattr(dataprep_cli, "_resolve_collection_mode", lambda *args: ("full", None))

    def collect(*args, **kwargs):
        assert kwargs["page_size"] == 100
        raise RuntimeError("Verified page-size forwarding")

    monkeypatch.setattr(dataprep_cli, "collect_live", collect)

    with pytest.raises(RuntimeError, match="Verified page-size forwarding"):
        dataprep_cli.main(["collect-live", "--page-size", "100"])


def test_vulnerability_delta_reconstructs_current_detected_snapshot():
    previous = [
        {"FindingKey": "old", "DeviceId": "d1", "CveId": "CVE-1", "SoftwareName": "App", "SoftwareVersion": "1", "FindingStatus": "Open", "DataOrigin": "Live"},
        {"FindingKey": "pending", "DeviceId": "d2", "CveId": "CVE-2", "SoftwareName": "App", "SoftwareVersion": "1", "FindingStatus": "PendingConfirmation", "DataOrigin": "Live"},
    ]
    changes = [
        {"id": "old", "deviceId": "d1", "cveId": "CVE-1", "softwareName": "App", "softwareVersion": "1", "status": "Fixed", "eventTimestamp": "2026-10-12T00:00:00Z"},
        {"id": "new", "deviceId": "d3", "cveId": "CVE-3", "softwareName": "Browser", "softwareVersion": "2", "status": "New", "eventTimestamp": "2026-10-12T00:00:00Z"},
    ]

    reconstructed = apply_vulnerability_delta(previous, changes)

    assert [row["id"] for row in reconstructed] == ["new"]


def test_vulnerability_delta_keeps_new_side_of_same_timestamp_rbac_move():
    previous = [{"FindingKey": "same", "DeviceId": "d1", "CveId": "CVE-1", "SoftwareName": "App", "SoftwareVersion": "1", "FindingStatus": "Open", "DataOrigin": "Live"}]
    changes = [
        {"id": "same", "deviceId": "d1", "cveId": "CVE-1", "softwareName": "App", "softwareVersion": "1", "status": "Fixed", "eventTimestamp": "2026-10-12T00:00:00Z"},
        {"id": "same", "deviceId": "d1", "cveId": "CVE-1", "softwareName": "App", "softwareVersion": "1", "status": "New", "eventTimestamp": "2026-10-12T00:00:00Z"},
    ]

    assert [row["id"] for row in apply_vulnerability_delta(previous, changes)] == ["same"]


def test_vulnerability_catalog_delta_merges_curated_baseline_and_changed_rows():
    previous = [{"CveId": "CVE-1", "Description": "old", "Severity": "High"}]
    changed = [{"id": "CVE-1", "description": "new", "severity": "Critical"}, {"id": "CVE-2", "description": "added"}]

    merged = {row["id"]: row for row in merge_vulnerability_delta(previous, changed)}

    assert merged["CVE-1"]["description"] == "new"
    assert merged["CVE-2"]["description"] == "added"


def test_pagination_archives_before_normalization(monkeypatch):
    archived = []
    progress = []
    client = DefenderClient(
        "https://example.test",
        Credential(),
        lambda name, page, content: archived.append((name, page, json.loads(content))),
        progress_callback=progress.append,
    )
    pages = iter([response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}), response({"value": [{"id": 2}]})])
    monkeypatch.setattr(client, "request", lambda url: next(pages))
    rows, status = client.collect(ENDPOINTS[1])
    assert [row["id"] for row in rows] == [1, 2]
    assert status["PageCount"] == 2
    assert [page for _, page, _ in archived] == [1, 2]
    assert any("1 rows downloaded; more data available" in message for message in progress)
    assert any("requesting page 1" in message for message in progress)
    assert any("page 2 received" in message for message in progress)


def test_pagination_reports_percentage_when_defender_supplies_total(monkeypatch):
    progress = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)
    pages = iter([
        response({"@odata.count": 2, "value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}),
        response({"@odata.count": 2, "value": [{"id": 2}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: next(pages))

    client.collect(ENDPOINTS[1])

    assert any("1/2 rows (50.0%)" in message for message in progress)
    assert any("2/2 rows (100.0%)" in message for message in progress)


def test_page_progress_is_emitted_before_request_and_after_each_archived_page(monkeypatch):
    progress = []
    archived = []
    clock = [0.0]
    client = DefenderClient(
        "https://example.test", Credential(),
        lambda name, page, content: archived.append(page),
        progress_callback=progress.append,
    )
    pages = iter([
        response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}),
        response({"value": [{"id": 2}, {"id": 3}]}),
    ])
    requested = []

    def request(url):
        requested.append(url)
        assert f"requesting page {len(requested)}" in progress[-1]
        clock[0] += 2.5
        return next(pages)

    def report(message):
        if "received:" in message:
            assert len(archived) == len(requested)
        progress.append(message)

    client.progress_callback = report
    monkeypatch.setattr(client, "request", request)
    monkeypatch.setattr("vulnerability_view.defender_client.time.monotonic", lambda: clock[0])

    client.collect(ENDPOINTS[0], retain_rows=False)

    assert "[machine_vulnerabilities] requesting page 1; 0 rows downloaded; 0.0s elapsed" in progress
    assert "[machine_vulnerabilities] page 1 received: 1 rows; 1 total rows; 2.5s page elapsed; 2.5s elapsed" in progress
    assert "[machine_vulnerabilities] requesting page 2; 1 rows downloaded; 2.5s elapsed" in progress
    assert "[machine_vulnerabilities] page 2 received: 2 rows; 3 total rows; 2.5s page elapsed; 5.0s elapsed" in progress


def test_page_progress_does_not_claim_failed_request_was_received(monkeypatch):
    progress = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)

    def request(url):
        assert "requesting page 1" in progress[-1]
        raise requests.ReadTimeout("timed out")

    monkeypatch.setattr(client, "request", request)

    with pytest.raises(requests.ReadTimeout):
        client.collect(ENDPOINTS[0])

    assert not any("received:" in message or "complete:" in message for message in progress)


def test_page_progress_respects_suppressed_enrichment_logging(monkeypatch):
    progress = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)
    monkeypatch.setattr(client, "request", lambda url: response({"value": [{"id": 1}]}))

    client.collect(ENDPOINTS[1], report_progress=False)

    assert progress == []


def test_pagination_can_archive_without_retaining_rows(monkeypatch):
    archived = []
    client = DefenderClient(
        "https://example.test",
        Credential(),
        lambda name, page, content: archived.append((name, page, json.loads(content))),
    )
    pages = iter([
        response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}),
        response({"value": [{"id": 2}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: next(pages))

    rows, status = client.collect(ENDPOINTS[1], retain_rows=False)

    assert rows == []
    assert status["RowCount"] == 2
    assert [page for _, page, _ in archived] == [1, 2]


def test_pagination_stops_reporting_invalid_total(monkeypatch):
    progress = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)
    pages = iter([
        response({"@odata.count": 1, "value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}),
        response({"value": [{"id": 2}], "@odata.nextLink": "https://example.test/page3"}),
        response({"value": [{"id": 3}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: next(pages))

    client.collect(ENDPOINTS[1])

    assert any("1/1 rows (100.0%)" in message for message in progress)
    assert any("2 rows downloaded; more data available" in message for message in progress)
    assert not any("2/1 rows" in message for message in progress)


def test_targeted_enrichment_skips_derivable_vulnerability_recommendations():
    vulnerability = {"id": "va-_-vendor-_-product", "exposedMachinesCount": 10}
    configuration = {"id": "sca-_-scid-1", "exposedMachinesCount": 10}

    assert recommendation_requires_api_enrichment(vulnerability, "targeted") is False
    assert recommendation_requires_api_enrichment(configuration, "targeted") is True
    assert recommendation_requires_api_enrichment(vulnerability, "full") is True
    assert recommendation_requires_api_enrichment(configuration, "none") is False


def test_live_normalization_uses_collector_first_observation_for_sla():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "productVendor": "Vendor", "productName": "Product", "productVersion": "1.0", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "live-device", "osPlatform": "Windows11", "version": "24H2", "riskScore": "High", "exposureLevel": "Medium", "lastSeen": "2026-09-16T00:00:00Z", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High", "cvssV3": 8.2, "publicExploit": True, "exploitVerified": False, "exploitInKit": False}],
        "recommendations": [],
    }
    result = normalize_live(payloads, datetime(2026, 9, 16, tzinfo=timezone.utc), "live-run")
    row = result["findings"][0]
    assert row["DataOrigin"] == "Live"
    assert row["FirstSeenUtc"] == ""
    assert row["FirstObservedUtc"] == "2026-09-16T00:00:00Z"
    assert row["SlaStartUtc"] == "2026-09-16T00:00:00Z"
    assert row["SlaPolicyVersion"] == "vulnerability-view-2026-10-12"
    assert row["SlaStatus"] == "OpenWithinSla"
    assert row["AssignedEngineer"] == ""


def test_live_normalization_consumes_large_payloads_without_changing_results():
    payloads = {
        "machine_vulnerabilities": [
            {"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"},
            {"id": "finding-2", "machineId": "device-1", "cveId": "CVE-2026-0002", "severity": "Medium"},
        ],
        "machines": [{"id": "device-1", "computerDnsName": "device-one"}],
        "vulnerabilities": [
            {"id": "CVE-2026-0001", "severity": "High", "cvssV3": 8.0},
            {"id": "CVE-2026-0002", "severity": "Medium", "cvssV3": 6.0},
            {"id": "CVE-2026-UNUSED", "severity": "Low", "cvssV3": 2.0},
        ],
        "recommendations": [],
    }
    expected_payloads = deepcopy(payloads)
    consumed_payloads = deepcopy(payloads)
    snapshot = datetime(2026, 9, 17, tzinfo=timezone.utc)

    expected = normalize_live(expected_payloads, snapshot, "live-run")
    actual = normalize_live(consumed_payloads, snapshot, "live-run", consume_payloads=True)

    assert actual == expected
    assert expected_payloads == payloads
    assert "machine_vulnerabilities" not in consumed_payloads
    assert "vulnerabilities" not in consumed_payloads


def test_live_normalization_streams_archived_large_payloads_without_changing_results(tmp_path):
    payloads = {
        "machine_vulnerabilities": [
            {"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"},
            {"id": "finding-2", "machineId": "device-1", "cveId": "CVE-2026-0002", "severity": "Medium"},
        ],
        "machines": [{"id": "device-1", "computerDnsName": "device-one"}],
        "vulnerabilities": [
            {"id": "CVE-2026-0001", "name": "first", "severity": "High", "cvssV3": 8.0},
            {"id": "CVE-2026-0002", "severity": "Medium", "cvssV3": 6.0},
            {"id": "CVE-2026-0001", "name": "replacement", "severity": "Critical", "cvssV3": 9.5},
            {"id": "CVE-2026-UNUSED", "severity": "Low", "cvssV3": 2.0},
        ],
        "recommendations": [],
    }
    run_folder = tmp_path / "live-run"
    run_folder.mkdir()
    archived_pages = {
        "machine_vulnerabilities": [payloads["machine_vulnerabilities"][:1], payloads["machine_vulnerabilities"][1:]],
        "vulnerabilities": [payloads["vulnerabilities"][:2], payloads["vulnerabilities"][2:]],
    }
    for endpoint, pages in archived_pages.items():
        for page_number, rows in enumerate(pages, start=1):
            with gzip.open(run_folder / f"{endpoint}-page-{page_number:04d}.json.gz", "wt", encoding="utf-8") as handle:
                json.dump({"value": rows}, handle)
    snapshot = datetime(2026, 9, 17, tzinfo=timezone.utc)
    expected = normalize_live(deepcopy(payloads), snapshot, "live-run")
    small_payloads = {key: deepcopy(rows) for key, rows in payloads.items() if key not in archived_pages}

    actual = normalize_live(
        small_payloads,
        snapshot,
        "live-run",
        consume_payloads=True,
        archived_large_payloads=run_folder,
        archived_row_counts={"machine_vulnerabilities": 2, "vulnerabilities": 4},
    )

    assert actual == expected
    assert actual["vulnerabilities"][0]["Name"] == "replacement"


def test_live_normalization_extracts_subscription_and_classifies_direct_resource_metadata():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "azure-vm", "resourceId": "/subscriptions/subscription-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azure-vm", "subscriptionId": "subscription-1"}],
        "vulnerabilities": [], "recommendations": [],
        "azure_subscriptions": [{"subscriptionId": "subscription-1", "displayName": "Production", "state": "Enabled", "tenantId": "tenant-1"}],
    }

    row = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["findings"][0]

    assert row["AssetClass"] == "AzureCloud"
    assert row["SubscriptionId"] == "subscription-1"
    assert row["AzureResourceId"].startswith("/subscriptions/subscription-1/")
    assert normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["subscriptions"] == [{
        "SubscriptionId": "subscription-1",
        "SubscriptionName": "Production",
        "State": "Enabled",
        "TenantId": "tenant-1",
        "DataOrigin": "Live",
        "ScenarioId": "LIVE-AZURE-SUBSCRIPTION-INVENTORY",
        "SnapshotTimeUtc": "2026-09-17T00:00:00Z",
        "CollectionRunId": "live-run",
    }]


def test_live_normalization_extracts_subscription_from_vm_metadata():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "Critical"}],
        "machines": [{"id": "device-1", "computerDnsName": "azure-vm", "vmMetadata": {"cloudProvider": "Azure", "resourceId": "/subscriptions/subscription-2/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azure-vm", "subscriptionId": None}}],
        "vulnerabilities": [], "recommendations": [],
    }

    row = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["findings"][0]

    assert row["AssetClass"] == "AzureCloud"
    assert row["SubscriptionId"] == "subscription-2"
    assert row["AzureResourceId"].startswith("/subscriptions/subscription-2/")


def test_live_reconciliation_requires_two_fresh_absences_to_confirm_fixed():
    snapshot = datetime(2026, 9, 17, 17, 5, 9, tzinfo=timezone.utc)
    previous = normalize_live({
        "machine_vulnerabilities": [
            {"id": "fixed-key", "machineId": "device-1", "cveId": "CVE-2026-0001", "productName": "windows_11", "severity": "High"},
            {"id": "open-key", "machineId": "device-1", "cveId": "CVE-2026-0002", "productName": "openssl", "severity": "Medium"},
        ],
        "machines": [{"id": "device-1", "computerDnsName": "sample-ws11", "machineTags": []}],
        "vulnerabilities": [],
        "recommendations": [],
    }, datetime(2026, 9, 17, 14, 23, 47, tzinfo=timezone.utc), "live-20260917T142347Z")["findings"]
    current = [dict(previous[1], SnapshotTimeUtc="2026-09-17T17:05:09Z", CollectionRunId="live-20260917T170509Z")]

    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-17T16:30:00Z", "HealthStatus": "Active", "OnboardingStatus": "Onboarded"}]
    first_reconciliation = reconcile_live_findings(current, previous, snapshot, "live-20260917T170509Z", devices)
    by_key = {row["FindingKey"]: row for row in first_reconciliation}

    assert by_key["fixed-key"]["FindingStatus"] == "PendingConfirmation"
    assert by_key["fixed-key"]["FirstAbsentUtc"] == "2026-09-17T17:05:09Z"
    assert by_key["fixed-key"]["EffectiveRemediationUtc"] == "2026-09-17T17:05:09Z"
    assert by_key["fixed-key"]["ConsecutiveAbsentCount"] == 1
    assert by_key["fixed-key"]["ConfirmationRunsCompleted"] == 1
    assert by_key["fixed-key"]["ConfirmationRunsRequired"] == 2
    assert by_key["fixed-key"]["SlaEvidenceStatus"] == "PendingConfirmation"
    assert by_key["fixed-key"]["SlaStatus"] == "FixedWithinSla"
    assert by_key["open-key"]["FindingStatus"] == "Open"

    second_snapshot = datetime(2026, 9, 18, 17, 5, 9, tzinfo=timezone.utc)
    devices[0]["LastSeenUtc"] = "2026-09-18T16:30:00Z"
    second_reconciliation = reconcile_live_findings(current, first_reconciliation, second_snapshot, "live-20260918T170509Z", devices)
    fixed = {row["FindingKey"]: row for row in second_reconciliation}["fixed-key"]

    assert fixed["FindingStatus"] == "Fixed"
    assert fixed["FixedUtc"] == "2026-09-17T17:05:09Z"
    assert fixed["EffectiveRemediationUtc"] == "2026-09-17T17:05:09Z"
    assert fixed["FixedConfirmedUtc"] == "2026-09-18T17:05:09Z"
    assert fixed["ConsecutiveAbsentCount"] == 2
    assert fixed["SlaEvidenceStatus"] == "Confirmed"


def test_live_reconciliation_does_not_fix_wholesale_device_disappearance():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    previous = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "Critical", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "FixedConfirmedUtc": "",
        "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-19T00:00:00Z", "CollectionRunId": "previous",
    }]
    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-20T00:00:00Z", "HealthStatus": "Active", "OnboardingStatus": "Onboarded"}]

    first = reconcile_live_findings([], previous, snapshot, "live-20260920T000000Z", devices)
    second = reconcile_live_findings([], first, datetime(2026, 9, 21, tzinfo=timezone.utc), "live-20260921T000000Z", devices)

    assert first[0]["FindingStatus"] == "PendingVerification"
    assert second[0]["FindingStatus"] == "PendingVerification"
    assert second[0]["FixedUtc"] == ""
    assert second[0]["FixedConfirmedUtc"] == ""
    assert second[0]["EffectiveRemediationUtc"] == ""
    assert second[0]["ConsecutiveAbsentCount"] == 2
    assert second[0]["SlaEvidenceStatus"] == "AwaitingCorroboration"
    assert "corroborating evidence is required" in second[0]["LifecycleReason"]


def test_live_reconciliation_repairs_absence_derived_false_fix_after_wholesale_disappearance():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    previous = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Fixed",
        "Severity": "Critical", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "2026-09-18T00:00:00Z", "ReopenedUtc": "", "FirstAbsentUtc": "2026-09-18T00:00:00Z",
        "FixedConfirmedUtc": "2026-09-19T00:00:00Z", "ConsecutiveAbsentCount": 2,
        "LifecycleReason": "Absent from 2 complete snapshots while device remained active and fresh",
        "SnapshotTimeUtc": "2026-09-19T00:00:00Z", "CollectionRunId": "previous",
    }]
    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-20T00:00:00Z", "HealthStatus": "Active", "OnboardingStatus": "Onboarded"}]

    reconciled = reconcile_live_findings([], previous, snapshot, "live-20260920T000000Z", devices)

    assert reconciled[0]["FindingStatus"] == "PendingVerification"
    assert reconciled[0]["FixedUtc"] == ""
    assert reconciled[0]["FixedConfirmedUtc"] == ""
    assert reconciled[0]["SlaStatus"].startswith("Open")


def test_live_reconciliation_does_not_fix_stale_device():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    previous = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "FixedConfirmedUtc": "",
        "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-19T00:00:00Z", "CollectionRunId": "live-20260919T000000Z",
    }]
    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-10T00:00:00Z", "HealthStatus": "Inactive", "OnboardingStatus": "Onboarded"}]

    reconciled = reconcile_live_findings([], previous, snapshot, "live-20260920T000000Z", devices)

    assert reconciled[0]["FindingStatus"] == "StaleDevice"
    assert reconciled[0]["FixedUtc"] == ""
    assert reconciled[0]["ConsecutiveAbsentCount"] == 0


def test_live_reconciliation_reopens_confirmed_finding():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    current = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "FixedConfirmedUtc": "",
        "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-20T00:00:00Z", "CollectionRunId": "live-20260920T000000Z",
    }]
    previous = [dict(current[0], FindingStatus="Fixed", FixedUtc="2026-09-18T00:00:00Z", FixedConfirmedUtc="2026-09-19T00:00:00Z")]

    reconciled = reconcile_live_findings(current, previous, snapshot, "live-20260920T000000Z")

    assert reconciled[0]["FindingStatus"] == "Reopened"
    assert reconciled[0]["ReopenedUtc"] == "2026-09-20T00:00:00Z"
    assert reconciled[0]["ConsecutiveAbsentCount"] == 0


def test_live_reconciliation_uses_first_qualified_absence_for_sla_before_confirmation():
    first_absence = datetime(2026, 9, 20, 23, 0, tzinfo=timezone.utc)
    previous = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "", "FirstObservedUtc": "2026-09-14T00:00:00Z",
        "SlaPolicyName": "High", "SlaPolicyVersion": "policy-v1", "SlaDays": 7,
        "SlaStartUtc": "2026-09-14T00:00:00Z", "SlaDueUtc": "2026-09-21T00:00:00Z",
        "SlaStatus": "OpenWithinSla", "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "",
        "FixedConfirmedUtc": "", "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-20T12:00:00Z",
        "CollectionRunId": "previous",
    }]
    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-20T22:30:00Z", "HealthStatus": "Active", "OnboardingStatus": "Onboarded"}]
    other_finding = dict(previous[0], FindingKey="finding-2", SnapshotTimeUtc="2026-09-20T23:00:00Z")

    pending_rows = reconcile_live_findings([other_finding], previous + [other_finding], first_absence, "first-absence", devices)
    pending = {row["FindingKey"]: row for row in pending_rows}["finding-1"]
    assert pending["FindingStatus"] == "PendingConfirmation"
    assert pending["SlaStatus"] == "FixedWithinSla"
    assert pending["SlaEvidenceStatus"] == "PendingConfirmation"

    confirmation = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    devices[0]["LastSeenUtc"] = "2026-09-21T11:30:00Z"
    confirmed_rows = reconcile_live_findings([other_finding], pending_rows, confirmation, "confirmation", devices)
    confirmed = {row["FindingKey"]: row for row in confirmed_rows}["finding-1"]
    assert confirmed["FindingStatus"] == "Fixed"
    assert confirmed["SlaStatus"] == "FixedWithinSla"
    assert confirmed["EffectiveRemediationUtc"] == "2026-09-20T23:00:00Z"
    assert confirmed["FixedConfirmedUtc"] == "2026-09-21T12:00:00Z"


def test_live_reconciliation_marks_detection_returned_and_revokes_provisional_sla_resolution():
    snapshot = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    current = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "", "FirstObservedUtc": "2026-09-14T00:00:00Z",
        "SlaPolicyName": "High", "SlaPolicyVersion": "policy-v1", "SlaDays": 7,
        "SlaStartUtc": "2026-09-14T00:00:00Z", "SlaDueUtc": "2026-09-21T00:00:00Z",
        "SlaStatus": "FixedWithinSla", "FixedUtc": "", "ReopenedUtc": "",
        "SnapshotTimeUtc": "2026-09-21T12:00:00Z", "CollectionRunId": "current",
    }]
    previous = [dict(
        current[0], FindingStatus="PendingConfirmation", FirstAbsentUtc="2026-09-20T23:00:00Z",
        EffectiveRemediationUtc="2026-09-20T23:00:00Z", ConsecutiveAbsentCount=1,
        ConfirmationRunsCompleted=1, ConfirmationRunsRequired=2,
    )]

    returned = reconcile_live_findings(current, previous, snapshot, "returned")[0]

    assert returned["FindingStatus"] == "DetectionReturned"
    assert returned["EffectiveRemediationUtc"] == ""
    assert returned["VerificationFailedUtc"] == "2026-09-21T12:00:00Z"
    assert returned["SlaStatus"] == "OpenOutsideSla"
    assert returned["SlaEvidenceStatus"] == "DetectionReturned"


def test_live_reconciliation_preserves_assigned_sla_policy_version():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    current = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "Critical", "PublicExploitAvailable": True, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "SlaPolicyName": "CriticalKnownExploit", "SlaPolicyVersion": "vulnerability-view-2026-09-21", "SlaDays": 7,
        "SlaStartUtc": "2026-09-10T00:00:00Z", "SlaDueUtc": "2026-09-17T00:00:00Z", "SlaStatus": "OpenWithinSla",
        "FixedUtc": "", "ReopenedUtc": "", "SnapshotTimeUtc": "2026-09-20T00:00:00Z", "CollectionRunId": "current",
    }]
    previous = [dict(current[0], SlaPolicyName="LegacyCritical", SlaPolicyVersion="legacy-v1", SlaDays=30, SlaDueUtc="2026-10-10T00:00:00Z")]

    reconciled = reconcile_live_findings(current, previous, snapshot, "live-20260920T000000Z")

    assert reconciled[0]["SlaPolicyName"] == "LegacyCritical"
    assert reconciled[0]["SlaPolicyVersion"] == "legacy-v1"
    assert reconciled[0]["SlaDueUtc"] == "2026-10-10T00:00:00Z"
    assert reconciled[0]["SlaStatus"] == "OpenWithinSla"


def test_live_normalization_links_recommendation_remediation_status():
    payloads = {
        "machine_vulnerabilities": [],
        "machines": [],
        "vulnerabilities": [],
        "recommendations": [{
            "id": "recommendation-1", "recommendationName": "Update Product", "productName": "Product",
            "vendor": "Vendor", "recommendedVersion": "2.0", "severityScore": 9.0, "status": "Active",
            "remediationType": "Update", "recommendationCategory": "Software", "subCategory": "Security update",
            "relatedComponent": "Runtime", "exposedMachinesCount": 12, "totalMachineCount": 20,
            "publicExploit": True, "activeAlert": False, "hasUnpatchableCve": False,
            "exposureImpact": 0.25, "configScoreImpact": 4.0, "associatedThreats": ["Threat"],
            "weaknesses": ["CWE-1"], "tags": ["InternetFacing"],
        }],
        "remediation_tasks": [{
            "id": "task-1", "recommendationReference": "recommendation-1", "title": "Deploy update",
            "status": "Active", "priority": "High", "targetDevices": 12, "fixedDevices": 5,
            "rbacGroupNames": ["Endpoints"],
        }],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    recommendation = result["recommendations"][0]
    assert recommendation["RecommendationId"] == "recommendation-1"
    assert recommendation["ExposedMachinesCount"] == 12
    assert recommendation["RemediationTriggered"] is True
    assert recommendation["RemediationStatus"] == "Active"
    assert result["remediationActivities"][0]["RecommendationId"] == "recommendation-1"


def test_live_normalization_prefers_vulnerability_recommendation_for_product_findings():
    payloads = {
        "machine_vulnerabilities": [
            {"id": f"finding-{index}", "machineId": f"device-{index}", "cveId": "CVE-2026-20941", "productVendor": "microsoft", "productName": "windows_11", "severity": "High"}
            for index in range(4)
        ],
        "machines": [{"id": f"device-{index}", "computerDnsName": f"device-{index}", "osPlatform": "Windows11", "machineTags": []} for index in range(4)],
        "vulnerabilities": [{"id": "CVE-2026-20941", "severity": "High", "exposedMachines": 4}],
        "recommendations": [
            {"id": "va-_-microsoft-_-windows_11", "recommendationName": "Update Microsoft Windows 11", "productName": "windows_11", "remediationType": "Update"},
            {"id": "sca-_-scid-2501", "recommendationName": "Block child processes", "productName": "windows_11", "remediationType": "ConfigurationChange"},
        ],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert {row["RecommendationId"] for row in result["findings"]} == {"va-_-microsoft-_-windows_11"}
    assert {row["DeviceId"] for row in result["findings"]} == {"device-0", "device-1", "device-2", "device-3"}


def test_live_normalization_emits_recommendation_machine_without_cve_finding():
    payloads = {
        "machine_vulnerabilities": [],
        "machines": [{"id": "device-1", "computerDnsName": "device-1", "osPlatform": "Windows11", "exposureLevel": "High", "machineTags": []}],
        "vulnerabilities": [],
        "recommendations": [{"id": "sca-_-scid-2501", "recommendationName": "Block child processes", "productName": "windows_11"}],
        "recommendation_machines": [{"_recommendationId": "sca-_-scid-2501", "id": "device-1", "computerDnsName": "device-1", "osPlatform": "Windows11", "rbacGroupName": "Endpoints"}],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert result["recommendationMachines"] == [{
        "RecommendationId": "sca-_-scid-2501", "DeviceId": "device-1", "DeviceName": "device-1",
        "OSPlatform": "Windows11", "DeviceGroupName": "Endpoints", "DeviceExposureLevel": "High",
        "LastSeenUtc": "", "AssetClass": "TraditionalIT", "AzureResourceId": "", "SubscriptionId": "", "OwnerTeam": "Endpoint Operations",
        "ClassificationReason": "Onboarded device without Azure resource evidence", "DataOrigin": "Live",
        "ScenarioId": "LIVE-DEFENDER-SNAPSHOT", "SnapshotTimeUtc": "2026-09-17T00:00:00Z",
        "CollectionRunId": "live-run",
    }]


def test_live_normalization_emits_actual_secure_score():
    payloads = {
        "machine_vulnerabilities": [], "machines": [], "vulnerabilities": [], "recommendations": [],
        "secure_scores": [{
            "currentScore": 42.0, "maxScore": 60.0, "createdDateTime": "2026-09-17T00:00:00Z",
            "activeUserCount": 90, "licensedUserCount": 100, "enabledServices": ["HasIntune"],
            "averageComparativeScores": [{"basis": "AllTenants", "averageScore": 35.0}],
            "controlScores": [{"controlCategory": "Device", "score": 12.0}],
        }],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert result["secureScores"][0]["ScorePercent"] == 70.0
    assert result["secureScores"][0]["DeviceScore"] == 12.0
    assert result["secureScores"][0]["DataOrigin"] == "Live"


def test_live_normalization_emits_vulnerability_detail_rows():
    payloads = {
        "machine_vulnerabilities": [{
            "id": "finding-1", "machineId": "machine-1", "cveId": "CVE-2026-0001",
            "productName": "Example", "productVersion": "1", "severity": "High",
        }],
        "machines": [{"id": "machine-1"}], "recommendations": [],
        "vulnerabilities": [{
            "id": "CVE-2026-0001", "name": "CVE-2026-0001", "description": "Important vulnerability",
            "severity": "High", "cvssV3": 8.4, "cvssVector": "CVSS:3.1/AV:N", "epss": 0.12,
            "exposedMachines": 3, "publishedOn": "2026-09-01T00:00:00Z", "updatedOn": "2026-09-02T00:00:00Z",
            "firstDetected": "2026-09-03T00:00:00Z", "patchFirstAvailable": "2026-09-04T00:00:00Z",
            "publicExploit": True, "exploitVerified": False, "exploitInKit": True,
            "exploitTypes": ["Remote"], "exploitUris": ["https://example.invalid"],
            "cveSupportability": "Supported", "status": "RemediationRequired", "tags": ["tag"],
        }, {
            "id": "CVE-2026-9999", "name": "CVE-2026-9999",
            "description": "Not referenced by a collected finding", "severity": "Low",
        }],
    }

    rows = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["vulnerabilities"]
    row = rows[0]

    assert len(rows) == 1
    assert row["CveId"] == "CVE-2026-0001"
    assert row["Description"] == "Important vulnerability"
    assert row["CvssScore"] == 8.4
    assert row["Epss"] == 0.12
    assert row["ExploitTypes"] == "Remote"
    assert row["Status"] == "RemediationRequired"


def test_raw_snapshot_replay(tmp_path):
    run_folder = tmp_path / "live-20260916T120000Z"
    run_folder.mkdir()
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "Unknown"}],
        "machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "Unknown"}],
        "recommendations": [], "remediation_tasks": [], "vulnerability_changes": [],
    }
    for endpoint, rows in payloads.items():
        with gzip.open(run_folder / f"{endpoint}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": rows}, handle)
    with gzip.open(run_folder / "recommendation_machines--va-_-vendor-_-product-page-0001.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"value": [{"id": "device-1", "computerDnsName": "device", "osPlatform": "Windows11", "rbacGroupName": "Endpoints"}]}, handle)
    with gzip.open(run_folder / "azure_subscriptions-page-0001.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"value": [{
            "type": "Microsoft.Management/managementGroups/subscriptions",
            "name": "subscription-1",
            "properties": {"displayName": "Production"},
        }]}, handle)
    data, statuses = replay_raw_snapshot(run_folder)
    assert len(data["findings"]) == 1
    assert data["findings"][0]["Severity"] == "Unknown"
    assert data["recommendationMachines"][0]["RecommendationId"] == "va-_-vendor-_-product"
    assert data["recommendationMachines"][0]["DeviceId"] == "device-1"
    assert data["subscriptions"][0]["SubscriptionName"] == "Production"
    statuses_by_endpoint = {status["Endpoint"]: status for status in statuses}
    assert statuses_by_endpoint["secure_scores"]["Status"] == "OptionalUnavailable"
    assert statuses_by_endpoint["azure_subscriptions"]["Status"] == "Success"


def test_delta_raw_snapshot_replay_uses_reconstructed_current_state(tmp_path):
    run_folder = tmp_path / "live-20260916T120000Z"
    run_folder.mkdir()
    payloads = {
        "derived_machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"}],
        "derived_vulnerabilities": [{"id": "CVE-2026-0001", "description": "Replayed from delta baseline", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": []}],
        "recommendations": [],
        "vulnerability_changes": [{"id": "finding-1", "status": "New"}],
    }
    for endpoint, rows in payloads.items():
        with gzip.open(run_folder / f"{endpoint}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": rows}, handle)

    data, statuses = replay_raw_snapshot(run_folder)

    assert data["findings"][0]["FindingKey"] == "finding-1"
    assert data["vulnerabilities"][0]["Description"] == "Replayed from delta baseline"
    statuses_by_endpoint = {status["Endpoint"]: status for status in statuses}
    assert statuses_by_endpoint["machine_vulnerabilities"]["Status"] == "Success"
    assert statuses_by_endpoint["vulnerabilities"]["Status"] == "Success"


def test_raw_snapshot_replay_can_allow_missing_required_pages(tmp_path):
    run_folder = tmp_path / "live-20260916T120000Z"
    run_folder.mkdir()
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High"}],
    }
    for endpoint, rows in payloads.items():
        with gzip.open(run_folder / f"{endpoint}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": rows}, handle)

    data, statuses = replay_raw_snapshot(run_folder, allow_missing_required=True)

    assert len(data["findings"]) == 1
    assert {status["Endpoint"]: status["Status"] for status in statuses}["recommendations"] == "HistoricalUnavailable"
    assert statuses[-1]["Status"] == "OptionalUnavailable"