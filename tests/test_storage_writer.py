import gzip
import hashlib
import json
from pathlib import Path

from vulnerability_view.config import Settings
from vulnerability_view.dataprep_cli import _include_synthetic_history, _latest_live_cve_catalog, backfill_history, main, seed_synthetic_history
from vulnerability_view.live_collector import normalize_live
from vulnerability_view.storage_writer import DATASET_FILES, create_run_bundle, download_current_dataset, download_current_manifest, upload_raw_archive, upload_run_bundle, verify_run_bundle


def test_create_run_bundle_preserves_curated_data_policy_and_checksums(tmp_path: Path):
    raw_run = tmp_path / "raw" / "live-20250102T030405Z"
    raw_run.mkdir(parents=True)
    (raw_run / "machines-page-0001.json.gz").write_bytes(b"raw")
    policy = tmp_path / "sla-policies.json"
    policy.write_text('[{"policyName":"High","slaDays":30}]')
    datasets = {"findings": [{"FindingKey": "finding-1", "SlaStatus": "OpenWithinSla"}]}
    statuses = [{"Endpoint": "machines", "Status": "Success", "RowCount": 1}]

    bundle = create_run_bundle(raw_run, datasets, statuses, policy, tmp_path / "history")

    assert {path.name for path in (bundle / "curated").glob("*.json.gz")} == {
        f"{basename}.json.gz" for basename in DATASET_FILES.values()
    }
    with gzip.open(bundle / "curated/findings.json.gz", "rt", encoding="utf-8") as handle:
        assert json.load(handle) == datasets["findings"]
    with gzip.open(bundle / "curated/recommendations.json.gz", "rt", encoding="utf-8") as handle:
        assert json.load(handle) == []
    assert (bundle / "policy/sla-policies.json").read_text() == policy.read_text()
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["complete"] is True
    assert manifest["runId"] == "live-20250102T030405Z"
    assert len(manifest["files"]) == len(DATASET_FILES) + 2
    assert all(file["sha256"] for file in manifest["files"])


def test_create_run_bundle_supports_synthetic_runs_without_raw_pages(tmp_path: Path):
    source_run = tmp_path / "synthetic" / "synthetic-20250102T030405Z-17"
    source_run.mkdir(parents=True)
    policy = tmp_path / "sla-policies.json"
    policy.write_text("[]")

    bundle = create_run_bundle(
        source_run,
        {"findings": [{"FindingKey": "synthetic-1", "DataOrigin": "Synthetic"}]},
        [{"Endpoint": "synthetic_generator", "Status": "Success"}],
        policy,
        tmp_path / "history",
    )

    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["runId"] == "synthetic-20250102T030405Z-17"
    assert manifest["snapshotTimeUtc"] == "2025-01-02T03:04:05Z"
    assert all(item["kind"] != "raw" for item in manifest["files"])
    assert verify_run_bundle(bundle, source_run) == []


def test_upload_run_bundle_writes_manifest_last(monkeypatch, tmp_path: Path):
    raw_run = tmp_path / "raw" / "live-20250102T030405Z"
    raw_run.mkdir(parents=True)
    (raw_run / "machines-page-0001.json.gz").write_bytes(b"raw")
    policy = tmp_path / "sla-policies.json"
    policy.write_text("[]")
    bundle = create_run_bundle(raw_run, {}, [], policy, tmp_path / "history")
    uploads = []

    class AlreadyExists(Exception):
        status_code = 409

    class FileClient:
        def __init__(self, remote_path):
            self.remote_path = remote_path

        def upload_blob(self, content, overwrite):
            uploads.append((self.remote_path, content.read(), overwrite))

    class ContainerClient:
        def create_container(self):
            raise AlreadyExists()

        def get_blob_client(self, remote_path):
            return FileClient(remote_path)

    class ServiceClient:
        def __init__(self, account_url, credential):
            pass

        def get_container_client(self, container_name):
            return ContainerClient()

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", ServiceClient)

    archived = upload_run_bundle(raw_run, bundle, "account", "dvm-history", "dvm-current", "credential")

    immutable_manifest = "runs/2025/01/02/live-20250102T030405Z/manifest.json"
    assert immutable_manifest in archived
    assert archived.index(immutable_manifest) < archived.index("current/manifest.json")
    assert archived[-1] == "current/manifest.json"
    assert uploads[-1][0] == archived[-1]
    assert all(overwrite is False for path, _, overwrite in uploads if not path.startswith("current/"))
    assert all(overwrite is True for path, _, overwrite in uploads if path.startswith("current/"))
    assert any(path.startswith("raw/2025/01/02/") for path in archived)
    assert any(path.startswith("curated/2025/01/02/") for path in archived)

    uploads.clear()
    archived = upload_run_bundle(
        raw_run, bundle, "account", "dvm-history", "dvm-current", "credential", publish_current=False
    )

    assert "current/manifest.json" not in archived
    assert all(path != "current/manifest.json" for path, _, _ in uploads)


def test_download_current_dataset_reads_compressed_json(monkeypatch):
    payload = gzip.compress(json.dumps([{"FindingKey": "finding-1"}]).encode())
    manifest = json.dumps({
        "schemaVersion": 1,
        "complete": True,
        "files": [{
            "kind": "curated",
            "dataset": "findings",
            "path": "curated/2025/01/02/live-20250102T030405Z/findings.json.gz",
            "sizeBytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }).encode()

    class Download:
        def __init__(self, content):
            self.content = content

        def readall(self):
            return self.content

    class FileClient:
        def __init__(self, remote_path):
            self.remote_path = remote_path

        def download_blob(self):
            return Download(manifest if self.remote_path == "current/manifest.json" else payload)

    class ContainerClient:
        def get_blob_client(self, remote_path):
            assert remote_path in {
                "current/manifest.json",
                "curated/2025/01/02/live-20250102T030405Z/findings.json.gz",
            }
            return FileClient(remote_path)

    class ServiceClient:
        def __init__(self, account_url, credential):
            pass

        def get_container_client(self, container_name):
            return ContainerClient()

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", ServiceClient)

    assert download_current_dataset("account", "dvm-history", "dvm-current", "findings", "credential") == [{"FindingKey": "finding-1"}]


def test_download_current_manifest_is_a_single_pointer_read(monkeypatch):
    content = json.dumps({"schemaVersion": 1, "complete": True, "runId": "live-run"}).encode()

    class Download:
        def readall(self):
            return content

    class BlobClient:
        def download_blob(self):
            return Download()

    class ContainerClient:
        def get_blob_client(self, remote_path):
            assert remote_path == "current/manifest.json"
            return BlobClient()

    class ServiceClient:
        def __init__(self, account_url, credential):
            pass

        def get_container_client(self, container_name):
            assert container_name == "dvm-current"
            return ContainerClient()

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", ServiceClient)

    assert download_current_manifest("account", "dvm-current", "credential")["runId"] == "live-run"


def test_verify_run_bundle_detects_tampering(tmp_path: Path):
    raw_run = tmp_path / "raw" / "live-20250102T030405Z"
    raw_run.mkdir(parents=True)
    (raw_run / "machines-page-0001.json.gz").write_bytes(b"raw")
    policy = tmp_path / "sla-policies.json"
    policy.write_text("[]")
    bundle = create_run_bundle(raw_run, {"findings": [{"FindingKey": "finding-1"}]}, [], policy, tmp_path / "history")

    assert verify_run_bundle(bundle, raw_run) == []
    (bundle / "curated/findings.json.gz").write_bytes(b"tampered")

    assert any("mismatch" in error.lower() for error in verify_run_bundle(bundle, raw_run))


def test_backfill_history_replays_runs_in_order(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text(Path(__file__).parents[1].joinpath("config/sla-policies.json").read_text())
    first = tmp_path / "output/raw/live-20260919T000000Z"
    second = tmp_path / "output/raw/live-20260920T000000Z"
    third = tmp_path / "output/raw/live-20260921T000000Z"
    fourth = tmp_path / "output/raw/live-20260922T000000Z"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    third.mkdir(parents=True)
    fourth.mkdir(parents=True)

    def replay(folder, progress_callback=None, allow_missing_required=False):
        snapshot = __import__("datetime").datetime.strptime(folder.name.removeprefix("live-"), "%Y%m%dT%H%M%SZ").replace(tzinfo=__import__("datetime").timezone.utc)
        vulnerable = folder.name in {first.name, fourth.name}
        payloads = {
            "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-1", "severity": "High"}] if vulnerable else [],
            "machines": [{"id": "device-1", "computerDnsName": "device-1", "lastSeen": snapshot.isoformat(), "healthStatus": "Active", "onboardingStatus": "Onboarded", "machineTags": []}],
            "vulnerabilities": [], "recommendations": [],
        }
        return normalize_live(payloads, snapshot, folder.name), [{"Endpoint": "required", "Status": "Success", "RowCount": 1}]

    monkeypatch.setattr("vulnerability_view.dataprep_cli.replay_raw_snapshot", replay)

    runs, uploaded = backfill_history(Settings(), upload=False)

    assert runs == 4
    assert uploaded == 0
    with gzip.open(tmp_path / "output/history/live-20260920T000000Z/curated/findings.json.gz", "rt") as handle:
        findings = json.load(handle)
    assert findings[0]["FindingStatus"] == "PendingConfirmation"
    with gzip.open(tmp_path / "output/history/live-20260921T000000Z/curated/findings.json.gz", "rt") as handle:
        findings = json.load(handle)
    assert findings[0]["FindingStatus"] == "Fixed"
    with gzip.open(tmp_path / "output/history/live-20260922T000000Z/curated/finding-events.json.gz", "rt") as handle:
        events = json.load(handle)
    assert [event["EventType"] for event in events] == ["New", "PendingConfirmation", "Fixed", "Reopened"]


def test_seed_synthetic_history_builds_six_month_labeled_bundle(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text(
        Path(__file__).parents[1].joinpath("config/sla-policies.json").read_text()
    )
    curated = tmp_path / "output/history/live-20260922T000000Z/curated"
    curated.mkdir(parents=True)
    with gzip.open(curated / "findings.json.gz", "wt", encoding="utf-8") as handle:
        json.dump([{"CveId": "CVE-2025-1234", "Severity": "High", "CvssScore": 8.8}], handle)

    bundle, uploaded = seed_synthetic_history(
        Settings(synthetic_seed=17, synthetic_months=6),
        upload=False,
    )

    assert uploaded == []
    assert bundle.name.startswith("synthetic-")
    with gzip.open(bundle / "curated/findings.json.gz", "rt", encoding="utf-8") as handle:
        findings = json.load(handle)
    assert findings
    assert {row["DataOrigin"] for row in findings} == {"Synthetic"}
    assert len({row["FirstObservedUtc"][:7] for row in findings}) == 6
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["complete"] is True
    assert all(item["kind"] != "raw" for item in manifest["files"])


def test_latest_live_cve_catalog_uses_real_cve_ids_from_retained_findings(tmp_path: Path):
    curated = tmp_path / "live-20260922T000000Z" / "curated"
    curated.mkdir(parents=True)
    with gzip.open(curated / "findings.json.gz", "wt", encoding="utf-8") as handle:
        json.dump([
            {"CveId": "CVE-2025-1234", "Severity": "High", "CvssScore": 8.8},
            {"CveId": "TVM-2026-0001", "Severity": "Unknown", "CvssScore": 0},
            {"CveId": "CVE-2025-1234", "Severity": "High", "CvssScore": 8.8},
        ], handle)

    catalog = _latest_live_cve_catalog(tmp_path)

    assert [row["CveId"] for row in catalog] == ["CVE-2025-1234"]


def test_combined_mode_carries_only_existing_synthetic_rows():
    live = {
        "findings": [{"FindingKey": "live-new", "DataOrigin": "Live"}],
        "devices": [{"DeviceId": "live-device", "DataOrigin": "Live"}],
    }
    existing = {
        "findings": [
            {"FindingKey": "synthetic-old", "DataOrigin": "Synthetic"},
            {"FindingKey": "live-old", "DataOrigin": "Live"},
        ],
        "devices": [{"DeviceId": "synthetic-device", "DataOrigin": "Synthetic"}],
    }

    combined = _include_synthetic_history(live, existing, "combined")

    assert [row["FindingKey"] for row in combined["findings"]] == ["synthetic-old", "live-new"]
    assert [row["DeviceId"] for row in combined["devices"]] == ["synthetic-device", "live-device"]
    assert _include_synthetic_history(live, existing, "live") == live


def test_seed_synthetic_history_requires_explicit_azure_write_confirmation(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)

    assert main(["seed-synthetic-history"]) == 2


def test_upload_raw_archive_is_immutable_and_idempotent(monkeypatch, tmp_path: Path):
    run_folder = tmp_path / "live-20250102T030405Z"
    run_folder.mkdir()
    (run_folder / "machines-page-0001.json.gz").write_bytes(b"first")
    (run_folder / "machines-page-0002.json.gz").write_bytes(b"existing")
    uploads = []

    class AlreadyExists(Exception):
        status_code = 409

    class FileClient:
        def __init__(self, remote_path):
            self.remote_path = remote_path

        def upload_blob(self, content, overwrite):
            uploads.append((self.remote_path, content.read(), overwrite))
            if self.remote_path.endswith("0002.json.gz"):
                raise AlreadyExists()

    class ContainerClient:
        def create_container(self):
            raise AlreadyExists()

        def get_blob_client(self, remote_path):
            return FileClient(remote_path)

    class ServiceClient:
        def __init__(self, account_url, credential):
            pass

        def get_container_client(self, container_name):
            return ContainerClient()

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", ServiceClient)

    archived = upload_raw_archive(run_folder, "account", "dvm-history", "credential")

    assert archived == [
        "raw/2025/01/02/live-20250102T030405Z/machines-page-0001.json.gz",
        "raw/2025/01/02/live-20250102T030405Z/machines-page-0002.json.gz",
    ]
    assert all(overwrite is False for _, _, overwrite in uploads)


def test_application_storage_code_has_no_remote_delete_operations():
    source_root = Path(__file__).parents[1] / "src/vulnerability_view"
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_root.glob("*.py"))
    forbidden = (
        ".delete_file(",
        ".delete_directory(",
        ".delete_file_system(",
        ".delete_container(",
        ".delete_blob(",
        ".remove_file(",
    )

    assert all(operation not in source for operation in forbidden)