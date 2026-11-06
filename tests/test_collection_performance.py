"""Production-shaped local verification benchmark; not an Azure end-to-end SLA test."""

import gzip
import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest

from test_collection_workflow import batch_store
from vulnerability_view.collection_workflow import publish_run, verify_batch


@pytest.mark.performance
def test_verify_customer_scale_pages_with_bounded_batches(tmp_path):
    store = batch_store(0)
    store.manifest["files"] = []
    remote = {}
    rows = 0
    remaining = 2091597 - 188 * 2501
    per_machine, extra = divmod(remaining, 2063)
    for machine in range(2252):
        sizes = (
            [2500, 1] if machine < 188 else
            [per_machine + (machine - 188 < extra)] if machine < 2251 else [0]
        )
        for page, size in enumerate(sizes):
            content = json.dumps({"value": [{
                "id": f"finding-{machine}-{page}-{index}", "machineId": f"machine-{machine}",
                "cveId": f"CVE-2026-{index % 13604:05d}", "severity": "High",
                "productName": "representative-software", "productVersion": "10.0.26100",
                "firstSeen": "2026-10-01T00:00:00Z", "lastSeen": "2026-11-06T18:34:06Z",
            } for index in range(size)]}, separators=(",", ":")).encode()
            compressed = gzip.compress(content, compresslevel=1, mtime=0)
            name = f"raw/run/machine-{machine}-page-{page}.json.gz"
            path = tmp_path / f"{machine}-{page}.gz"
            path.write_bytes(compressed)
            remote[name] = path
            store.manifest["files"].append({
                "path": name, "sha256": hashlib.sha256(compressed).hexdigest(),
                "sizeBytes": len(compressed), "rowCount": size, "kind": "raw",
            })
            rows += size
    assert rows == 2091597
    assert len(remote) == len(store.manifest["files"]) == 2440
    store.save_manifest()
    lock = threading.Lock()
    active = peak = downloads = 0

    def download(name, **kwargs):
        assert kwargs == {"max_concurrency": 1}

        def chunks():
            nonlocal active, peak, downloads
            with lock:
                active += 1
                downloads += 1
                peak = max(peak, active)
            try:
                with remote[name].open("rb") as handle:
                    yield from iter(lambda: handle.read(65536), b"")
            finally:
                with lock:
                    active -= 1
        return SimpleNamespace(chunks=chunks)

    store.history.download_blob = download
    started = time.monotonic()
    index = batches = 0
    while index < 2440:
        result = verify_batch({**store.reference, "fileIndex": index}, store)
        assert 0 < result["nextIndex"] - index <= 32
        index = result["nextIndex"]
        batches += 1
    assert batches == 77
    assert downloads == 2440
    assert active == 0 and peak <= 4
    assert publish_run(store.reference, store)["published"]
    elapsed = time.monotonic() - started
    assert elapsed < 480, f"Local verification/publication exceeded eight minutes: {elapsed:.1f}s"
    print(f"scale verification: rows={rows} machines=2252 files=2440 batches={batches} peakDownloads={peak} seconds={elapsed:.2f}")
