"""Author: Kevin Tigges
Last modified: 2026-09-27
Purpose: Verify append-only shared recommendation workflow persistence.
"""

import json

import pytest

from vulnerability_view.recommendation_tracking import RecommendationTrackingStore


class FakeBlob:
    def __init__(self, content: bytes = b""):
        self.content = content

    def upload_blob(self, content: bytes, overwrite: bool):
        assert overwrite is False
        self.content = content

    def download_blob(self):
        return self

    def readall(self):
        return self.content


class FakeContainer:
    def __init__(self):
        self.blobs = {}

    def get_blob_client(self, name):
        return self.blobs.setdefault(name, FakeBlob())

    def list_blobs(self, name_starts_with):
        return [
            type("BlobItem", (), {"name": name})()
            for name in sorted(self.blobs)
            if name.startswith(name_starts_with)
        ]


class FakeService:
    def __init__(self, container):
        self.container = container

    def get_container_client(self, _name):
        return self.container


def test_tracking_store_appends_events_and_returns_latest():
    container = FakeContainer()
    store = RecommendationTrackingStore(
        "account",
        "workflow",
        object(),
        service_factory=lambda **_: FakeService(container),
    )

    first = store.record("rec/1", "InProgress", "run-1", "2026-09-27T12:00:00Z", "user-1", "User One")
    second = store.record("rec/1", "ReadyForValidation", "run-1", "2026-09-27T12:00:00Z", "user-1", "User One")
    latest = store.latest()["rec/1"]

    assert first["BlobName"] != second["BlobName"]
    assert len(container.blobs) == 2
    assert latest["UserStatus"] == "ReadyForValidation"
    assert json.loads(container.blobs[second["BlobName"]].content)["RecommendationId"] == "rec/1"


def test_tracking_store_surfaces_malformed_events():
    container = FakeContainer()
    container.blobs["events/hash/2026/09/27/broken.json"] = FakeBlob(b"not-json")
    store = RecommendationTrackingStore(
        "account",
        "workflow",
        object(),
        service_factory=lambda **_: FakeService(container),
    )

    with pytest.raises(json.JSONDecodeError):
        store.latest()


def test_tracking_store_rejects_an_event_without_a_recommendation():
    container = FakeContainer()
    container.blobs["events/hash/2026/09/27/missing-id.json"] = FakeBlob(
        json.dumps({"UserStatus": "InProgress"}).encode(),
    )
    store = RecommendationTrackingStore(
        "account",
        "workflow",
        object(),
        service_factory=lambda **_: FakeService(container),
    )

    with pytest.raises(ValueError, match="no RecommendationId"):
        store.latest()
