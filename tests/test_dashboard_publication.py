from threading import Event

import pytest

from vulnerability_view.dashboard_publication import DashboardPublication


def test_publication_coalesces_dirty_products_without_blocking_callers():
    publication = DashboardPublication()
    calls = []
    try:
        publication.enqueue("products", lambda: calls.append("old"), delay=60)
        publication.enqueue("products", lambda: calls.append("latest"), delay=60)
        publication.flush(1)
        assert calls == ["latest"]
        assert publication.diagnostics() == {"pending": 0, "active": False, "error": ""}
    finally:
        publication.close()


def test_changes_during_publication_are_not_lost():
    publication = DashboardPublication()
    entered, release = Event(), Event()
    calls = []

    def publish():
        entered.set()
        assert release.wait(5)
        calls.append("first")

    try:
        publication.enqueue("products", publish)
        assert entered.wait(1)
        publication.enqueue("products", lambda: calls.append("second"), delay=60)
        release.set()
        publication.flush(1)
        assert calls == ["first", "second"]
    finally:
        release.set()
        publication.close()


def test_publication_failure_is_logged_visible_and_retryable(caplog):
    publication = DashboardPublication()
    attempts = []

    def publish():
        attempts.append(True)
        if len(attempts) == 1:
            raise OSError("storage unavailable")

    try:
        publication.enqueue("products", publish)
        with pytest.raises(TimeoutError):
            publication.flush(.05)
        assert "storage unavailable" in caplog.text
        assert publication.diagnostics()["error"]
        publication.flush(1)
        assert len(attempts) == 2
        assert not publication.diagnostics()["error"]
    finally:
        publication.close()
