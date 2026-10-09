import base64

from vulnerability_view.dashboard_branding import (
    LOGO_PREFIX,
    DashboardBrandingStore,
    validate_png,
)


VALID_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class FakeDownload:
    def __init__(self, content):
        self.content = content

    def readall(self):
        return self.content


class FakeBlob:
    def __init__(self, container, name):
        self.container = container
        self.name = name

    def upload_blob(self, content, **kwargs):
        self.container.uploads.append((self.name, bytes(content), kwargs))
        self.container.blobs[self.name] = bytes(content)

    def download_blob(self):
        return FakeDownload(self.container.blobs[self.name])


class FakeContainer:
    def __init__(self):
        self.blobs = {}
        self.uploads = []

    def get_blob_client(self, name):
        return FakeBlob(self, name)

    def list_blobs(self, name_starts_with):
        return [
            type("BlobItem", (), {"name": name})
            for name in self.blobs
            if name.startswith(name_starts_with)
        ]


class FakeService:
    def __init__(self, container):
        self.container = container

    def get_container_client(self, _):
        return self.container


def test_validate_png_returns_dimensions_and_rejects_corruption():
    assert validate_png(VALID_PNG) == (1, 1)

    corrupted = bytearray(VALID_PNG)
    corrupted[-1] ^= 1

    try:
        validate_png(bytes(corrupted))
    except ValueError as error:
        assert "checksum" in str(error)
    else:
        raise AssertionError("Corrupted PNG was accepted")


def test_branding_store_appends_versions_without_overwrite_and_reads_newest():
    container = FakeContainer()
    store = DashboardBrandingStore(
        "storage",
        "workflow",
        credential=object(),
        service_factory=lambda **_: FakeService(container),
    )

    store.upload(VALID_PNG)
    store.upload(VALID_PNG + b"newer")

    assert len(container.uploads) == 2
    assert all(name.startswith(LOGO_PREFIX) and name.endswith(".png") for name, _, _ in container.uploads)
    assert all(options["overwrite"] is False for _, _, options in container.uploads)
    assert store.latest() == container.blobs[sorted(container.blobs)[-1]]
