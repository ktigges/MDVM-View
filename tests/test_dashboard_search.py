import hashlib
import random

import pytest

from test_dashboard_queries import datasets, engine, finding
from vulnerability_view import dashboard_search
from vulnerability_view.dashboard_control import QueryCancelled, QueryControl, query_control


def test_trigram_projection_preserves_exact_unicode_null_and_cross_field_substrings(tmp_path):
    rng = random.Random(42)
    data = datasets(0)
    alphabet = 'abCD019\n\x00\x01" *()-ßüİ🦊🐈🌊'
    data["findings"] = [
        finding(index, ProductName="".join(rng.choices(alphabet, k=45)))
        for index in range(520)
    ]
    e = engine(tmp_path, data)
    e._ensure("findings")
    published = []
    e.search_index.publisher = published.append
    e.search_index.prepare()
    assert published == [e.search_index.path]
    e.search_index.validate()
    terms = ["", "a", "ab", "\x00", "ßü", "i\u0307", '"""', "🦊🐈🌊", "not present anywhere"]
    for row in data["findings"][:100]:
        value = row["ProductName"].lower()
        start = rng.randrange(len(value) - 6)
        terms.append(value[start:start + rng.randrange(1, 7)])
    with e._connect() as db:
        text = db.execute("SELECT search FROM findings WHERE _rowid=1").fetchone()[0]
        boundary = text.index("\n")
        terms.extend((text[boundary - 2:boundary + 3], "\n\n", "a\nb", "2026-"))
        for term in terms:
            expected = [r[0] for r in db.execute(
                "SELECT _rowid FROM findings WHERE instr(search,?)>0 ORDER BY _rowid", (term.lower(),),
            )]
            assert list(e.search_index.matches(term)) == expected, repr(term)


def test_search_projection_does_not_change_or_reingest_primary(tmp_path):
    data = datasets(300)
    e = engine(tmp_path, data)
    e.build_index({"findings": 300})
    before = hashlib.sha256(e.path.read_bytes()).hexdigest()
    e.search_index.prepare()
    assert hashlib.sha256(e.path.read_bytes()).hexdigest() == before
    restored = engine(tmp_path, data)
    restored.search_index.prepare()
    assert restored.reads == {}
    assert list(restored.search_index.matches("finding-0299")) == [300]


def test_unseen_search_term_uses_projection_instead_of_finding_payload_scan(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(300))
    e.prepare_workspace_indexes()
    e.search_index.prepare()
    import vulnerability_view.dashboard_queries as queries
    from contextlib import contextmanager
    original = queries.startup_stage

    @contextmanager
    def stage(name):
        assert name != "query:search:exact-substring-scan"
        with original(name):
            yield

    monkeypatch.setattr(queries, "startup_stage", stage)
    result = e.query({"view": "overview", "filters": {"search": "finding-0299"}})
    assert result["scope"]["findings"] == 1
    assert result["tables"]["findingsTable"]["items"][0]["FindingKey"] == "finding-0299"


def test_incomplete_or_cancelled_search_index_is_never_installed(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(300))
    e._ensure("findings")
    monkeypatch.setattr(dashboard_search, "MAX_BYTES", 16 * 1024)
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        e.search_index.prepare()
    assert not e.search_index.ready()
    assert not e.search_index.path.with_suffix(".building").exists()
    control = QueryControl()
    control.cancel()
    with pytest.raises(QueryCancelled), query_control(control):
        e.search_index.prepare()
    assert not e.search_index.ready()
