"""
Unit tests for the search functionality (FTS5 + ILIKE fallback).
"""

import pytest
from response.search_fts import (
    parse_fts5_query,
    _escape_like,
    _normalize_bm25,
    init_fts5_tables,
    backfill_fts5,
)


class TestParseFTS5Query:
    def test_single_word(self):
        assert parse_fts5_query("ssh") == '"ssh"'

    def test_multiple_words_default_and(self):
        assert parse_fts5_query("ssh brute force") == '"ssh" "brute" "force"'

    def test_explicit_or(self):
        assert parse_fts5_query("ssh OR brute") == '"ssh" OR "brute"'

    def test_explicit_and(self):
        assert parse_fts5_query("ssh AND brute") == '"ssh" AND "brute"'

    def test_phrase_query(self):
        assert parse_fts5_query('"ssh brute force"') == '"ssh brute force"'

    def test_prefix_query(self):
        assert parse_fts5_query("container*") == '"container"*'

    def test_not_operator(self):
        assert parse_fts5_query("-wazuh") == 'NOT "wazuh"'

    def test_mixed_query(self):
        assert parse_fts5_query('ssh "brute force" -wazuh container*') == (
            '"ssh" "brute force" NOT "wazuh" "container"*'
        )

    def test_empty_query(self):
        assert parse_fts5_query("") == ""
        assert parse_fts5_query("   ") == ""

    def test_special_chars_escaped(self):
        # Internal quotes should be escaped
        assert parse_fts5_query('say "hello"') == '"say" "hello"'

    def test_unicode(self):
        assert parse_fts5_query("攻击") == '"攻击"'


class TestEscapeLike:
    def test_no_special_chars(self):
        assert _escape_like("hello") == "hello"

    def test_percent(self):
        assert _escape_like("100%") == "100\\%"

    def test_underscore(self):
        assert _escape_like("test_case") == "test\\_case"

    def test_backslash(self):
        assert _escape_like("foo\\bar") == "foo\\\\bar"

    def test_mixed(self):
        assert _escape_like("_%\\") == "\\_\\%\\\\"


class TestNormalizeBM25:
    def test_empty(self):
        assert _normalize_bm25([]) == []

    def test_all_same(self):
        assert _normalize_bm25([5.0, 5.0, 5.0]) == [1.0, 1.0, 1.0]

    def test_different_scores(self):
        scores = [0.0, 5.0, 10.0]
        result = _normalize_bm25(scores)
        assert result[0] == 1.0
        assert result[2] == 0.0
        assert 0.0 < result[1] < 1.0

    def test_single_score(self):
        assert _normalize_bm25([3.0]) == [1.0]


@pytest.mark.asyncio
async def test_init_fts5_tables_runs():
    """Smoke test: init should not raise."""
    await init_fts5_tables()


@pytest.mark.asyncio
async def test_backfill_fts5_runs():
    """Smoke test: backfill should not raise."""
    await backfill_fts5()
