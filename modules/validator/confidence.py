"""
Confidence score calculation — 3 independent dimensions, max 100 pts.

    Source reliability (40 pts):
        trusted  → 40
        known    → 20
        unknown  → 0

    Freshness (30 pts):
        < 24h  → 30
        < 7d   → 20
        < 30d  → 10
        ≥ 30d  → 0

    Corroboration (30 pts):
        ≥ 3 sources → 30   (populated by Deduplicator on merge)
        2 sources   → 15
        1 source    → 0

At validation time, corroboration is always 0 (first insert).
The Deduplicator recalculates after each merge.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta


def compute_confidence(
    source_category: str,
    published_at: datetime | None,
    fetched_at: datetime,
    source_count: int = 1,
) -> int:
    """
    Compute confidence score [0, 100].

    Args:
        source_category: "trusted", "known", or "unknown"
        published_at:    Article publication date (None → use fetched_at)
        fetched_at:      When the document was collected
        source_count:    Number of distinct sources (for corroboration)
    """
    return (
        _reliability_score(source_category)
        + _freshness_score(published_at or fetched_at)
        + _corroboration_score(source_count)
    )


def _reliability_score(category: str) -> int:
    match category.lower():
        case "trusted":
            return 40
        case "known":
            return 20
        case _:
            return 0


def _freshness_score(reference_date: datetime) -> int:
    now = datetime.now(UTC)
    # Ensure timezone-aware comparison
    if reference_date.tzinfo is None:
        reference_date = reference_date.replace(tzinfo=UTC)
    age = now - reference_date
    if age < timedelta(hours=24):
        return 30
    if age < timedelta(days=7):
        return 20
    if age < timedelta(days=30):
        return 10
    return 0


def _corroboration_score(source_count: int) -> int:
    if source_count >= 3:
        return 30
    if source_count == 2:
        return 15
    return 0


def recalculate_after_merge(
    current_confidence: int,
    source_category: str,
    published_at: datetime | None,
    fetched_at: datetime,
    source_count: int,
) -> int:
    """
    Recalculate confidence after a merge, updating the corroboration component.
    Reliability and freshness are recomputed from the best (most trusted, most recent)
    source. Called by the Deduplicator after each merge.
    """
    return compute_confidence(source_category, published_at, fetched_at, source_count)
