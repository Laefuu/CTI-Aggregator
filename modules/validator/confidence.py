"""
Confidence score calculation — 4 independent dimensions, max 100 pts.

    Source reliability (35 pts):
        trusted  → 35
        known    → 18
        unknown  → 0

    Freshness (25 pts):
        < 24h  → 25
        < 7d   → 17
        < 30d  → 8
        ≥ 30d  → 0

    Corroboration (20 pts):
        ≥ 3 sources → 20   (populated by Deduplicator on merge)
        2 sources   → 10
        1 source    → 0

    LLM Quality (20 pts):
        0 hallucinations corrected → 20
        1                         → 15
        2                         → 10
        ≥ 3                       → 0
        Coherence rules (override to 0):
          - threat-actor without a name
          - indicator without a pattern

At validation time, corroboration is always 0 (first insert).
The Deduplicator recalculates after each merge.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def compute_confidence(
    source_category: str,
    published_at: datetime | None,
    fetched_at: datetime,
    source_count: int = 1,
    hallucination_count: int = 0,
    stix_obj: dict[str, Any] | None = None,
) -> int:
    """
    Compute confidence score [0, 100].

    Args:
        source_category:    "trusted", "known", or "unknown"
        published_at:       Article publication date (None → use fetched_at)
        fetched_at:         When the document was collected
        source_count:       Number of distinct sources (for corroboration)
        hallucination_count: Number of x_cti_* fields corrected by hallucination check
        stix_obj:           Validated STIX object dict (for coherence checks)
    """
    score, _ = compute_confidence_with_detail(
        source_category=source_category,
        published_at=published_at,
        fetched_at=fetched_at,
        source_count=source_count,
        hallucination_count=hallucination_count,
        stix_obj=stix_obj,
    )
    return score


def compute_confidence_with_detail(
    source_category: str,
    published_at: datetime | None,
    fetched_at: datetime,
    source_count: int = 1,
    hallucination_count: int = 0,
    stix_obj: dict[str, Any] | None = None,
) -> tuple[int, dict[str, int]]:
    """
    Compute confidence score and return the per-dimension breakdown.

    Returns:
        (total_score, detail_dict) where detail_dict has keys:
            reliability, freshness, corroboration, llm_quality
    """
    reliability = _reliability_score(source_category)
    freshness = _freshness_score(published_at or fetched_at)
    corroboration = _corroboration_score(source_count)
    llm_quality = _llm_quality_score(stix_obj, hallucination_count)

    total = reliability + freshness + corroboration + llm_quality
    detail: dict[str, int] = {
        "reliability": reliability,
        "freshness": freshness,
        "corroboration": corroboration,
        "llm_quality": llm_quality,
    }
    return total, detail


def _reliability_score(category: str) -> int:
    match category.lower():
        case "trusted":
            return 35
        case "known":
            return 18
        case _:
            return 0


def _freshness_score(reference_date: datetime) -> int:
    now = datetime.now(UTC)
    # Ensure timezone-aware comparison
    if reference_date.tzinfo is None:
        reference_date = reference_date.replace(tzinfo=UTC)
    age = now - reference_date
    if age < timedelta(hours=24):
        return 25
    if age < timedelta(days=7):
        return 17
    if age < timedelta(days=30):
        return 8
    return 0


def _corroboration_score(source_count: int) -> int:
    if source_count >= 3:
        return 20
    if source_count == 2:
        return 10
    return 0


def _llm_quality_score(
    stix_obj: dict[str, Any] | None,
    hallucination_count: int,
) -> int:
    """
    LLM quality dimension (0–20 pts).

    Deducts 5 pts per hallucination corrected.
    Returns 0 for coherence violations (threat-actor without name,
    indicator without pattern).
    """
    # Coherence checks — hard zero regardless of hallucinations
    if stix_obj is not None:
        stix_type = stix_obj.get("type", "")
        if stix_type == "threat-actor" and not stix_obj.get("name", "").strip():
            return 0
        if stix_type == "indicator" and not stix_obj.get("pattern", "").strip():
            return 0

    return max(0, 20 - hallucination_count * 5)


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

    LLM quality is not re-evaluated at merge time (no hallucination context available);
    it defaults to 20 pts (assumes the original object passed quality checks).
    """
    return compute_confidence(
        source_category=source_category,
        published_at=published_at,
        fetched_at=fetched_at,
        source_count=source_count,
    )
