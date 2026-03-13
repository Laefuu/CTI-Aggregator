"""
STIX object validation using shared Pydantic models.

Dispatches each raw dict to the appropriate model based on "type".
Returns a validated dict (not the model instance — keeps the pipeline
working with plain dicts throughout).

Unsupported STIX types are silently skipped (not rejected) since the LLM
may occasionally produce valid STIX types we don't track yet.
"""
from __future__ import annotations

from typing import Any

import structlog
from pydantic import ValidationError

from shared.models.stix import (
    AttackPatternSTIX,
    IndicatorSTIX,
    RelationshipSTIX,
    ThreatActorSTIX,
)

log = structlog.get_logger()

_VALIDATORS = {
    "indicator": IndicatorSTIX,
    "threat-actor": ThreatActorSTIX,
    "attack-pattern": AttackPatternSTIX,
    "relationship": RelationshipSTIX,
}


class ValidationResult:
    __slots__ = ("obj", "error", "skipped")

    def __init__(
        self,
        obj: dict[str, Any] | None = None,
        error: str | None = None,
        skipped: bool = False,
    ) -> None:
        self.obj = obj
        self.error = error
        self.skipped = skipped

    @property
    def valid(self) -> bool:
        return self.obj is not None

    @classmethod
    def ok(cls, obj: dict[str, Any]) -> "ValidationResult":
        return cls(obj=obj)

    @classmethod
    def fail(cls, reason: str) -> "ValidationResult":
        return cls(error=reason)

    @classmethod
    def skip(cls, reason: str) -> "ValidationResult":
        return cls(skipped=True, error=reason)


def validate_stix_object(raw: dict[str, Any]) -> ValidationResult:
    """
    Validate a single STIX object dict.

    Returns ValidationResult with:
        .valid   → True if validation passed
        .obj     → validated dict (with normalized fields)
        .error   → error message if invalid
        .skipped → True if the type is not in our tracked set
    """
    stix_type = raw.get("type", "")

    if not stix_type:
        return ValidationResult.fail("missing 'type' field")

    validator_class = _VALIDATORS.get(stix_type)
    if validator_class is None:
        return ValidationResult.skip(f"unsupported stix type: {stix_type!r}")

    try:
        validated = validator_class.model_validate(raw)
        # Return as dict — model_dump preserves all fields including x_cti_*
        return ValidationResult.ok(validated.model_dump())
    except ValidationError as exc:
        # Extract first error message for logging
        first_error = exc.errors()[0]
        reason = f"{'.'.join(str(l) for l in first_error['loc'])}: {first_error['msg']}"
        return ValidationResult.fail(reason)
    except Exception as exc:
        return ValidationResult.fail(f"unexpected validation error: {exc}")
