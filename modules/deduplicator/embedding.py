"""
Embedding generation using BAAI/bge-m3 via sentence-transformers.

Model: BAAI/bge-m3
  - 1024 dimensions
  - Multilingual (100+ languages)
  - Runs on CPU (no GPU required for inference)
  - ~570MB download on first use

The model is loaded once at module level and reused across all calls.
Loading is lazy — triggered on first embed() call.
"""
from __future__ import annotations

import structlog
import numpy as np

log = structlog.get_logger()

_MODEL_NAME = "BAAI/bge-m3"
_model = None


def _get_model():
    global _model
    if _model is None:
        log.info("embedding_model_loading", model=_MODEL_NAME)
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(_MODEL_NAME)
        log.info("embedding_model_loaded", model=_MODEL_NAME)
    return _model


def embed(text: str) -> list[float]:
    """
    Generate a 1024-dimensional embedding for the given text.

    The text should be the STIX object's name + pattern for indicators,
    or name + description for threat-actors and attack-patterns.
    """
    model = _get_model()
    # bge-m3 recommends no instruction prefix for symmetric similarity
    vector = model.encode(text, normalize_embeddings=True)
    # encode() returns ndarray in production, but tests may mock it as a plain list
    if hasattr(vector, 'tolist'):
        return vector.tolist()
    return list(vector)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """
    Compute cosine similarity between two normalized vectors.
    Since bge-m3 returns normalized embeddings, this is just the dot product.
    """
    va = np.array(a, dtype=np.float32)
    vb = np.array(b, dtype=np.float32)
    return float(np.dot(va, vb))


def text_for_embedding(stix_obj: dict) -> str:
    """
    Build the text to embed for a STIX object.

    Combines the most semantically distinctive fields per type.
    """
    stix_type = stix_obj.get("type", "")
    name = stix_obj.get("name", "")

    match stix_type:
        case "indicator":
            pattern = stix_obj.get("pattern", "")
            description = stix_obj.get("description", "")
            return f"{name} {pattern} {description}".strip()
        case "threat-actor":
            aliases = " ".join(stix_obj.get("aliases", []))
            description = stix_obj.get("description", "")
            return f"{name} {aliases} {description}".strip()
        case "attack-pattern":
            mitre_id = stix_obj.get("x_mitre_id", "")
            description = stix_obj.get("description", "")
            return f"{name} {mitre_id} {description}".strip()
        case "relationship":
            rel_type = stix_obj.get("relationship_type", "")
            source = stix_obj.get("source_ref", "")
            target = stix_obj.get("target_ref", "")
            return f"relationship {rel_type} {source} {target}".strip()
        case _:
            return name
