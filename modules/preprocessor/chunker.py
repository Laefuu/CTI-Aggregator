"""
Chunker — splits extracted text into overlapping chunks for LLM inference.

Uses LangChain's RecursiveCharacterTextSplitter with tiktoken token counting.
Chunk size and overlap are controlled by settings:
    CHUNK_MAX_TOKENS    (default: 3000)
    CHUNK_OVERLAP_TOKENS (default: 200)

Why recursive splitter?
    Tries to split on paragraph boundaries first, then sentences, then words.
    This preserves context better than a fixed-size token window.
"""
from __future__ import annotations

import structlog
from langchain_text_splitters import RecursiveCharacterTextSplitter

from shared.config import get_settings

log = structlog.get_logger()


def chunk_text(text: str) -> list[str]:
    """
    Split text into chunks suitable for LLM inference.

    Returns a list of non-empty text chunks.
    Returns empty list if text is too short (below MIN_CONTENT_WORDS).
    """
    settings = get_settings()

    # Word count filter — applied before chunking
    word_count = len(text.split())
    if word_count < settings.min_content_words:
        log.debug("chunker_text_too_short", word_count=word_count, minimum=settings.min_content_words)
        return []

    splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        model_name="gpt-3.5-turbo",   # tiktoken model for token counting (not the inference model)
        chunk_size=settings.chunk_max_tokens,
        chunk_overlap=settings.chunk_overlap_tokens,
        separators=["\n\n", "\n", ". ", "! ", "? ", " ", ""],
    )

    chunks = splitter.split_text(text)

    # Filter out empty or near-empty chunks
    chunks = [c.strip() for c in chunks if c.strip() and len(c.split()) >= 10]

    log.debug(
        "chunker_split",
        word_count=word_count,
        chunk_count=len(chunks),
        max_tokens=settings.chunk_max_tokens,
    )
    return chunks
