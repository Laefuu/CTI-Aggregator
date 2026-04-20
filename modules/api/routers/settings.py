"""GET/PUT /settings/llm-prompt — read and update the LLM system prompt."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.deps import get_current_user, get_db
from modules.llm_normalizer.prompt import SYSTEM_PROMPT

router = APIRouter(prefix="/settings", tags=["settings"])

_PROMPT_KEY = "llm_system_prompt"


class LLMPromptResponse(BaseModel):
    prompt: str
    is_default: bool


class LLMPromptUpdate(BaseModel):
    prompt: str


@router.get("/llm-prompt", response_model=LLMPromptResponse)
async def get_llm_prompt(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> LLMPromptResponse:
    result = await db.execute(
        text("SELECT value FROM settings WHERE key = :key"),
        {"key": _PROMPT_KEY},
    )
    row = result.scalar()
    if row:
        return LLMPromptResponse(prompt=row, is_default=False)
    return LLMPromptResponse(prompt=SYSTEM_PROMPT, is_default=True)


@router.put("/llm-prompt", response_model=LLMPromptResponse)
async def update_llm_prompt(
    body: LLMPromptUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> LLMPromptResponse:
    await db.execute(
        text("""
            INSERT INTO settings (key, value)
            VALUES (:key, :value)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """),
        {"key": _PROMPT_KEY, "value": body.prompt},
    )
    await db.commit()
    return LLMPromptResponse(prompt=body.prompt, is_default=False)


@router.delete("/llm-prompt", response_model=LLMPromptResponse)
async def reset_llm_prompt(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
) -> LLMPromptResponse:
    """Reset the LLM prompt to the built-in default."""
    await db.execute(
        text("DELETE FROM settings WHERE key = :key"),
        {"key": _PROMPT_KEY},
    )
    await db.commit()
    return LLMPromptResponse(prompt=SYSTEM_PROMPT, is_default=True)
