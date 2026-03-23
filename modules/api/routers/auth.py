"""POST /auth/login — issue JWT. GET /auth/me — current user."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from modules.api.auth import create_access_token, verify_password
from modules.api.deps import get_current_user, get_db
from modules.api.schemas.auth import LoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    result = await db.execute(
        text("SELECT id::text, password_hash, is_active FROM users WHERE email = :email"),
        {"email": body.email},
    )
    row = result.mappings().first()

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    await db.execute(
        text("UPDATE users SET last_login = NOW() WHERE id = CAST(:id AS uuid)"), {"id": row["id"]}
    )
    await db.commit()

    token, expires_in = create_access_token(row["id"], body.email)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.get("/me", response_model=UserResponse)
async def me(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    result = await db.execute(
        text("SELECT id::text, email, is_active FROM users WHERE id = CAST(:id AS uuid)"),
        {"id": current_user["sub"]},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(**dict(row))
