"""Bootstrap CLI — creates the first admin user."""
from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import text

from modules.api.auth import hash_password
from shared.db import close_engine, get_session
from shared.logging import configure_logging


async def create_user(email: str, password: str) -> None:
    async with get_session() as session:
        existing = await session.execute(
            text("SELECT id FROM users WHERE email = :email"), {"email": email}
        )
        if existing.first():
            print(f"User {email} already exists.")
            return
        await session.execute(
            text("INSERT INTO users (email, password_hash) VALUES (:email, :hash)"),
            {"email": email, "hash": hash_password(password)},
        )
        await session.commit()
        print(f"User {email} created successfully.")


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    asyncio.run(create_user(args.email, args.password))
    asyncio.run(close_engine())


if __name__ == "__main__":
    main()
