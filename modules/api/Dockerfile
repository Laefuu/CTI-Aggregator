FROM python:3.12-slim

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project
COPY shared/ shared/
COPY modules/api/ modules/api/
COPY modules/llm_normalizer/prompt.py modules/llm_normalizer/prompt.py
COPY modules/llm_normalizer/__init__.py modules/llm_normalizer/__init__.py
RUN uv sync --no-dev

CMD ["uv", "run", "uvicorn", "modules.api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--loop", "uvloop"]
