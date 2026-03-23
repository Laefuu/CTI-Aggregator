FROM python:3.12-slim

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project
COPY shared/ shared/
COPY modules/validator/ modules/validator/
RUN uv sync --no-dev

CMD ["uv", "run", "python", "-m", "modules.validator"]
