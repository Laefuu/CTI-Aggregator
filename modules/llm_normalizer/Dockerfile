FROM python:3.12-slim

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project
COPY shared/ shared/
COPY modules/llm_normalizer/ modules/llm_normalizer/
RUN uv sync --no-dev

# Runs with network_mode: host in docker-compose to reach Ollama on 127.0.0.1
CMD ["uv", "run", "python", "-m", "llm_normalizer"]
