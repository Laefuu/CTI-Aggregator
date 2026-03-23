FROM python:3.12-slim

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project
COPY shared/ shared/
COPY modules/deduplicator/ modules/deduplicator/
RUN uv sync --no-dev

# Pre-download the bge-m3 model during image build (not on first request)
# RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-m3')"

CMD ["uv", "run", "python", "-m", "modules.deduplicator"]
