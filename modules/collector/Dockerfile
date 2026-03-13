FROM python:3.12-slim

# System dependencies for OCR and PDF processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-fra \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies (without dev extras)
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project

# Copy source
COPY shared/ shared/
COPY modules/collector/ modules/collector/

# Install the project itself
RUN uv sync --no-dev

CMD ["uv", "run", "python", "-m", "collector"]
