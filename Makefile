.DEFAULT_GOAL := help
COMPOSE := docker compose -f infra/docker-compose.yml
MODULE_NAME ?= unknown

.PHONY: help up down build restart logs migrate pull-model \
        run-source test test-unit test-integration test-llm \
        lint fmt audit shell-db shell-redis clean

# ── Help ──────────────────────────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Infrastructure ────────────────────────────────────────────────────────────

up: ## Start all services
	$(COMPOSE) up -d

up-infra: ## Start infrastructure only (postgres, redis, ollama, nginx)
	$(COMPOSE) up -d postgres redis ollama nginx

down: ## Stop all services
	$(COMPOSE) down

down-volumes: ## Stop all services and remove volumes (DESTRUCTIVE)
	$(COMPOSE) down -v

build: ## Rebuild all service images
	$(COMPOSE) build

build-no-cache: ## Rebuild all images without cache
	$(COMPOSE) build --no-cache

restart: ## Restart all services
	$(COMPOSE) restart

logs: ## Stream logs from all services
	$(COMPOSE) logs -f --tail=100

logs-%: ## Stream logs from a specific service (e.g. make logs-collector)
	$(COMPOSE) logs -f --tail=100 $*

ps: ## Show service status
	$(COMPOSE) ps

# ── Database ──────────────────────────────────────────────────────────────────

migrate: ## Apply all pending Alembic migrations
	$(COMPOSE) exec api alembic upgrade head

migrate-down: ## Rollback last migration
	$(COMPOSE) exec api alembic downgrade -1

migrate-status: ## Show migration status
	$(COMPOSE) exec api alembic current

migrate-history: ## Show full migration history
	$(COMPOSE) exec api alembic history --verbose

shell-db: ## Open a psql shell
	$(COMPOSE) exec postgres psql -U cti -d cti

# ── Redis ─────────────────────────────────────────────────────────────────────

shell-redis: ## Open a redis-cli shell
	$(COMPOSE) exec redis redis-cli -a $${REDIS_PASSWORD}

streams: ## Show all Redis stream lengths
	$(COMPOSE) exec redis redis-cli -a $${REDIS_PASSWORD} \
	  KEYS "cti:*" | xargs -I{} sh -c \
	  'echo -n "{}: "; docker compose -f infra/docker-compose.yml exec redis redis-cli -a $${REDIS_PASSWORD} XLEN {}'

# ── LLM ───────────────────────────────────────────────────────────────────────

pull-model: ## Pull the primary LLM model (llama3.3:70b-instruct-q4_K_M)
	$(COMPOSE) exec ollama ollama pull llama3.3:70b-instruct-q4_K_M

pull-model-fallback: ## Pull the fallback LLM model (mistral:7b-instruct-q4_K_M)
	$(COMPOSE) exec ollama ollama pull mistral:7b-instruct-q4_K_M

list-models: ## List available Ollama models
	$(COMPOSE) exec ollama ollama list

benchmark-llm: ## Run LLM latency benchmark and save results
	$(COMPOSE) exec llm-normalizer python -m llm_normalizer.benchmark

# ── Sources ───────────────────────────────────────────────────────────────────

run-source: ## Force immediate collection of a source (SOURCE_ID=<uuid>)
ifndef SOURCE_ID
	$(error SOURCE_ID is required. Usage: make run-source SOURCE_ID=<uuid>)
endif
	$(COMPOSE) exec collector python -m collector.run_once --source-id $(SOURCE_ID)

# ── Tests ─────────────────────────────────────────────────────────────────────

test: ## Run unit and integration tests
	uv run pytest tests/unit tests/integration -m "not slow"

test-unit: ## Run unit tests only (no I/O)
	uv run pytest tests/unit -m unit -v

test-integration: ## Run integration tests (requires running postgres + redis)
	uv run pytest tests/integration -m integration -v

test-llm: ## Run LLM quality evaluation on golden dataset (slow)
	uv run pytest tests/golden_dataset -m slow -v -s

test-cov: ## Run tests with coverage report
	uv run pytest tests/unit tests/integration --cov --cov-report=term-missing

# ── Code quality ──────────────────────────────────────────────────────────────

lint: ## Run ruff check + mypy
	uv run ruff check .
	uv run mypy --strict modules/ shared/

fmt: ## Format code with ruff
	uv run ruff format .
	uv run ruff check --fix .

fmt-check: ## Check formatting without modifying files
	uv run ruff format --check .

audit: ## Run security audit on dependencies
	uv run pip-audit
	uv run safety check

# ── Bootstrap ─────────────────────────────────────────────────────────────────

bootstrap-admin: ## Create the first admin user (EMAIL and PASSWORD required)
ifndef EMAIL
	$(error EMAIL is required. Usage: make bootstrap-admin EMAIL=admin@org.internal PASSWORD=secret)
endif
ifndef PASSWORD
	$(error PASSWORD is required. Usage: make bootstrap-admin EMAIL=admin@org.internal PASSWORD=secret)
endif
	$(COMPOSE) exec api python -m api.bootstrap --email $(EMAIL) --password $(PASSWORD)

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean: ## Remove Python cache files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

clean-dist: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info/
