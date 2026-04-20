.DEFAULT_GOAL := help
COMPOSE := docker compose -f infra/docker-compose.yml --env-file .env
MODULE_NAME ?= unknown

# NOTE: docker compose commands auto-negotiate the API version (no pin needed).
# For bare `docker` CLI calls (docker exec, docker ps, etc.), use:
#   DOCKER_API_VERSION=1.43 docker <cmd>
# because the daemon on this host caps at 1.43.

.PHONY: help up down build restart logs migrate migrate-down \
        migrate-status migrate-history migrate-new pull-model \
        run-source test test-unit test-integration test-llm \
        lint fmt audit shell-db shell-redis clean bootstrap-env \
        start stop frontend-install frontend-dev status

# ── Help ──────────────────────────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Infrastructure ────────────────────────────────────────────────────────────

# Docker Compose interpolates ${VAR} from a .env file next to the compose file,
# NOT from --env-file (which only loads vars into container envs). To keep
# interpolation working for raw `docker compose -f infra/docker-compose.yml`
# invocations AND for `make ...`, we symlink infra/.env -> ../.env on bootstrap.
bootstrap-env: ## Ensure infra/.env symlink exists (needed for Compose interpolation)
	@if [ ! -e infra/.env ]; then \
	  echo ">> Creating symlink infra/.env -> ../.env"; \
	  ln -s ../.env infra/.env; \
	fi

up: bootstrap-env ## Start all services
	$(COMPOSE) up -d

# ── One-shot launcher ────────────────────────────────────────────────────────
# Everything runs in Docker — backend + frontend.
# `make start` is an alias for `make up`.

start: up ## Start everything — backend + frontend (all in Docker)
	@echo ""
	@echo "========================================"
	@echo "  Frontend : http://localhost:5173"
	@echo "  API      : http://localhost:8000"
	@echo "========================================"

stop: down ## Stop all containers

status: ## Show all container status
	@$(COMPOSE) ps

frontend-dev: ## Start Vite dev server locally (hot-reload for frontend dev)
	@if [ ! -d frontend/node_modules ]; then cd frontend && npm install; fi
	@cd frontend && npm run dev

frontend-build: ## Rebuild only the frontend Docker image
	$(COMPOSE) build frontend

up-infra: bootstrap-env ## Start infrastructure only (postgres, redis, ollama, nginx)
	$(COMPOSE) up -d postgres redis ollama nginx

down: ## Stop all services
	$(COMPOSE) down

down-volumes: ## Stop all services and remove volumes (DESTRUCTIVE)
	$(COMPOSE) down -v

build: bootstrap-env ## Rebuild all service images
	$(COMPOSE) build

build-no-cache: bootstrap-env ## Rebuild all images without cache
	$(COMPOSE) build --no-cache

restart: bootstrap-env ## Restart all services
	$(COMPOSE) restart

logs: ## Stream logs from all services
	$(COMPOSE) logs -f --tail=100

logs-%: ## Stream logs from a specific service (e.g. make logs-collector)
	$(COMPOSE) logs -f --tail=100 $*

ps: ## Show service status
	$(COMPOSE) ps

# ── Database ──────────────────────────────────────────────────────────────────

# Alembic runs inside the store container so it can reach postgres on cti-net
ALEMBIC := $(COMPOSE) run --rm store uv run alembic -c modules/store/alembic.ini

migrate: ## Apply all pending Alembic migrations (requires infra running)
	$(ALEMBIC) upgrade head

migrate-down: ## Rollback last migration
	$(ALEMBIC) downgrade -1

migrate-status: ## Show migration status
	$(ALEMBIC) current

migrate-history: ## Show full migration history
	$(ALEMBIC) history --verbose

migrate-new: ## Create a new migration file (MSG="description")
ifndef MSG
	$(error MSG is required. Usage: make migrate-new MSG="add column foo")
endif
	$(ALEMBIC) revision -m "$(MSG)"

shell-db: ## Open a psql shell
	$(COMPOSE) exec postgres psql -U cti -d cti

# ── Redis ─────────────────────────────────────────────────────────────────────

shell-redis: ## Open a redis-cli shell
	@REDIS_PASSWORD=$$(grep '^REDIS_PASSWORD=' .env | cut -d= -f2) && \
	$(COMPOSE) exec redis redis-cli -a $$REDIS_PASSWORD

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
	$(COMPOSE) exec api python -m modules.api.bootstrap --email $(EMAIL) --password $(PASSWORD)

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean: ## Remove Python cache files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

clean-dist: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info/
