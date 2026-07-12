.PHONY: all setup build test clean docs lint format

PG_VERSION ?= 16
PG_IMAGE ?= pgvector/pgvector:pg$(PG_VERSION)
PG_CONTAINER ?= postkit-test
PG_PORT ?= 5433
DATABASE_URL ?= postgresql://postgres:postgres@localhost:$(PG_PORT)/postgres
PYTEST = cd sdk && uv run --extra dev pytest

RED = \033[0;31m
GREEN = \033[0;32m
NC = \033[0m

all: build format lint docs test

db:
	@image=$$(docker inspect -f '{{.Config.Image}}' $(PG_CONTAINER) 2>/dev/null); \
	if [ -n "$$image" ] && [ "$$image" != "$(PG_IMAGE)" ]; then \
		echo "Recreating $(PG_CONTAINER): $$image is not $(PG_IMAGE)"; \
		docker rm -f $(PG_CONTAINER) > /dev/null; \
	fi
	@nc -z localhost $(PG_PORT) 2>/dev/null || \
		(docker start $(PG_CONTAINER) 2>/dev/null || make setup)

setup:
	@echo "Starting Postgres $(PG_VERSION)..."
	@docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_PASSWORD=postgres \
		-p $(PG_PORT):5432 \
		$(PG_IMAGE) \
		-c max_prepared_transactions=5 > /dev/null
	@echo "Waiting for Postgres..."
	@sleep 3
	@until docker exec $(PG_CONTAINER) pg_isready -q; do sleep 1; done
	@echo "$(GREEN)✓ Postgres $(PG_VERSION) ready$(NC)"

build:
	@mkdir -p dist
	@./scripts/build.sh > dist/postkit.sql
	@./scripts/build.sh authz > dist/authz.sql
	@./scripts/build.sh authn > dist/authn.sql
	@./scripts/build.sh config > dist/config.sql
	@./scripts/build.sh lease > dist/lease.sql
	@./scripts/build.sh memory > dist/memory.sql
	@./scripts/build.sh meter > dist/meter.sql
	@./scripts/build.sh outbox > dist/outbox.sql
	@./scripts/build.sh presence > dist/presence.sql
	@./scripts/build.sh queue > dist/queue.sql
	@echo "$(GREEN)✓ Built dist/*.sql$(NC)"

test: db build
ifdef TEST
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -v -p randomly $(TEST)
else
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -v -p randomly -n auto --dist loadgroup --ignore=tests/integration
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -v -p randomly tests/integration
	@cd scripts && uv run --with pglast --with pytest pytest gendocs/
endif

docs:
	@cd scripts && uv run --with pglast --with 'psycopg[binary]' --with jsonschema python -m gendocs.cli
	@echo "$(GREEN)✓ Generated docs$(NC)"

clean:
	@docker rm -f $(PG_CONTAINER) 2>/dev/null || true
	@rm -rf dist/ sdk/dist/ sdk/.venv .venv
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned up$(NC)"

lint:
	@uvx ruff check .
	@uvx --with 'psycopg[binary]' --with jsonschema ty check sdk/src/
	@if git grep -nI "$$(printf '\342\200\224')"; then echo "$(RED)em dashes found: use ' - '$(NC)"; exit 1; fi
	@echo "$(GREEN)✓ Lint passed$(NC)"

format:
	@uvx ruff check --fix .
	@uvx ruff check --select I --fix .
	@uvx ruff format .
	@echo "$(GREEN)✓ Formatted$(NC)"
