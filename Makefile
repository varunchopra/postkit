.PHONY: setup build test test-authz test-authn dev release clean

PG_VERSION ?= 16
PG_CONTAINER = postkit-test
PG_PORT = 5433
DATABASE_URL = postgresql://postgres:postgres@localhost:$(PG_PORT)/postgres
PYTEST = uv run --with pytest --with 'psycopg[binary]' pytest

GREEN = \033[0;32m
NC = \033[0m

setup:
	@echo "Starting Postgres $(PG_VERSION)..."
	@docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_PASSWORD=postgres \
		-p $(PG_PORT):5432 \
		postgres:$(PG_VERSION) > /dev/null
	@echo "Waiting for Postgres..."
	@sleep 3
	@until docker exec $(PG_CONTAINER) pg_isready -q; do sleep 1; done
	@echo "$(GREEN) Postgres $(PG_VERSION) ready$(NC)"

build:
	@mkdir -p dist
	@./scripts/build.sh > dist/postkit.sql
	@./scripts/build.sh authz > dist/authz.sql
	@./scripts/build.sh authn > dist/authn.sql
	@echo "$(GREEN) Built dist/postkit.sql, dist/authz.sql, dist/authn.sql$(NC)"

test: build
ifdef TEST
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -q -v $(TEST)
else
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -q -v authz/tests/ authn/tests/
endif

test-authz: build
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -q -v authz/tests/

test-authn: build
	@DATABASE_URL=$(DATABASE_URL) $(PYTEST) -q -v authn/tests/

dev: build test
	@echo "$(GREEN) Build and tests passed$(NC)"

release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.0.0)
endif
	@echo "Releasing v$(VERSION)..."
	@make build
	@make test
	@echo "$(GREEN) Ready to release$(NC)"
	@echo ""
	@echo "Next steps:"
	@echo "  git tag v$(VERSION) && git push --tags"

clean:
	@docker rm -f $(PG_CONTAINER) 2>/dev/null || true
	@rm -rf dist/
	@echo "$(GREEN) Cleaned up$(NC)"
