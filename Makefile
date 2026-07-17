# Makefile for FlowGuard Lite
# Supports both native local execution and Dockerized workflows.

.PHONY: all setup generate build test lint dev clean product-test frontend-gate pre-release-gate docker-build docker-up docker-test docker-ui-test docker-ui-smoke docker-capture-config docker-export ui-dev ui-build ui-lint ui-check ui-cypress-open benchmark-run docker-benchmark-run benchmark-matrix benchmark-smoke

-include .env
export

CYPRESS_DOCKER_IMAGE ?= cypress/included:13.17.0
CYPRESS_BASE_URL ?= http://127.0.0.1:5173
CYPRESS_BROWSER ?= electron
CYPRESS_WAIT_TIMEOUT_SECONDS ?= 60

# Default target
all: generate build

# 1. Setup local Git exclusions for private developer workspace files
setup:
	@echo "Configuring local developer exclusions in .git/info/exclude..."
	@mkdir -p .git/info
	@grep -qxF '.local/' .git/info/exclude || echo '.local/' >> .git/info/exclude
	@grep -qxF 'scratch/' .git/info/exclude || echo 'scratch/' >> .git/info/exclude
	@echo "Local developer exclusions configured successfully."
	@echo "Checking git status..."
	@git status --porcelain

# 2. Native compile and run targets
generate:
	@echo "Generating configuration JSON schema validation assets..."
	go generate ./...

build:
	@echo "Building Go backend natively..."
	go build -tags production -o bin/flowguard ./cmd/flowguard

test:
	@echo "Running native Go product tests..."
	go test -v -race ./cmd/... ./internal/...

lint:
	@echo "Running native code formatting and validation check..."
	go fmt ./cmd/... ./internal/...
	go vet ./cmd/... ./internal/...

dev:
	@echo "Running Go backend natively in development mode..."
	@test -f config-dev.yaml || (echo "config-dev.yaml is missing. Run: cp config.example.yaml config-dev.yaml" && exit 1)
	go run -tags !production ./cmd/flowguard -config config-dev.yaml

clean:
	@echo "Cleaning native build artifacts..."
	rm -rf bin/
	rm -rf dist/

product-test:
	@echo "Running product Go package tests..."
	go test ./cmd/... ./internal/...

frontend-gate: docker-ui-test docker-ui-smoke

pre-release-gate: product-test frontend-gate benchmark-smoke
	@echo "Running repository whitespace check..."
	git diff --check

# 3. Docker workflow targets
docker-build:
	@echo "Building production-ready Docker image..."
	docker build -f deploy/Dockerfile -t flowguard:latest .

docker-up:
	@echo "Starting development containers via Docker Compose..."
	docker compose -f deploy/docker-compose.yml up --build

docker-test:
	@echo "Running tests in a containerized environment..."
	docker run --rm flowguard:latest go test -v ./...

docker-ui-test:
	@echo "Running UI JavaScript compilation checks in Dockerized Node..."
	@test -n "$(NODE_DOCKER_IMAGE)" || (echo "NODE_DOCKER_IMAGE is not set. Copy .env.example to .env or export NODE_DOCKER_IMAGE." && exit 1)
	docker run --rm -v "$(PWD):/work" -w /work $(NODE_DOCKER_IMAGE) sh -c "cd web && npm install && npm run build && npm run lint"

docker-ui-smoke:
	@echo "Running Cypress UI smoke/regression tests in Docker..."
	@docker run --rm \
		-v "$(PWD):/work" \
		-w /work/web \
		-e CYPRESS_BASE_URL="$(CYPRESS_BASE_URL)" \
		-e CYPRESS_WAIT_TIMEOUT_SECONDS="$(CYPRESS_WAIT_TIMEOUT_SECONDS)" \
		--entrypoint sh \
		$(CYPRESS_DOCKER_IMAGE) \
		-lc '\
			set -eu; \
			npm install; \
			npm run dev -- --host 0.0.0.0 --force > /tmp/flowguard-vite.log 2>&1 & \
			vite_pid=$$!; \
			trap "kill $$vite_pid 2>/dev/null || true" EXIT; \
			if ! node -e '"'"' \
				const url = process.env.CYPRESS_BASE_URL || "http://127.0.0.1:5173"; \
				const timeoutMs = Number(process.env.CYPRESS_WAIT_TIMEOUT_SECONDS || 60) * 1000; \
				const startedAt = Date.now(); \
				function waitForServer() { \
					fetch(url) \
						.then(() => process.exit(0)) \
						.catch(() => { \
							if (Date.now() - startedAt >= timeoutMs) { \
								console.error("Timed out waiting for " + url); \
								process.exit(1); \
							} \
							setTimeout(waitForServer, 1000); \
						}); \
				} \
				waitForServer(); \
			'"'"'; then \
				echo "Vite did not become ready. Last Vite logs:"; \
				tail -80 /tmp/flowguard-vite.log || true; \
				exit 1; \
			fi; \
			cypress run --browser "$(CYPRESS_BROWSER)" --headless || { echo "Cypress failed. Vite logs:"; cat /tmp/flowguard-vite.log; exit 1; }; \
		'

docker-capture-config:
	@echo "Validating opt-in passive capture Compose configuration..."
	docker compose -f deploy/docker-compose.capture.yml config --quiet

docker-export:
	@echo "Exporting production Docker image to tar archive..."
	@mkdir -p dist
	docker save -o dist/flowguard-image.tar flowguard:latest
	@echo "Image successfully exported to dist/flowguard-image.tar"

# 4. Performance & Benchmark Targets
benchmark-run:
	@echo "Running local performance benchmarks and generating reports..."
	go run cmd/benchrunner/main.go

docker-benchmark-run:
	@echo "Running containerized benchmarks via Docker Compose..."
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-1c-2g

benchmark-matrix:
	@echo "Running performance benchmarks across 1 CPU and 2 CPU configurations for 2GB, 4GB, and 8GB RAM profiles..."
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-1c-2g
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-1c-4g
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-1c-8g
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-2c-2g
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-2c-4g
	docker compose -f deploy/docker-compose.benchmark.yml run --rm benchmark-2c-8g

benchmark-smoke:
	@echo "Running lightweight performance smoke test..."
	go test -v -run=TestPerformanceRegressionSmoke ./internal/benchmark

# 5. Vite Frontend Development Targets
ui-dev:
	@echo "Starting Vite development server..."
	cd web && npm install && npm run dev

ui-build:
	@echo "Building Vite production assets..."
	cd web && npm install && npm run build

ui-lint:
	@echo "Running frontend lint natively..."
	cd web && npm install && npm run lint

ui-check: ui-build ui-lint

ui-cypress-open:
	@echo "Opening Cypress interactively against an already running Vite app..."
	cd web && npm install && CYPRESS_BASE_URL="$(CYPRESS_BASE_URL)" npx cypress open
