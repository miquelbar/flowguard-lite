# Makefile for FlowGuard Lite
# Supports both native local execution and Dockerized workflows.

.PHONY: all setup generate build test lint dev clean docker-build docker-up docker-test docker-ui-test docker-export

-include .env
export

# Default target
all: generate build

# 1. Setup local Git exclusions for private developer workspace files
setup:
	@echo "Configuring local developer exclusions in .git/info/exclude..."
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
	@echo "Running native Go tests..."
	go test -v -race ./...

lint:
	@echo "Running native code formatting and validation check..."
	go fmt ./...
	go vet ./...

dev:
	@echo "Running Go backend natively in development mode..."
	go run -tags !production ./cmd/flowguard -config config.yaml

clean:
	@echo "Cleaning native build artifacts..."
	rm -rf bin/
	rm -rf dist/

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

docker-export:
	@echo "Exporting production Docker image to tar archive..."
	@mkdir -p dist
	docker save -o dist/flowguard-image.tar flowguard:latest
	@echo "Image successfully exported to dist/flowguard-image.tar"

# 4. Vite Frontend Development Targets
ui-dev:
	@echo "Starting Vite development server..."
	cd web && npm install && npm run dev

ui-build:
	@echo "Building Vite production assets..."
	cd web && npm install && npm run build
