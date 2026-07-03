# Makefile for FlowGuard Lite
# Supports both native local execution and Dockerized workflows.

.PHONY: all setup build test lint dev clean docker-build docker-up docker-test docker-export

# Default target
all: build

# 1. Setup local Git exclusions for private developer workspace files
setup:
	@echo "Configuring local developer exclusions in .git/info/exclude..."
	@grep -qxF '.local/' .git/info/exclude || echo '.local/' >> .git/info/exclude
	@grep -qxF 'scratch/' .git/info/exclude || echo 'scratch/' >> .git/info/exclude
	@echo "Local developer exclusions configured successfully."
	@echo "Checking git status..."
	@git status --porcelain

# 2. Native compile and run targets
build:
	@echo "Building Go backend natively..."
	go build -o bin/flowguard ./cmd/flowguard

test:
	@echo "Running native Go tests..."
	go test -v -race ./...

lint:
	@echo "Running native code formatting and validation check..."
	go fmt ./...
	go vet ./...

dev:
	@echo "Running Go backend natively in development mode..."
	go run ./cmd/flowguard -config config.yaml

clean:
	@echo "Cleaning native build artifacts..."
	rm -rf bin/
	rm -rf dist/

# 3. Docker workflow targets
docker-build:
	@echo "Building production multi-stage Docker image..."
	docker build -t flowguard:latest -f deploy/Dockerfile .

docker-up:
	@echo "Starting development containers via Docker Compose..."
	docker compose -f deploy/docker-compose.yml up --build

docker-test:
	@echo "Running tests in a containerized environment..."
	docker run --rm flowguard:latest go test -v ./...

docker-export:
	@echo "Exporting production Docker image to tar archive..."
	@mkdir -p dist
	docker save -o dist/flowguard-image.tar flowguard:latest
	@echo "Image successfully exported to dist/flowguard-image.tar"
