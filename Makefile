# Makefile for OWASP Scanner

VERSION ?= 1.0.0
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)

# Binary names
BINARY_NAME := owasp-scanner
BUILD_DIR := build

# Platforms to build for
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all clean build build-all test docker-build docker-run help

all: clean build

help:
	@echo "Available targets:"
	@echo "  build        - Build for current platform"
	@echo "  build-all    - Build for all platforms"
	@echo "  test         - Run tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  install      - Install binary to /usr/local/bin"

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/owasp-scanner
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@$(foreach platform,$(PLATFORMS), \
		export GOOS=$(word 1,$(subst /, ,$(platform))); \
		export GOARCH=$(word 2,$(subst /, ,$(platform))); \
		export OUTPUT=$(BUILD_DIR)/$(BINARY_NAME)-$GOOS-$GOARCH; \
		if [ "$GOOS" = "windows" ]; then export OUTPUT=$OUTPUT.exe; fi; \
		echo "Building $OUTPUT..."; \
		CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $OUTPUT ./cmd/owasp-scanner ; \
	)
	@echo "All binaries built in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

test:
	@echo "Running tests..."
	go test -v ./...

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

docker-build:
	@echo "Building Docker image..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		.

docker-build-local:
	@echo "Building Docker image for local platform..."
	docker build -t $(BINARY_NAME):latest .

docker-run:
	@echo "Running Docker container..."
	docker run --rm -it \
		-v $(PWD)/payloads:/app/payloads \
		-v $(PWD)/reports:/app/reports \
		$(BINARY_NAME):latest

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete"

# Development helpers
dev-run:
	go run ./cmd/owasp-scanner --help

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/releases
	@cd $(BUILD_DIR) && \
	for binary in owasp-scanner-*; do \
		if [[ $$binary == *.exe ]]; then \
			platform=$${binary%.exe}; \
			platform=$${platform#owasp-scanner-}; \
			zip releases/owasp-scanner-$$platform-$(VERSION).zip $$binary; \
		else \
			platform=$${binary#owasp-scanner-}; \
			tar czf releases/owasp-scanner-$$platform-$(VERSION).tar.gz $$binary; \
		fi; \
	done
	@echo "Release archives created in $(BUILD_DIR)/releases/"
	@ls -lh $(BUILD_DIR)/releases/