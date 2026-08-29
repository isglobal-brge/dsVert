# Makefile for dsvert-mpc
# Builds binaries for all supported platforms

BINARY_NAME = dsvert-mpc
VERSION ?= 1.2.0
override GO_VERSION_REQUIRED := go1.25.7

# Output directories
BIN_DIR = ../bin
LINUX_AMD64_DIR = $(BIN_DIR)/linux-amd64
DARWIN_AMD64_DIR = $(BIN_DIR)/darwin-amd64
DARWIN_ARM64_DIR = $(BIN_DIR)/darwin-arm64
WINDOWS_AMD64_DIR = $(BIN_DIR)/windows-amd64

# Reproducible pure-Go release flags. Disabling VCS stamping and the build ID,
# trimming host paths, and injecting only the declared package version makes
# identical source/module inputs produce identical binaries under one Go
# toolchain and target environment.
GO_LDFLAGS = -s -w -buildid= -X main.runtimeVersion=$(VERSION)
GO_FLAGS = -trimpath -buildvcs=false -ldflags="$(GO_LDFLAGS)"
GO_ENV = CGO_ENABLED=0

.PHONY: all clean check-go-version deps linux darwin-amd64 darwin-arm64 windows checksums

all: checksums
	@echo "Build complete! Binaries in $(BIN_DIR)/"

check-go-version:
	@actual="$$(go env GOVERSION 2>/dev/null || true)"; \
	if [ "$$actual" != "$(GO_VERSION_REQUIRED)" ]; then \
		echo "dsvert-mpc release build requires exactly $(GO_VERSION_REQUIRED); found $${actual:-unavailable}" >&2; \
		exit 1; \
	fi

deps: check-go-version
	@echo "Downloading dependencies..."
	go mod download
	go mod verify

linux: deps
	@echo "Building for Linux (amd64)..."
	@mkdir -p $(LINUX_AMD64_DIR)
	$(GO_ENV) GOOS=linux GOARCH=amd64 go build $(GO_FLAGS) -o $(LINUX_AMD64_DIR)/$(BINARY_NAME) .

darwin-amd64: deps
	@echo "Building for macOS (amd64)..."
	@mkdir -p $(DARWIN_AMD64_DIR)
	$(GO_ENV) GOOS=darwin GOARCH=amd64 go build $(GO_FLAGS) -o $(DARWIN_AMD64_DIR)/$(BINARY_NAME) .

darwin-arm64: deps
	@echo "Building for macOS (arm64)..."
	@mkdir -p $(DARWIN_ARM64_DIR)
	$(GO_ENV) GOOS=darwin GOARCH=arm64 go build $(GO_FLAGS) -o $(DARWIN_ARM64_DIR)/$(BINARY_NAME) .

windows: deps
	@echo "Building for Windows (amd64)..."
	@mkdir -p $(WINDOWS_AMD64_DIR)
	$(GO_ENV) GOOS=windows GOARCH=amd64 go build $(GO_FLAGS) -o $(WINDOWS_AMD64_DIR)/$(BINARY_NAME).exe .

checksums: linux darwin-amd64 darwin-arm64 windows
	@set -eu; \
	if command -v sha256sum >/dev/null 2>&1; then \
		checksum="sha256sum"; \
	elif command -v shasum >/dev/null 2>&1; then \
		checksum="shasum -a 256"; \
	else \
		echo "No SHA-256 checksum tool found" >&2; exit 1; \
	fi; \
	cd "$(BIN_DIR)"; \
	for artifact in \
		darwin-amd64/$(BINARY_NAME) \
		darwin-arm64/$(BINARY_NAME) \
		linux-amd64/$(BINARY_NAME); do \
		test -x "$$artifact" || { \
			echo "Runtime artifact is not executable: $$artifact" >&2; \
			exit 1; \
		}; \
	done; \
	$$checksum \
		darwin-amd64/$(BINARY_NAME) \
		darwin-arm64/$(BINARY_NAME) \
		linux-amd64/$(BINARY_NAME) \
		windows-amd64/$(BINARY_NAME).exe > SHA256SUMS.tmp; \
	mv SHA256SUMS.tmp SHA256SUMS

# Build for current platform only (for development)
dev:
	@echo "Building for current platform..."
	$(GO_ENV) go build $(GO_FLAGS) -o $(BINARY_NAME) .

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe

# Install dependencies and verify
verify: deps
	@echo "Verifying build..."
	$(GO_ENV) go build $(GO_FLAGS) -o /dev/null .
	@echo "Build verification successful!"
