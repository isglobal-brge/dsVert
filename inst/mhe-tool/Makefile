# Makefile for mhe-tool
# Builds binaries for all supported platforms

BINARY_NAME = mhe-tool
VERSION = 1.8.0

# Output directories
BIN_DIR = ../bin
LINUX_AMD64_DIR = $(BIN_DIR)/linux-amd64
DARWIN_AMD64_DIR = $(BIN_DIR)/darwin-amd64
DARWIN_ARM64_DIR = $(BIN_DIR)/darwin-arm64
WINDOWS_AMD64_DIR = $(BIN_DIR)/windows-amd64

# Go build flags
GO_FLAGS = -ldflags="-s -w"

.PHONY: all clean deps linux darwin-amd64 darwin-arm64 windows

all: deps linux darwin-amd64 darwin-arm64 windows
	@echo "Build complete! Binaries in $(BIN_DIR)/"

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

linux:
	@echo "Building for Linux (amd64)..."
	@mkdir -p $(LINUX_AMD64_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GO_FLAGS) -o $(LINUX_AMD64_DIR)/$(BINARY_NAME) .

darwin-amd64:
	@echo "Building for macOS (amd64)..."
	@mkdir -p $(DARWIN_AMD64_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(GO_FLAGS) -o $(DARWIN_AMD64_DIR)/$(BINARY_NAME) .

darwin-arm64:
	@echo "Building for macOS (arm64)..."
	@mkdir -p $(DARWIN_ARM64_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(GO_FLAGS) -o $(DARWIN_ARM64_DIR)/$(BINARY_NAME) .

windows:
	@echo "Building for Windows (amd64)..."
	@mkdir -p $(WINDOWS_AMD64_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GO_FLAGS) -o $(WINDOWS_AMD64_DIR)/$(BINARY_NAME).exe .

# Build for current platform only (for development)
dev:
	@echo "Building for current platform..."
	go build $(GO_FLAGS) -o $(BINARY_NAME) .

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
	go build -o /dev/null .
	@echo "Build verification successful!"
