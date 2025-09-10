.PHONY: build require-version release-darwin-arm64 release-linux-amd64 release clean

VERSION ?= dev
BINARY_NAME = certi
RELEASE_DIR = dist
RELEASE_BUILD_FLAGS=-v -ldflags "-w -s -X main.version=$(VERSION)" -trimpath

build:
	go vet ./...
	go build -o $(BINARY_NAME) ./cmd/certi

require-version:
	@if [ "$(VERSION)" = "dev" ]; then \
		echo "VERSION environment variable is required"; \
		exit 1; \
	fi

release-darwin-arm64: require-version
	@echo "############################################################"
	@echo "# Building certi $(VERSION) release binary for darwin-arm64"
	@echo "############################################################"

	rm -rf $(RELEASE_DIR)
	go vet ./...

	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ${RELEASE_BUILD_FLAGS} -o $(RELEASE_DIR)/$(BINARY_NAME) ./cmd/certi

	@echo "📦 packaging certi for darwin-arm64"
	tar -czvf $(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz -C $(RELEASE_DIR) $(BINARY_NAME)

release-linux-amd64: require-version
	@echo "############################################################"
	@echo "# Building certi $(VERSION) release binary for linux-amd64"
	@echo "############################################################"

	rm -rf $(RELEASE_DIR)
	go vet ./...

	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ${RELEASE_BUILD_FLAGS} -o $(RELEASE_DIR)/$(BINARY_NAME) ./cmd/certi

	@echo "📦 packaging certi for linux-amd64"
	tar -czvf $(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(RELEASE_DIR) $(BINARY_NAME)

release: release-darwin-arm64 release-linux-amd64

clean:
	git clean -fd
