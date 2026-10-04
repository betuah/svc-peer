.PHONY: build test test-integration docker-build compose-up compose-down certs smoke-hub

BIN_DIR := bin
GO ?= go

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/hub ./cmd/hub
	$(GO) build -o $(BIN_DIR)/agent ./cmd/agent
	$(GO) build -o $(BIN_DIR)/relay ./cmd/relay

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./test/integration/...

docker-build:
	docker build -f Dockerfile.hub -t svc-peer-hub:local .
	docker build -f Dockerfile.agent -t svc-peer-agent:local .
	docker build -f Dockerfile.relay -t svc-peer-relay:local .

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

certs:
	./scripts/gen-dev-certs.sh

smoke-hub:
	./scripts/smoke-hub.sh
