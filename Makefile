.PHONY: all build build-web test run clean docker-build

all: build-web build

build-web:
	@echo "==> Building frontend web assets..."
	@cd web && npm install && npm run build

build:
	@echo "==> Compiling ky_server_base binary..."
	@go build -o ky_server_base ./cmd/server

test:
	@echo "==> Running test suite..."
	@go test -v ./...

run: build
	@./ky_server_base

docker-build:
	@docker build -t ky_server_base .

clean:
	@rm -rf ky_server_base web/dist web/node_modules data/ backups/
