# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

##### Help message #####
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target> \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

COMPOSE ?= docker-compose

all: build lint test integration

.PHONY: build
build: ## Build go project
	go build ./...

.PHONY: lint 
lint: ## Lint the codebase
	gofmt -l -w .
	go mod tidy
	golangci-lint run -E gosec,asciicheck,bodyclose,gocyclo,unconvert,gocognit,misspell,revive,whitespace --timeout 5m

.PHONY: test
test: ## Run unit tests
	go test -race -count 1 ./...

.PHONY: integration
integration: up ## Run integration tests
	go test -race -count 1 -tags integration ./...
	$(MAKE) down

.PHONY: up
up: ## Start python test server
	$(COMPOSE) -f integration/docker-compose.yml up --build --detach

.PHONY: down
down: ## Stop python test server
	$(COMPOSE) -f integration/docker-compose.yml down -v
