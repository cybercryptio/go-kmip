# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

##### Help message #####
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target> \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

COMPOSE ?= docker-compose

all: build lint up test down

.PHONY: build
build: ## Build go project
	go build ./...

.PHONY: lint 
lint: ## Lint the codebase
	gofmt -l -w .
	go mod tidy
	golangci-lint run

.PHONY: test
test: ## Run tests
	go test -v -race -coverprofile=coverage.txt -covermode=atomic -count 1 ./...

.PHONY: up
up: ## Start python test server
	$(COMPOSE) build --pull pykmip-server
	$(COMPOSE) run --rm dependencies

.PHONY: down
down: ## Stop python test server
	$(COMPOSE) down -v --remove-orphans
