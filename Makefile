# Protocol Ward — top-level Makefile
# `make help` for available targets.

SHELL       := bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS   += --no-builtin-rules --no-print-directory
.DEFAULT_GOAL := help

# --- Variables --------------------------------------------------------------

GO                 ?= go
GOFUMPT_VERSION      ?= v0.7.0
GOLANGCI_VERSION     ?= v1.62.2
GOVULNCHECK_VERSION  ?= v1.1.4
GORELEASER_VERSION   ?= v2.16.0

BIN_DIR     := bin
TOOLS_DIR   := .tools
DIST_DIR    := dist
BINARY      := ward
PKG         := ./...
COVER_OUT   := coverage.out
WASM_DIR       := $(DIST_DIR)/wasm
WASM_MAX_BYTES := 5000000

# Project-local tool binaries take precedence over system installs.
export PATH := $(CURDIR)/$(TOOLS_DIR):$(PATH)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X main.version=$(VERSION) \
  -X main.commit=$(COMMIT) \
  -X main.date=$(DATE)

# Verbosity: `make <target> V=1` shows full commands.
V ?= 0
ifeq ($(V),1)
  Q :=
else
  Q := @
endif

# Color helpers (TTY-only).
ifneq (,$(findstring xterm,${TERM}))
  C_OK   := \033[32m
  C_HI   := \033[36m
  C_WARN := \033[33m
  C_OFF  := \033[0m
else
  C_OK   :=
  C_HI   :=
  C_WARN :=
  C_OFF  :=
endif

PREFIX  ?= /usr/local
DESTDIR ?=

# --- Help -------------------------------------------------------------------

.PHONY: help
help: ## Show available targets grouped by section
	@awk 'BEGIN {FS = ":.*?## "} \
	  /^## ===/ { printf "\n$(C_HI)%s$(C_OFF)\n", substr($$0, 7); next } \
	  /^[a-zA-Z0-9_.-]+:.*?## / { printf "  $(C_OK)%-18s$(C_OFF) %s\n", $$1, $$2 }' \
	  $(MAKEFILE_LIST)

## === Bootstrap ===

.PHONY: bootstrap
bootstrap: tools hooks ## Set up a fresh checkout (tools + git hooks)
	@printf "$(C_OK)bootstrap complete$(C_OFF). Try: make ci\n"

.PHONY: tools
tools: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/gofumpt $(TOOLS_DIR)/govulncheck $(TOOLS_DIR)/goreleaser ## Install pinned dev tools into .tools/

$(TOOLS_DIR)/golangci-lint:
	$(Q)mkdir -p $(TOOLS_DIR)
	$(Q)GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_VERSION)

$(TOOLS_DIR)/gofumpt:
	$(Q)mkdir -p $(TOOLS_DIR)
	$(Q)GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

$(TOOLS_DIR)/govulncheck:
	$(Q)mkdir -p $(TOOLS_DIR)
	$(Q)GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(TOOLS_DIR)/goreleaser:
	$(Q)mkdir -p $(TOOLS_DIR)
	$(Q)GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

.PHONY: hooks
hooks: ## Install pre-commit + pre-push git hooks
	$(Q)command -v pre-commit >/dev/null || { printf "$(C_WARN)pre-commit not installed; brew install pre-commit$(C_OFF)\n"; exit 1; }
	$(Q)pre-commit install --hook-type pre-commit
	$(Q)pre-commit install --hook-type pre-push

## === Build ===

.PHONY: build
build: ## Build the ward binary into ./bin/
	$(Q)mkdir -p $(BIN_DIR)
	$(Q)$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/ward
	@printf "$(C_OK)built$(C_OFF) %s (%s)\n" "$(BIN_DIR)/$(BINARY)" "$(VERSION)"

.PHONY: install
install: build ## Install ward into $$DESTDIR$$PREFIX/bin (default /usr/local/bin)
	$(Q)install -d $(DESTDIR)$(PREFIX)/bin
	$(Q)install -m 0755 $(BIN_DIR)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

## === Test & verify ===

.PHONY: test
test: ## Run unit tests with race detector
	$(Q)$(GO) test -race -count=1 -timeout=120s $(PKG)

.PHONY: test-cover
test-cover: ## Run tests with coverage report
	$(Q)$(GO) test -race -count=1 -coverprofile=$(COVER_OUT) $(PKG)
	$(Q)$(GO) tool cover -func=$(COVER_OUT) | tail -1

.PHONY: lint
lint: tools ## Run golangci-lint
	$(Q)$(TOOLS_DIR)/golangci-lint run $(PKG)

.PHONY: fmt
fmt: tools ## Format Go code (gofumpt)
	$(Q)$(TOOLS_DIR)/gofumpt -w .

.PHONY: vet
vet: ## go vet
	$(Q)$(GO) vet $(PKG)

.PHONY: tidy
tidy: ## go mod tidy
	$(Q)$(GO) mod tidy

.PHONY: check-testing-doc
check-testing-doc: ## Verify every internal/pkg package has a row in docs/engineering/testing.md
	$(Q)scripts/check-testing-doc.sh

.PHONY: check-spdx
check-spdx: ## Verify every Go file starts with its SPDX licence line (ADR-0007)
	$(Q)scripts/check-spdx-selftest.sh
	$(Q)scripts/check-spdx.sh

.PHONY: check-public
check-public: ## Fail on content that must not reach the public repo (ADR-0007)
	$(Q)scripts/check-public-selftest.sh
	$(Q)scripts/check-public.sh

.PHONY: check
check: lint vet test check-testing-doc check-spdx check-public ## Lint + vet + test + testing-doc + spdx + public-content gate — the "is everything OK" gate

.PHONY: ci
ci: check build wasm-check wasm ## What CI runs (incl. js/wasm compile + 5 MB size gate)

## === Audit ===

.PHONY: vuln
vuln: tools ## Run govulncheck against the module
	$(Q)$(TOOLS_DIR)/govulncheck $(PKG)

.PHONY: audit
audit: tools ## Pre-release audit: module verify + vuln scan + goreleaser config lint + (future) pnpm audit signatures
	$(Q)$(GO) mod verify
	$(Q)$(TOOLS_DIR)/govulncheck $(PKG)
	$(Q)$(TOOLS_DIR)/goreleaser check
	$(Q)test ! -f pnpm-lock.yaml || { command -v pnpm >/dev/null && pnpm audit --audit-level=moderate && pnpm audit signatures; }
	@printf "$(C_OK)audit clean$(C_OFF)\n"

## === Cross-compile ===

.PHONY: dist
dist: dist-linux-amd64 dist-linux-arm64 dist-darwin-arm64 ## Cross-compile binaries for all reference architectures

.PHONY: dist-linux-amd64
dist-linux-amd64: ## Build linux/amd64
	$(Q)mkdir -p $(DIST_DIR)
	$(Q)GOOS=linux  GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/ward-linux-amd64  ./cmd/ward

.PHONY: dist-linux-arm64
dist-linux-arm64: ## Build linux/arm64 (Pi 5, RK3588)
	$(Q)mkdir -p $(DIST_DIR)
	$(Q)GOOS=linux  GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/ward-linux-arm64  ./cmd/ward

.PHONY: dist-darwin-arm64
dist-darwin-arm64: ## Build darwin/arm64 (Apple Silicon)
	$(Q)mkdir -p $(DIST_DIR)
	$(Q)GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/ward-darwin-arm64 ./cmd/ward

## === WebAssembly ===

.PHONY: wasm
wasm: ## Build dist/wasm/ward.wasm + wasm_exec.js; fails if ward.wasm > 5 MB
	$(Q)mkdir -p $(WASM_DIR)
	$(Q)GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags '-s -w' -o $(WASM_DIR)/ward.wasm ./cmd/wardwasm
	$(Q)cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" $(WASM_DIR)/wasm_exec.js
	$(Q)scripts/check-wasm-size.sh $(WASM_DIR)/ward.wasm $(WASM_MAX_BYTES)
	@printf "$(C_OK)built$(C_OFF) %s (%s bytes, budget %s)\n" "$(WASM_DIR)/ward.wasm" "$$(wc -c < $(WASM_DIR)/ward.wasm | tr -d ' ')" "$(WASM_MAX_BYTES)"

.PHONY: wasm-check
wasm-check: ## Compile + vet cmd/wardwasm for js/wasm (no artifacts; ./... skips js-only files)
	$(Q)GOOS=js GOARCH=wasm $(GO) vet ./cmd/wardwasm/...
	$(Q)GOOS=js GOARCH=wasm $(GO) build -o /dev/null ./cmd/wardwasm

.PHONY: wasm-smoke
wasm-smoke: wasm ## Exercise globalThis.ward in Node (needs node >= 18; not part of ci)
	$(Q)command -v node >/dev/null || { printf "$(C_WARN)node not installed; wasm-smoke needs node >= 18$(C_OFF)\n"; exit 1; }
	$(Q)node scripts/wasm-smoke.mjs $(WASM_DIR)

## === Run ===

.PHONY: run
run: build ## Build then run `ward version`
	$(Q)$(BIN_DIR)/$(BINARY) version

## === Acceptance ===

.PHONY: dod
dod: ## Run the v0.2 DOD harness; pass CLOSEOUT=1 to include the no-unpushed-commits bullet
	$(Q)scripts/dod.sh $(if $(CLOSEOUT),--closeout,)

## === Hygiene ===

.PHONY: prune-superpowers
prune-superpowers: ## Dry-run prune of shipped-slice plans/reviews under docs/superpowers/ (pass APPLY=1 to delete)
	$(Q)scripts/prune-superpowers.sh $(if $(APPLY),--apply,)

## === Data ===

.PHONY: ngrams
ngrams: ## Regenerate pkg/detect/ngrams.bin + testdata/eval/lexical-v1.jsonl (MAJESTIC=path/to/majestic_million.csv)
	$(Q)test -n "$(MAJESTIC)" || { printf "usage: make ngrams MAJESTIC=/path/to/majestic_million.csv\n"; exit 2; }
	$(Q)$(GO) run ./scripts/build-ngrams -in "$(MAJESTIC)"

## === Clean ===

.PHONY: clean
clean: ## Remove build artifacts
	$(Q)rm -rf $(BIN_DIR) $(DIST_DIR) $(COVER_OUT)

.PHONY: distclean
distclean: clean ## Remove build artifacts AND project-local tools
	$(Q)rm -rf $(TOOLS_DIR)
