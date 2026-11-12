GO        ?= go
BIN       := bin/keepia-mail
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# PostgreSQL with CREATEDB for `make test`: every database test creates and
# drops a database of its own (internal/store/storetest).
TEST_DATABASE_URL ?= postgres://keepia:keepia@localhost:5432/keepia?sslmode=disable
# golangci-lint version for `make lint`; CI's lint job names the same version
# (.github/workflows/ci.yml). Dependabot cannot update `go install
# pkg@version`, so bump both here by hand.
GOLANGCI_LINT_VERSION := v2.14.0
GOLANGCI_LINT := bin/golangci-lint-$(GOLANGCI_LINT_VERSION)/golangci-lint
# govulncheck version for `make vuln`; bump it here by hand as well.
GOVULNCHECK_VERSION := v1.8.0
# gitleaks version for secret scanning. Dependabot cannot update
# `go install pkg@version`, so bump it here by hand and rescan the full
# history (`make secrets`) after a bump.
GITLEAKS_VERSION := v8.30.1
GITLEAKS  := bin/gitleaks-$(GITLEAKS_VERSION)/gitleaks
# Git history to scan; `make secrets` scans all refs unless SECRETS_LOG_OPTS
# (git log options, e.g. a commit range) is set.
SECRETS_SOURCE ?= .
# actionlint version for the workflows check. Dependabot cannot update it
# either, so bump it here by hand.
ACTIONLINT_VERSION := v1.7.12
ACTIONLINT := bin/actionlint-$(ACTIONLINT_VERSION)/actionlint

.PHONY: build test test-unit lint vuln tidy secrets secrets-test links links-test workflows workflows-test

## build: the keepia-mail binary in bin/
build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/keepia-mail

## test: all tests, including the PostgreSQL tests (TEST_DATABASE_URL)
test:
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(GO) test -race -shuffle=on -count=1 ./...

## test-unit: the tests that need no database (the database tests skip)
test-unit:
	TEST_DATABASE_URL= $(GO) test -race -shuffle=on ./...

# golangci-lint is built with the project's toolchain and verified through
# the Go checksum database, like gitleaks.
$(GOLANGCI_LINT):
	GOTOOLCHAIN=$$($(GO) env GOVERSION) GOBIN=$(CURDIR)/$(dir $(GOLANGCI_LINT)) $(GO) install \
		github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

## lint: golangci-lint with .golangci.yml (linters and gofmt/goimports)
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

## vuln: govulncheck on all packages (queries vuln.go.dev)
# govulncheck must be built with the project's toolchain (see go.mod) to load
# packages that require it.
vuln:
	GOTOOLCHAIN=$$($(GO) env GOVERSION) $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

## tidy: go mod tidy
tidy:
	$(GO) mod tidy

# gitleaks is built with the project's toolchain and verified through the Go
# checksum database.
$(GITLEAKS):
	GOTOOLCHAIN=$$($(GO) env GOVERSION) GOBIN=$(CURDIR)/$(dir $(GITLEAKS)) $(GO) install \
		-ldflags=-X=github.com/zricethezav/gitleaks/v8/version.Version=$(GITLEAKS_VERSION) \
		github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

## secrets: scan the git history (all refs by default) for committed credentials
secrets: $(GITLEAKS)
	$(GITLEAKS) git --redact --verbose --no-banner --exit-code 1 --config .gitleaks.toml \
		--log-opts="$$SECRETS_LOG_OPTS" $(SECRETS_SOURCE)

## secrets-test: self-test of the secret scan (temporary git repos, no network)
secrets-test: $(GITLEAKS)
	GITLEAKS=$(CURDIR)/$(GITLEAKS) sh scripts/secret-scan-test.sh

## links: every relative Markdown link and heading anchor in the repository resolves
links:
	sh scripts/check-links.sh

## links-test: self-test of the links check (fixtures, no network)
links-test:
	sh scripts/check-links-test.sh

# actionlint is built with the project's toolchain and verified through the Go
# checksum database, like gitleaks.
$(ACTIONLINT):
	GOTOOLCHAIN=$$($(GO) env GOVERSION) GOBIN=$(CURDIR)/$(dir $(ACTIONLINT)) $(GO) install \
		github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

## workflows: actionlint on all workflows, action pins, valid labels.json
# No shellcheck/pyflakes: the result must not depend on what is installed.
workflows: $(ACTIONLINT)
	$(ACTIONLINT) -shellcheck= -pyflakes=
	$(GO) run ./tools/check-action-pins
	jq empty .github/labels.json

## workflows-test: tests of the action pin check (fixtures, no network)
workflows-test:
	$(GO) test -count=1 ./tools/check-action-pins/
