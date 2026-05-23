VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -w -s -extldflags '-static' -X main.Version=$(VERSION)
COVERAGE_MIN ?= 80

.PHONY: build vet test version docker tidy fmt lint gosec govulncheck cover bench fuzz ci

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -tags netgo -o dist/wazuh-exporter ./cmd/wazuh-exporter

vet:
	go vet ./...

test:
	go test -race ./...

tidy:
	go mod tidy

version: build
	./dist/wazuh-exporter --version

docker:
	docker build --build-arg VERSION=$(VERSION) -t wazuh-prometheus-exporter:$(VERSION) .

# fmt fails if any tracked Go file is not gofmt-clean. Scoped to git-tracked
# files so a local wazuh-docker checkout / tests/config never trips it.
fmt:
	@unformatted=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed for:"; echo "$$unformatted"; exit 1; fi

lint:
	golangci-lint run

# gosec runs as a golangci-lint linter (so it honors //nolint:gosec); this target
# runs it in isolation. It is also covered by `make lint`.
gosec:
	golangci-lint run --enable-only=gosec

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...

# cover runs the race-enabled test suite with whole-module coverage attribution
# (-coverpkg=./..., so untested packages count) and enforces COVERAGE_MIN.
cover:
	go test -race -coverpkg=./... -coverprofile=coverage.out ./...
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | tr -d '%'); \
	echo "total coverage: $$total% (min $(COVERAGE_MIN)%)"; \
	awk "BEGIN{exit !($$total >= $(COVERAGE_MIN))}" || { echo "coverage gate failed (< $(COVERAGE_MIN)%)"; exit 1; }

bench:
	go test -bench=. -benchmem -run=^$$ ./...

# go test -fuzz requires the regexp to match exactly one target, so run each.
# These fuzz the Wazuh API JSON decoders (daemons/stats + the recursive
# decoded_breakdown flatten), which consume external API responses.
fuzz:
	go test -run=^$$ -fuzz='^FuzzEmitDaemonsStats$$' -fuzztime=15s ./pkg/exporter/
	go test -run=^$$ -fuzz='^FuzzFlattenBreakdown$$' -fuzztime=15s ./pkg/exporter/

# ci aggregates the merge-gating quality checks (mirrors quality-assurance.yml).
# `lint` already includes gosec, so it is not repeated here.
ci: fmt vet lint govulncheck cover
