GO ?= go

.PHONY: build test vet fmt lint ddl-check

# build + vet + test the L1-physical registry module. It is its OWN Go module
# (own go.mod/go.sum, pulls modernc.org/sqlite) so the parse engine at ../ stays
# deliberately stdlib-only; `go` here never descends into it.
build:
	$(GO) build ./...

test:
	$(GO) vet ./...
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

# The embedded schema.sql is emitted by `python model/generate.py`; this is the
# drift gate (the Python side owns the DDL).
ddl-check:
	cd ../.. && python -m byakugan.l1physical --check

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is not installed: see https://golangci-lint.run/docs/welcome/install/"; exit 1; }
	golangci-lint config verify
	golangci-lint run ./...
