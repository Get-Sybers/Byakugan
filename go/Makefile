GO ?= go

.PHONY: build test vet fmt clean gen-ir gen-ir-check

build:
	$(GO) build -o bin/byakugan-parse ./cmd/byakugan-parse

# Regenerate the embedded ir.json from the Go authoring layer
# (go/internal/authoring) — the single source of truth for the map tables.
gen-ir: build
	./bin/byakugan-parse gen-ir --out internal/ir/ir.json

# CI gate: fail if ir.json has drifted from the Go authoring tables.
gen-ir-check: build
	./bin/byakugan-parse gen-ir --check internal/ir/ir.json

test:
	$(GO) vet ./...
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w ./cmd ./internal

clean:
	rm -rf bin
