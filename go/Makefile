GO ?= go

.PHONY: build test vet fmt clean

build:
	$(GO) build -o bin/byakugan-parse ./cmd/byakugan-parse

test:
	$(GO) vet ./...
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w ./cmd ./internal

clean:
	rm -rf bin
