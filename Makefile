BIN     := digest
MODULE  := github.com/youwantitdarker28/Command-Guard
CMD     := ./cmd/digest
PREFIX  ?= /usr/local

GOFLAGS :=
LDFLAGS := -s -w

.PHONY: all build test vet tidy install uninstall clean smoke-test

## all — default: build the binary
all: build

## build — compile the binary from cmd/digest into the project root
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

## test — run the full test suite with race detection
test:
	go test -race -count=1 ./...

## vet — run go vet across all packages
vet:
	go vet ./...

## tidy — sync go.mod and go.sum
tidy:
	go mod tidy

## install — build and copy the binary to $(PREFIX)/bin
install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "Installed $(PREFIX)/bin/$(BIN)"

## uninstall — remove the installed binary
uninstall:
	rm -f $(PREFIX)/bin/$(BIN)
	@echo "Removed $(PREFIX)/bin/$(BIN)"

## clean — remove build artefacts
clean:
	rm -f $(BIN)

## smoke-test — build then run the end-to-end smoke test
smoke-test: build
	bash scripts/smoke_test.sh
