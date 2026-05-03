BIN       := digest
MODULE    := github.com/digest
CMD       := ./cmd/digest
PREFIX    ?= /usr/local

GOFLAGS   :=
LDFLAGS   := -s -w

.PHONY: all build test install uninstall clean tidy lint vet

## Default target
all: build

## build — compile the binary into the project root
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

## install — build and install the binary to $(PREFIX)/bin
install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "Installed to $(PREFIX)/bin/$(BIN)"

## uninstall — remove the installed binary
uninstall:
	rm -f $(PREFIX)/bin/$(BIN)
	@echo "Removed $(PREFIX)/bin/$(BIN)"

## clean — remove build artefacts
clean:
	rm -f $(BIN)
