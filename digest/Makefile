BIN      := digest
PKG      := github.com/digest
GOFLAGS  :=

.PHONY: all build install clean tidy

all: build

## build — compile the binary into ./digest
build:
	go build $(GOFLAGS) -o $(BIN) .

## install — build and place the binary in $GOPATH/bin (or ~/go/bin)
install:
	go install $(GOFLAGS) .

## tidy — sync go.mod / go.sum
tidy:
	go mod tidy

## clean — remove the compiled binary
clean:
	rm -f $(BIN)
