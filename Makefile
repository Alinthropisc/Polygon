# Polygon — Go Makefile
# Analogous to cargo's Makefile.toml or CMakeLists.txt

BINARY   := polygon
MODULE   := Polygon
CMD      := ./cmd/polygon
OUT      := ./bin/$(BINARY)
GOFLAGS  := -trimpath -ldflags="-s -w"

.PHONY: all build run test lint vet fmt tidy clean install docker

all: build

build:
	@mkdir -p bin
	go build $(GOFLAGS) -o $(OUT) $(CMD)

# Build with race detector (dev/testing)
build-race:
	@mkdir -p bin
	go build -race -o $(OUT)-race $(CMD)

run: build
	$(OUT) HELP

test:
	go test ./... -v -timeout 60s

# Race-safe test run
test-race:
	go test -race ./... -timeout 60s

# golangci-lint (equivalent to clippy)
lint:
	golangci-lint run ./...

# go vet — built-in static analysis
vet:
	go vet ./...

# gofmt + goimports (equivalent to rustfmt / clang-format)
fmt:
	gofmt -w -s .
	@which goimports >/dev/null 2>&1 && goimports -w . || true

# go mod tidy — keeps go.mod/go.sum clean
tidy:
	go mod tidy

# go mod download — pre-fetch deps (useful in CI)
download:
	go mod download

clean:
	rm -rf bin/

install: build
	install -m 0755 $(OUT) /usr/local/bin/$(BINARY)

# Cross-compile targets
build-linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o bin/$(BINARY)-linux-amd64 $(CMD)

build-windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o bin/$(BINARY)-windows-amd64.exe $(CMD)

docker:
	docker build -t $(BINARY):latest .
