.PHONY: build test vet fmt fmt-check run

build:
	go build ./...

test:
	go test ./... -race

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@diff <(gofmt -l .) <(echo -n "")

run:
	go run ./cmd/axto

check: build vet test fmt-check
