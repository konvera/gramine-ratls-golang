.PHONY: test lint lint-strict

test:
	go test ./...

lint:
	gofmt -d ./
	go vet ./...
	staticcheck ./...

lint-strict: lint
	gofumpt -d -extra .
	golangci-lint run
