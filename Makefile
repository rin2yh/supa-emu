.PHONY: build test test-race lint fmt run clean

BIN := bin/supabase-emulator

build:
	go build -o $(BIN) .

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

lint:
	go vet ./...

fmt:
	gofmt -w .

run: build
	./$(BIN)

clean:
	rm -rf bin
