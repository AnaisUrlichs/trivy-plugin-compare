.PHONY: clean build test

clean:
	rm -rf compare

build:
	go build -o compare .

test:
	go test -race -v ./...