#!/usr/bin/env bash

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-linux-amd64 kubi-cli.go
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-linux-arm64 kubi-cli.go
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-darwin-amd64 kubi-cli.go
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-darwin-arm64 kubi-cli.go
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-windows-amd64.exe kubi-cli.go

(cd ./bin && shasum -a 256 kubi-linux-amd64 kubi-linux-arm64 kubi-darwin-amd64 kubi-darwin-arm64 kubi-windows-amd64.exe > sha256)
