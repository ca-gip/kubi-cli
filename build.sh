#!/usr/bin/env bash

GOOS=linux go build -o ./bin/kubi kubi-cli.go
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-darwin kubi-cli.go
GOOS=windows GOARCH=386 go build -o ./bin/kubi.exe

(cd ./bin && shasum -a 256 kubi kubi-darwin kubi.exe > sha256)
