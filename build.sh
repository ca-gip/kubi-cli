#!/usr/bin/env bash

GOOS=linux go build -o ./bin/kubi kubi-cli.go
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/kubi-darwin kubi-cli.go
GOOS=windows GOARCH=386 go build -o ./bin/kubi.exe
md5sum ./bin/kubi ./bin/kubi.exe ./bin/kubi-darwin > ./bin/md5
