#!/usr/bin/env bash

GOOS=linux go build -o ./bin/linux/kubi kubi-cli.go
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o ./bin/mac/kubi kubi-cli.go
GOOS=windows GOARCH=386 go build -o ./bin/windows/kubi.exe
md5sum ./bin/linux/kubi ./bin/windows/kubi.exe ./bin/mac/kubi > ./bin/md5
