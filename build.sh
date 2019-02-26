#!/usr/bin/env bash

GOOS=linux go build -o ./bin/kubi kubi-cli.go
GOOS=windows GOARCH=386 go build -o ./bin/kubi.exe
md5sum ./bin/kubi ./bin/kubi.exe > ./bin/md5
