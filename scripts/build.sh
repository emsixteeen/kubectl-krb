#!/bin/bash

tag=$(git describe --tags --abbrev=0)
os=linux
arch=amd64
project=github.com/emsixteeen/kubectl-krb
sources=cmd/kubectl-krb
binary=kubectl-krb

GOOS=${os} GOARCH=${arch} go build -o ${binary}-${os}-${arch}-${tag} ${project}/${sources}
