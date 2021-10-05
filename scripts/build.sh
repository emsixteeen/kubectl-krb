#!/bin/bash
set -x

tag=$(git describe --tags --abbrev=0)
os=${os:-linux}
arch=${arch:-amd64}
project=github.com/emsixteeen/kubectl-krb
sources=cmd/kubectl-krb
binary=${binary:-kubectl-krb}

GOOS=${os} GOARCH=${arch} go build -o ${binary}-${os}-${arch}-${tag} ${project}/${sources}
