#!/bin/bash

set -e

ISSUER_ROOT="${LOCAL_REPOSITORY_ISSUER_ROOT:-$HOME/Git/swiyu-issuer}"
VERIFIER_ROOT="${LOCAL_REPOSITORY_VERIFIER_ROOT:-$HOME/Git/swiyu-verifier}"

if [ ! -d "$ISSUER_ROOT" ]; then
    echo "Error: Issuer repository not found at: $ISSUER_ROOT" >&2
    exit 1
fi

if [ ! -d "$VERIFIER_ROOT" ]; then
    echo "Error: Verifier repository not found at: $VERIFIER_ROOT" >&2
    exit 1
fi

docker rmi -f swiyu-issuer:local 2>/dev/null || true
docker rmi -f swiyu-verifier:local 2>/dev/null || true

pushd "$ISSUER_ROOT" >/dev/null
mvn clean package -DskipTests
docker build -t swiyu-issuer:local .
popd >/dev/null

pushd "$VERIFIER_ROOT" >/dev/null
mvn clean package -DskipTests
docker build -t swiyu-verifier:local .
popd >/dev/null

export ISSUER_IMAGE_NAME=swiyu-issuer
export ISSUER_IMAGE_TAG=local
export VERIFIER_IMAGE_NAME=swiyu-verifier
export VERIFIER_IMAGE_TAG=local

