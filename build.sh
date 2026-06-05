#!/bin/bash

APP_NAME="roothawkx"
OUTPUT_DIR="build"

mkdir -p ${OUTPUT_DIR}

echo "Building for Linux amd64..."
GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -ldflags="-s -w" -o ${OUTPUT_DIR}/${APP_NAME}_linux_amd64 roothawk.go

echo "Building for Linux x86 (386)..."
GOOS=linux CGO_ENABLED=0 GOARCH=386 go build -ldflags="-s -w" -o ${OUTPUT_DIR}/${APP_NAME}_linux_386 roothawk.go

echo "Building for Linux arm64..."
GOOS=linux CGO_ENABLED=0 GOARCH=arm64 go build -ldflags="-s -w" -o ${OUTPUT_DIR}/${APP_NAME}_linux_arm64 roothawk.go

echo ""
echo "Build complete! Output files are in the '${OUTPUT_DIR}' directory."
