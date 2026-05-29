#!/bin/bash
set -e
echo "==================================="
echo "  NetScan Pro Build Script"
echo "==================================="

cd "$(dirname "$0")"

echo ""
echo "[1/3] Installing Go dependencies..."
go mod tidy

echo ""
echo "[2/3] Building frontend..."
cd frontend
npm install
npm run build
cd ..

echo ""
echo "[3/3] Building Wails application..."
wails build

echo ""
echo "==================================="
echo "  Build completed!"
echo "  Output: build/bin/netscan"
echo "==================================="
