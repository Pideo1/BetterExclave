#!/bin/bash
# Prepares the patched modules that go.mod replaces:
#   build/exclave-core   - exclave-core at the version libexclavecore requires, with patches/exclave-core-*.patch applied
#   build/amneziawg-go   - amneziawg-go renamed to golang.zx2c4.com/wireguard (drop-in, same API)
set -e
cd "$(dirname "$0")"

AMNEZIAWG_VERSION=v3.1.20260828

EXCLAVE_CORE_VERSION=$(awk '$1 == "github.com/exclavenetwork/exclave-core/v5" && $2 ~ /^v/ { print $2; exit }' go.mod)
[ -n "$EXCLAVE_CORE_VERSION" ] || { echo "exclave-core version not found in go.mod"; exit 1; }

stamp="$EXCLAVE_CORE_VERSION $AMNEZIAWG_VERSION $(cat patches/*.patch | sha256sum | cut -c1-16)"
if [ "$(cat build/.prepared 2>/dev/null)" = "$stamp" ]; then
  exit 0
fi

# download outside this module: its replace directives point at the directories we are about to create
module_dir() {
  (cd "$(mktemp -d)" && GOFLAGS=-mod=mod go mod download -json "$1" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')
}

rm -rf build/exclave-core build/amneziawg-go build/.prepared
mkdir -p build

src=$(module_dir "github.com/exclavenetwork/exclave-core/v5@$EXCLAVE_CORE_VERSION")
cp -r "$src" build/exclave-core
chmod -R u+w build/exclave-core
for p in patches/exclave-core-*.patch; do
  patch -d build/exclave-core -p1 --no-backup-if-mismatch < "$p"
done

src=$(module_dir "github.com/amnezia-vpn/amneziawg-go/v3@$AMNEZIAWG_VERSION")
cp -r "$src" build/amneziawg-go
chmod -R u+w build/amneziawg-go
sed -i 's#^module .*#module golang.zx2c4.com/wireguard#' build/amneziawg-go/go.mod
find build/amneziawg-go -name '*.go' -exec sed -i 's#"github.com/amnezia-vpn/amneziawg-go/v3#"golang.zx2c4.com/wireguard#g' {} +

echo "$stamp" > build/.prepared
