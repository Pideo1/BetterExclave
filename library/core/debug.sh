#!/bin/bash

./prepare.sh || exit 1

# http2legacy: https://github.com/XTLS/Xray-core/issues/6797
CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -tags="with_clash,http2legacy" "github.com/exclavenetwork/libexclavecore" || exit 1

proj=../../app/libs
if [ -d $proj ]; then
  cp -vf libexclavecore.aar $proj
fi
