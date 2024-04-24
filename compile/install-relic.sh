#!/bin/bash

RELIC_TAG="0.6.0"
CURVE=${CURVE:-bls12-381}

sudo apt-get update
sudo apt-get install -y git cmake make g++ libgmp-dev vim flex libfl-dev pkg-config openssl libssl-dev

git clone --branch ${RELIC_TAG} --depth 1 https://github.com/relic-toolkit/relic /tmp/relic

mkdir -p /tmp/relic/build-${CURVE}
cd /tmp/relic/build-${CURVE}
sed -i 's/-DSHLIB=OFF -DSTBIN=ON/-DSHLIB=ON -DSTBIN=OFF/' ../preset/x64-pbc-${CURVE}.sh
../preset/x64-pbc-${CURVE}.sh ..
make -j && sudo make install
sudo cp /tmp/relic/src/md/blake2.h /usr/local/include/
