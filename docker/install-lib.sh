#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <RELIC_IMAGE_NAME> <LSSS_IMAGE_NAME> <COMPRESSION>"
  exit 1
fi

RELIC_IMAGE_NAME="$1"
LSSS_IMAGE_NAME="$2"
COMPRESSION="$3"

cd ../
docker run -e COMPRESSION_OPTION=${COMPRESSION} --name build-lsss--container -v $(pwd):/lsss -w /lsss ${RELIC_IMAGE_NAME} /bin/bash -c "mkdir -p /tmp/build-lsss && cd /tmp/build-lsss && cmake /lsss && make && make install && rm -rf * && cmake /lsss -DCOMPRESSION_ENABLED=OFF -DBUILD_TESTS=ON && make && make install && rm -rf *"

# -DCOMPRESSION_ENABLED=${COMPRESSION_OPTION} -DBUILD_TESTS=ON

# export this container as an image
docker commit build-lsss--container ${LSSS_IMAGE_NAME}
docker rm build-lsss--container