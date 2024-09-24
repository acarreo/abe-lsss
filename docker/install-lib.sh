#!/bin/bash

RELIC_IMAGE_NAME="$1"
LSSS_IMAGE_NAME="$2"

if [ -z "$RELIC_IMAGE_NAME" ] || [ -z "$LSSS_IMAGE_NAME" ]; then
  echo "Usage: $0 <relic-image-name> <lsss-image-name>"
  exit 1
fi

if ! docker image inspect ${RELIC_IMAGE_NAME} > /dev/null 2>&1; then
  echo "Relic image not found. Please build it first."
  exit 1
fi


cd ../
docker run --name lsss--container -v $(pwd):/lsss ${RELIC_IMAGE_NAME} /bin/bash -c "mkdir -p /tmp/build-lsss && cd /tmp/build-lsss && cmake -S /lsss -B . && make -j && make install && rm -rf /tmp/build-lsss"

# export this container as an image
docker commit --change='CMD ["/bin/bash"]' lsss--container ${LSSS_IMAGE_NAME}
docker rm lsss--container
