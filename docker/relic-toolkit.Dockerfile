FROM debian:bookworm

ARG RELIC_TAG="0.6.0"
ARG TARGET_CURVE="x64-pbc-bls12-381"

RUN apt-get update && apt-get install -y --no-install-recommends sudo git \
	cmake make g++ ca-certificates libgmp-dev vim flex libfl-dev pkg-config \
	openssl libssl-dev && apt-get clean

RUN git clone --branch ${RELIC_TAG} --depth 1 https://github.com/relic-toolkit/relic /tmp/relic

RUN mkdir -p /tmp/relic/target--${TARGET_CURVE}
WORKDIR /tmp/relic/target--${TARGET_CURVE}
RUN sed -i 's/-DSHLIB=OFF -DSTBIN=ON/-DSHLIB=ON -DSTBIN=OFF/' ../preset/${TARGET_CURVE}.sh
RUN ../preset/${TARGET_CURVE}.sh ..
RUN make -j && make install
RUN cp -u /tmp/relic/src/md/blake2.h /usr/local/include/
