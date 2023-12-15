FROM debian:buster

ARG RELIC_TAG="0.6.0"

ENV CURVE=${CURVE:-bls12-381}
ENV RELIC_INCLUDE="/usr/local/include/relic"

RUN apt-get update && apt-get install -y --no-install-recommends sudo git \
	cmake make g++ ca-certificates libgmp-dev vim flex libfl-dev pkg-config && apt-get clean

RUN git clone --branch ${RELIC_TAG} --depth 1 https://github.com/relic-toolkit/relic /relic

RUN mkdir -p /relic/build-${CURVE}
WORKDIR /relic/build-${CURVE}
RUN ../preset/x64-pbc-${CURVE}.sh ..
RUN make -j && make install

WORKDIR /root