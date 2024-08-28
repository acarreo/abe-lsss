ARG RELIC_IMAGE="cryptolib/relic-toolkit:0.6.0-bls12-381"

FROM ${RELIC_IMAGE}

RUN apt-get update && apt-get upgrade -y

RUN git clone https://github.com/acarreo/abe-lsss.git /tmp/abe-lsss
WORKDIR /tmp/abe-lsss
RUN mkdir -p /tmp/abe-lsss/build
WORKDIR /tmp/abe-lsss/build
RUN cmake ..
RUN make && make install
RUN ldconfig

WORKDIR /root