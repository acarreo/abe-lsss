FROM debian:buster

RUN apt-get update && apt-get install -y sudo ca-certificates && apt-get clean

WORKDIR /root/
COPY install-relic.sh .
RUN ./install-relic.sh
