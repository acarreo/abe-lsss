.PHONY: all clean local docker

all: local

local:
	./install-relic.sh

docker:
	docker build -t lsss-abe:0.1.0 .
