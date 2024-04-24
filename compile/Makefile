.PHONY: all clean local docker

all: local

local:
	./install-relic.sh

docker:
	docker build -t relic-toolkit:0.6.0 .
