CURVE ?= bls12-381
RELIC_TAG ?= 0.6.0

all: install-relic

install-relic:
	CURVE=$(CURVE) RELIC_TAG=$(RELIC_TAG) ./install-relic.sh

.PHONY: all clean install-relic
