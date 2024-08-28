# Variables par défaut
CURVE = bls12-381
RELIC_TAG = 0.6.0
RELIC_IMAGE_NAME = cryptolib/relic-toolkit
RELIC_FULL_IMAGE_NAME = $(RELIC_IMAGE_NAME):$(RELIC_TAG)-$(CURVE)

ABE_LSSS_IMAGE_NAME = cryptolib/abe-lsss
ABE_LSSS_VERSION = 0.1.0
ABE_LSSS_FULL_IMAGE_NAME = $(ABE_LSSS_IMAGE_NAME):$(ABE_LSSS_VERSION)

# Target to build the relic-toolkit image
build_relic:
	docker build --build-arg RELIC_TAG=$(RELIC_TAG) --build-arg TARGET_CURVE=x64-pbc-$(CURVE) -t $(RELIC_FULL_IMAGE_NAME) -f relic-toolkit.Dockerfile .

# Target to build the abe-lsss image
build_abe_lsss: check_relic_image
	docker build --build-arg RELIC_IMAGE=$(RELIC_FULL_IMAGE_NAME) -t $(ABE_LSSS_FULL_IMAGE_NAME) -f abe-lsss.Dockerfile .

# Check if the relic-toolkit image exists, build it if not
check_relic_image:
	@if ! docker image inspect $(RELIC_FULL_IMAGE_NAME) > /dev/null 2>&1; then \
		echo "Image $(RELIC_FULL_IMAGE_NAME) not found. Building it..."; \
		$(MAKE) build_relic RELIC_TAG=$(RELIC_TAG) CURVE=$(CURVE); \
	fi

# Default target to build both images
all: build_relic build_abe_lsss

.PHONY: all build_relic build_abe_lsss check_relic_image
