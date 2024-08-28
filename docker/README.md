# Docker Setup for Project

This directory contains all the necessary Dockerfiles and a Makefile to build Docker images required for this project.

As prerequisites, you need to have Docker installed on your machine. You can download Docker from the official website: [https://www.docker.com/get-started](https://www.docker.com/get-started).


## Directory Structure

- `relic-toolkit.Dockerfile`: Dockerfile to build the `relic-toolkit` image.
- `abe-lsss.Dockerfile`: Dockerfile to build the `abe-lsss` image, which depends on `relic-toolkit`.
- `Makefile`: A Makefile to automate the building process of the Docker images.

## Building the Docker Images

### 1. Build `relic-toolkit` Image

The `relic-toolkit` image is the base image required for `abe-lsss`.

#### Build with Default Settings

To build the `relic-toolkit` image with default settings (curve `bls12-381` and RELIC tag `0.6.0`):

```
make build_relic
```

#### Build with Custom Arguments

You can customize the curve and RELIC tag by passing arguments directly via the command line:
  
```bash
make build_relic RELIC_TAG=0.6.0 CURVE=bn254
```

This command will build an image named cryptolib/relic-toolkit:0.6.0-bn254

### 2. Build `abe-lsss` Image

The `abe-lsss` image is built on top of the `relic-toolkit` image. Ensure that the required relic-toolkit image is available before building abe-lsss.

#### Build with Default Settings

If the default relic-toolkit image (cryptolib/relic-toolkit:0.6.0-bls12-381) exists, you can build abe-lsss directly:
  
```bash
make build_abe_lsss
```

If the `relic-toolkit` image does not exist, the Makefile will automatically build it before creating the `abe-lsss` image.

#### Build with Custom Arguments

To build `abe-lsss` with a specific `relic-toolkit` version and curve:

```bash
make build_abe_lsss RELIC_TAG=<version> CURVE=<curve> ABE_LSSS_VERSION=<image_version>
```

This command will check if `cryptolib/relic-toolkit:<version>-<curve>` exists. If not, it will build the `relic-toolkit` image first before building the `cryptolib/abe-lsss:<image_version>` image.

### 3. Build All Images
Building all images follows the same process as described above for `abe-lsss` or `relic`, using the same `make` commands.