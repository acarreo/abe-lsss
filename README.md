# abe-lsss

## Installation on Docker

To install the project using Docker, go to the `docker` folder and follow the instructions in the README file located in that folder.

## Installation on the Host Machine

### Install Dependencies -- RELIC Toolkit
```bash
git clone https://github.com/acarreo/abe-lsss.git
cd abe-lsss/compile
make
```

By default, the RELIC Toolkit is built with curve `bls12-381` and tag `0.6.0`. You can customize the build by passing options to the `make` command. For example, to build RELIC with curve `bls12-446` and tag `0.6.0`, you can do the following:

```bash
make CURVE=bls12-446
```

### Install the abe-lsss Library
You can customize the build by passing options to cmake. For example, to disable compression, you can do the following:

```bash
mkdir ../build && cd ../build
cmake -DCOMPRESSION_ENABLED=OFF ..
make && make install
```

By default, compression is enabled. If you want to enable or disable specific features, you can pass additional cmake options as needed.
