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
To install the library, you can use the following commands:

```bash
mkdir ../build && cd ../build
cmake ..
make && make install
```

By default, compression is enabled for serialization of group elements. If you want to enable or disable specific features, you can call the `set_compression_flag` in your main program. For example, to disable compression, you can do the following:

```c
#include <abe-lsss.h>

int main() {
  InitializeOpenABE();

  set_compression_flag(0);
  
  // Your code here

  ShutdownOpenABE();
  return 0;
}
```

