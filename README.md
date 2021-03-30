# Crypto Finance Development Kit for Rust (CFD-RUST)

CFD library for Rust.

## Overview

This library is development kit for crypto finance application.
Useful when developing applications for cryptocurrencies.

### Target Network

- Bitcoin
- Liquid Network

### Support function by cfd

- Bitcoin
  - Bitcoin Script (builder, viewer)
  - Transaction
    - Create, Parse, Decode
    - Simple pubkey-hash sign / verify
    - Estimate Fee
    - Coin Selection (FundRawTransaction)
  - ECDSA Pubkey/Privkey (TweakAdd/Mul, Negate, Sign, Verify)
  - BIP32, BIP39
  - Output Descriptor (contains miniscript parser)
  - Schnorr/Taproot
  - Bitcoin Address (Segwit-v0, Segwit-v1, P2PKH/P2SH)
- Liquid Network
  - Confidential Transaction
    - Blind, Unblind
    - Reissuance
  - Confidential Address

### Libraries for each language

- Rust : cfd-rust
  - C/C++ : cfd
    - Extend the cfd-core library. Defines the C language API and extension classes.
  - C++ : cfd-core
    - Core library. Definition base class.
- other language:
  - JavaScript : cfd-js
  - WebAssembly : cfd-js-wasm
  - Python : cfd-python
  - C# : cfd-csharp
  - Go : cfd-go

## Dependencies

- Rust
- C/C++ Compiler
  - can compile c++11
- CMake (3.14.3 or higher)

### Windows

download and install files.

- [Rustup](https://rustup.rs/)
- [CMake](https://cmake.org/) (3.14.3 or higher)
- MSVC
  - [Visual Studio](https://visualstudio.microsoft.com/downloads/) (Verified version is 2017 or higher)
  - [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) (2017 or higher)
  - (Using only) [msvc redistribution package](https://support.microsoft.com/help/2977003/the-latest-supported-visual-c-downloads)

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake rust
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential cmake
curl https://sh.rustup.rs -sSf | sh  (select is 1)
```

cmake version 3.14.2 or lower, download from website and install cmake.
([https://cmake.org/download/](https://cmake.org/download/))

---

## Build

```Shell
cargo build
```

### Prepare cfd native library from using source code

only `cargo build`. However, it takes time to build.

### Prepare cfd native library from releases asset (MacOS / Linux)

Using pkg-config, build is quickly.

```Shell
# The described version is an example. If you use it, please rewrite it to an appropriate version.
wget https://github.com/p2pderivatives/cfd-rust/releases/download/v0.3.0/cfd-sys-v0.3.0-osx-xcode12.4-static-x86_64.zip

# decompress
sudo unzip -d / cfd-sys-v0.3.0-osx-xcode12.4-static-x86_64.zip
# build
cargo build
```

### Prepare cfd native library from releases asset (Windows)

Using cmake find_package.

1. get releases asset. (ex. [https://github.com/p2pderivatives/cfd-rust/releases/download/v0.3.0/cfd-sys-v0.3.0-win-vs2019-x86_64.zip](https://github.com/p2pderivatives/cfd-rust/releases/download/v0.3.0/cfd-sys-v0.3.0-win-vs2019-x86_64.zip) )
2. Expand to PATH

---

## Test and Example

### Test

```shell
cargo test
```

### Example

```shell
cargo run --example create_pubkey_address
```

---

## Information for developers

### using library

- cfd (called by cfd-sys)
  - cfd-core
    - [libwally-core](https://github.com/cryptogarageinc/libwally-core/tree/cfd-develop) (forked from [ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core))
    - [univalue](https://github.com/jgarzik/univalue) (for JSON encoding and decoding)

### formatter

- rustfmt

### linter

- clippy

### document tool

- cargo

  ```shell
  cargo doc
  ```

### support compilers

- Visual Studio (2017 or higher)
- Clang (7.x or higher)
- GCC (5.x or higher)

---

## Note

### Git connection

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)

```bat
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):

```shell
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project

Depending on your git environment, you may get the following error when checking out external:

```log
  Performing update step for 'libwally-core-download'
  Current branch cmake_build is up to date.
  No stash entries found.
  No stash entries found.
  No stash entries found.
  CMake Error at /workspace/cfd-core/build/external/libwally-core/download/libwally-core-download-prefix/tmp/libwally-core-download-gitupdate.cmake:133 (message):


    Failed to unstash changes in:
    '/workspace/cfd-core/external/libwally-core/'.

    You will have to resolve the conflicts manually
```

This phenomenon is due to the `git update` related command.
Please set an environment variable that skips update processing.

- Windows: (On the command line. Or set from the system setting screen.)

```bat
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):

```shell
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```
