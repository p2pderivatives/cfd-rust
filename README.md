# Crypto Finance Development Kit for Rust (CFD-RUST)

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
(https://cmake.org/download/)

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
wget https://github.com/p2pderivatives/cfd-rust/releases/download/v0.0.1/cfd-sys-v0.0.1-osx-xcode9.4-static_x86_64.zip
# decompress
sudo unzip -d / cfd-sys-v0.0.1-osx-xcode9.4-static_x86_64.zip
# build
cargo build
```

### Prepare cfd native library from releases asset (Windows)

Using cmake find_package.
1. get releases asset. (ex. https://github.com/p2pderivatives/cfd/releases/download/v0.0.1/cfd-v0.0.1-win-vs2019-x86_64.zip )
2. Expand to PATH

---

## Test and Example

### Test

```
cargo test
```

### Example

```
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
  ```
  cargo doc
  ```

### support compilers

- Visual Studio (2017 or higher)
- Clang (7.x or higher)
- GCC (5.x or higher)

---

## Note

### Git connection:

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project:

Depending on your git environment, you may get the following error when checking out external:
```
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
```
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```
