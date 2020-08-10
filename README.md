# Crypto Finance Development Kit for Rust (CFD-RUST)

## Dependencies

- Rust
- C/C++ Compiler
  - can compile c++11
  - make support compiler
- CMake (3.14.3 or higher)
- Python 3.x

### Windows 

- Visual Studio 2019

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
wget https://github.com/cryptogarageinc/cfd/releases/download/v0.1.13/cfd-v0.1.13-osx-xcode9.4_x86_64-static.zip
# decompress
sudo unzip -d / cfd-v0.1.13-osx-xcode9.4_x86_64-static.zip
# build
cargo build
```

---

### Test

```
cargo test
```

### Example

```
cargo run --example create_pubkey_address
```

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
