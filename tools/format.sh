#!/bin/sh
cd `git rev-parse --show-toplevel`
cargo fmt --all -- --emit files
