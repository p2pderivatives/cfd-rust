#!/bin/sh
cd `git rev-parse --show-toplevel`
cargo clippy
