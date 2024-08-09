#!/bin/bash
cargo build --release
mkdir -p ~/.ivcnotes
cp -r ./keys/ ~/.ivcnotes
cp target/release/cli ~/.cargo/bin/notes