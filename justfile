#!/usr/bin/env just --justfile

release:
  cargo build --release    

lint:
  cargo clippy

run:
  cargo run

example:
  cargo run --example exname -- arg1