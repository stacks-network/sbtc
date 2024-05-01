#!/bin/bash

# `.generated-sources/emily/Cargo.toml` changes when the build script runs.
git update-index --assume-unchanged .generated-sources/emily/Cargo.toml
# to undo: `git update-index --no-assume-unchanged .generated-sources/emily/Cargo.toml`
