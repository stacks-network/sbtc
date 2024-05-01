#!/bin/bash

# TODO: replace this with a more organic build script that
# automatically triggers when building the cdk.
if [[ "$(uname -m)" == "arm64" ]]; then
  cargo lambda build --release --output-format zip --arm64
else
  cargo lambda build --release --output-format zip
fi
