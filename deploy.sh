#!/bin/sh

CDK_DIR="emily/cdk/"
HANDLER_DIR="emily/handler/"
ROOT_DIR=$(pwd)


# Build the Rust Lambda handler
{
    cd "$ROOT_DIR" || exit
    cd "$HANDLER_DIR" || exit
    # cargo lambda build --bin emily-lambda --release --no-default-features --output-format zip --x86-64
    cargo lambda build --bin emily-lambda --release --output-format zip --x86-64
}

# Deploy the CDK stack
{
    cd "$ROOT_DIR" || exit
    cd "./$CDK_DIR" || exit
    pnpm run deploy
    pwd
}
