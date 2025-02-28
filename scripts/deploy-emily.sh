#!/bin/bash

# AWS_DEPLOYMENT_PROFILE=sbtcDevDeployment

GIT_REPO_ROOT=$(git rev-parse --show-toplevel)
EMILY_CDK_PATH="${GIT_REPO_ROOT}/emily/cdk"
EMILY_HANDLER_PATH="${GIT_REPO_ROOT}/emily/handler"

# Deployment variables.
ENV_FILE="${GIT_REPO_ROOT}/scripts/emily-testnet/.env"

# Export environment variables.
if [ -f "${ENV_FILE}" ]; then
  export $(grep -v '^#' "${ENV_FILE}" | xargs)
else
  echo "Error: $ENV_FILE does not exist."
  exit 1
fi

# Build emily.
{
    cd "${EMILY_HANDLER_PATH}" || exit
    echo "Building emily-lambda..."
    cargo lambda build \
        --bin emily-lambda \
        --release \
        --output-format zip \
        --x86-64
    echo "Done building emily lambda."
}

{
    cd "${EMILY_CDK_PATH}" || exit
    echo "Ensuring that CDK is boostraped..."
    npx aws-cdk bootstrap \
        --profile "${AWS_DEPLOYMENT_PROFILE}"
    echo "Done bootstrapping CDK."
    npx aws-cdk deploy \
        --profile "${AWS_DEPLOYMENT_PROFILE}" \
        --require-approval any-change
}
