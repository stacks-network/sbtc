#!/bin/bash
set -e  # Exit on error

# Ensure required environment variables are set
if [[ -z "$BUNDLE_PATH" || -z "$TRUSTED_ROOT_PATH" ]]; then
  echo "❌ ERROR: BUNDLE_PATH and TRUSTED_ROOT_PATH environment variables must be set."
  exit 1
fi

# Define the image and repo (since they are fixed)
IMAGE="index.docker.io/blockstack/sbtc:$TAG"  # You can pass $TAG as environment variable
REPO="stacks-network/sbtc"

# Verifying attestation
echo "✅ Verifying attestation for image: $IMAGE..."
gh attestation verify \
  oci://$IMAGE \
  -R "$REPO" \
  --bundle "$BUNDLE_PATH" \
  --custom-trusted-root "$TRUSTED_ROOT_PATH"

# If verification succeeds, run the signer app
echo "🎉 Attestation verified successfully! Running the signer..."
exec "$@"