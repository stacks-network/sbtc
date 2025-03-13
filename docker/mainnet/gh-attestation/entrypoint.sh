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
apt-get update
apt-get install -y curl
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
&& chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
&& apt update \
&& apt install gh -y
gh --version
gh attestation verify \
  oci://$IMAGE \
  -R "$REPO" \
  --bundle "$BUNDLE_PATH" \
  --custom-trusted-root "$TRUSTED_ROOT_PATH"

# If verification succeeds, run the signer app
echo "🎉 Attestation verified successfully! Running the signer..."
exec "$@"