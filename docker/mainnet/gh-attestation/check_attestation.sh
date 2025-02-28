#!/bin/bash

# Set strict mode
set -e

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Default SKIP_CHECK to false if not set in .env
SKIP_CHECK=${SKIP_CHECK:-false}

# Hardcoded GitHub repository details (OWNER and REPO)
OWNER="blockstack"
REPO="sbtc"

# Extract images from docker-compose.yml (if exists)
if [[ -f docker-compose.yml ]]; then
    IMAGES=$(grep 'image:' docker-compose.yml | awk '{print $2}' | tr -d '"')
else
    IMAGES=""
fi

# Function to check if an image needs attestation based on the tag
requires_attestation() {
    [[ "$1" =~ ^blockstack/sbtc:(signer-.*|blocklist-client-.*) ]]
}

# Ensure GitHub CLI is authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ GitHub CLI not authenticated! Attempting to log in..."
    gh auth login --with-token
    if [ $? -ne 0 ]; then
        echo "❌ Authentication failed! Please authenticate with 'gh auth login'."
        exit 1
    fi
fi

# Ensure Docker is logged into GHCR
if ! docker info | grep -q 'Server Version'; then
    echo "❌ Docker is not authenticated with GHCR. Attempting to log in..."
    docker login ghcr.io
    if [ $? -ne 0 ]; then
        echo "❌ Docker login to GHCR failed! Please log in with 'docker login ghcr.io'."
        exit 1
    fi
fi

# If attestation check is enabled, verify only specific images
if [ "$SKIP_CHECK" = false ]; then
    for IMAGE in $IMAGES; do
        if requires_attestation "$IMAGE"; then
            echo "🔍 Checking GitHub attestation for $IMAGE..."

            # Extract the tag from the image name (removes the * from the pattern)
            TAG=$(echo "$IMAGE" | sed -E 's/.*:(signer-[^*]+|blocklist-client-[^*]+).*/\1/')

            if [ -z "$TAG" ]; then
                echo "❌ Could not extract a valid tag from the image name: $IMAGE"
                exit 1
            fi

            # Verify attestation using gh attestation
            gh attestation verify oci://ghcr.io/$OWNER/$IMAGE:$TAG -R $OWNER/$REPO

            if [ $? -ne 0 ]; then
                echo "❌ Attestation verification failed for $IMAGE:$TAG! Blocking execution."
                exit 1
            fi

            echo "✅ Attestation verified for $IMAGE:$TAG!"
        else
            echo "ℹ️ Skipping attestation check for $IMAGE (not in required list)."
        fi
    done
else
    echo "⚠️ Skipping attestation check due to .env setting (SKIP_CHECK=true)."
fi

# Run the original docker-compose with all arguments
exec /usr/local/bin/docker-compose-original "$@"