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

# Function to check if an image needs attestation
requires_attestation() {
    [[ "$1" =~ ^blockstack/sbtc:(signer|blocklist-client).* ]]
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

# If attestation check is enabled, verify only specific images
if [ "$SKIP_CHECK" = false ]; then
    for IMAGE in $IMAGES; do
        if requires_attestation "$IMAGE"; then
            echo "🔍 Checking GitHub attestation for $IMAGE..."

            # Check if the image exists in GitHub Container Registry
            DIGEST=$(gh api -H "Accept: application/vnd.github.v3+json" \
              "/orgs/$OWNER/packages/container/sbtc/versions" \
              | jq -r '.[0].metadata.container.tags[] | select(.=="latest")')

            if [ -z "$DIGEST" ]; then
                echo "❌ Image not found in GitHub Container Registry!"
                exit 1
            fi

            echo "✅ Image found: $IMAGE"

            # Check if the image has a valid GitHub security attestation
            ATTESTATIONS=$(gh api \
              -H "Accept: application/vnd.github.v3+json" \
              "/repos/$OWNER/$REPO/dependabot/alerts" \
              | jq '. | length')

            if [ "$ATTESTATIONS" -eq "0" ]; then
                echo "❌ No valid attestations found for $IMAGE! Blocking execution."
                exit 1
            fi

            echo "✅ Attestation verified for $IMAGE!"
        else
            echo "ℹ️ Skipping attestation check for $IMAGE (not in required list)."
        fi
    done
else
    echo "⚠️ Skipping attestation check due to .env setting (SKIP_CHECK=true)."
fi

# Run the original docker-compose with all arguments
exec /usr/local/bin/docker-compose-original "$@"