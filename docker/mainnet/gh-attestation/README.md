# Docker Compose with GitHub Attestation Verification

This script modifies the behavior of `docker-compose` to enforce **GitHub attestation verification** for specific images. It ensures that **only verified images** from the **GitHub Container Registry** are run. If the image is not attested, the script will block execution.

## Features

- Enforces **GitHub attestation checks** for images of the format:
  - `blockstack/sbtc:signer*`
  - `blockstack/sbtc:blocklist-client*`
- Allows bypassing attestation checks via a `.env` configuration.
- Does **not require command-line flags** to skip checks, everything is controlled by the `.env` file.

## Setup

### 1. Backup Original Docker Compose

Make sure to back up your existing `docker-compose` binary:

```bash
mv /usr/local/bin/docker-compose /usr/local/bin/docker-compose-original
```

### 2. Save the Script

Copy the script `check_attestation.sh` to 

```bash
sudo nano /usr/local/bin/docker-compose
```

### 3. Make It Executable

Ensure the script is executable:

```bash
chmod +x /usr/local/bin/docker-compose
```

### 4. Configure `.env` File

The script uses the `.env` file for configuration.  
- To **disable attestation verification**, set `SKIP_CHECK=true`
- To **enforce attestation verification**, set `SKIP_CHECK=false` (or leave it unset) 

### 5. Run `docker-compose` Normally

Once the script is installed, you can use `docker-compose` as usual:

```bash
docker-compose up
docker-compose down
docker-compose ps
```

If the script finds an image that requires attestation and it has not been verified, it will block the execution with a message. Otherwise, it will run the `docker-compose` command normally.

## How It Works

- The script checks **Docker images** specified in `docker-compose.yml`.
- For images matching `blockstack/sbtc:signer*` or `blockstack/sbtc:blocklist-client*`, the script verifies their **attestation** status using GitHub CLI.
- If the image is **not attested**, the script blocks the execution and outputs an error.
- If the image is verified, it allows the Docker container to run.
- The **attestation check** can be skipped by setting `SKIP_CHECK=true` in the `.env` file.

## Dependencies

- **GitHub CLI**: The script will try to login to Github, if an error is triggered you can log in by running:

```bash
gh auth login
```
