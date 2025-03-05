# **Docker Image with Attestation Verification**

This repository provides a Docker image that can be used to run a signer application with **attestation verification**. Before running the application, the image verifies its attestation, ensuring that the image and its contents are trusted.

## **Features**
- **Attestation Verification**: Verifies the integrity of the Docker image before execution using GitHub's attestation tools.
- **Custom Entry Point**: Uses a custom entry point script to enforce attestation verification before running the signer app.
- **Supports Local Files for Attestation**: Instead of URLs, this setup uses local file paths for the attestation bundle and trusted root.

---

## **Environment Variables**

- `TAG`: The tag of the Docker image you want to verify (e.g., `signer-test-attestation`).
- `BUNDLE_PATH`: Local path to the attestation bundle file (e.g., `/path/to/bundle.jsonl`).
- `TRUSTED_ROOT_PATH`: Local path to the trusted root file (e.g., `/path/to/trusted_root.jsonl`).

---

## **Example Docker Command:**

To run your Docker image and perform attestation verification, use the following command:

```bash
docker run --rm \
  -e TAG="signer" \
  -e BUNDLE_PATH="/path/to/your/bundle.jsonl" \
  -e TRUSTED_ROOT_PATH="/path/to/your/trusted_root.jsonl" \
  -v /path/to/your/bundle.jsonl:/path/to/your/bundle.jsonl \
  -v /path/to/your/trusted_root.jsonl:/path/to/your/trusted_root.jsonl \
  --entrypoint /entrypoint.sh \
  image_name \
  /usr/local/bin/signer --config /signer-config.toml --migrate-db
```

```bash
docker run --rm \
  -e TAG="blocklist-cli" \
  -e BUNDLE_PATH="/path/to/your/bundle.jsonl" \
  -e TRUSTED_ROOT_PATH="/path/to/your/trusted_root.jsonl" \
  -v /path/to/your/bundle.jsonl:/path/to/your/bundle.jsonl \
  -v /path/to/your/trusted_root.jsonl:/path/to/your/trusted_root.jsonl \
  --entrypoint /entrypoint.sh \
  image_name \
  /usr/local/bin/blocklist-client
```

This command will:
1. **Set the environment variables**:
    - `TAG="signer"`: This sets the image tag used to identify the Docker image for verification.
    - `BUNDLE_PATH="/path/to/your/bundle.jsonl"`: Specifies the local path to the attestation bundle file.
    - `TRUSTED_ROOT_PATH="/path/to/your/trusted_root.jsonl"`: Specifies the local path to the trusted root file for the attestation.
  
2. **Use `/entrypoint.sh`**: The entrypoint of the Docker image is overridden to run the `entrypoint.sh` script, which performs the attestation verification before running the application.
   
3. **Run the Signer Application**: The signer application is started with the provided configuration file (`/signer-config.toml`) and the database will be migrated using the `--migrate-db` flag.

---

## **Example Docker Compose Configuration:**

```yaml
services:
  signer:
    image: signer
    environment:
      - TAG="signer"  # Set your specific image tag
      - BUNDLE_PATH="/path/to/your/bundle.jsonl"
      - TRUSTED_ROOT_PATH="/path/to/your/trusted_root.jsonl"
    volumes:
      - /path/to/your/bundle.jsonl:/path/to/your/bundle.jsonl
      - /path/to/your/trusted_root.jsonl:/path/to/your/trusted_root.jsonl
    entrypoint: ["/entrypoint.sh"]
    command: ["/usr/local/bin/signer", "--config", "/signer-config.toml", "--migrate-db"]
```

```yaml
services:
  signer:
    image: blocklist-cli
    environment:
      - TAG="blocklist-cli"  # Set your specific image tag
      - BUNDLE_PATH="/path/to/your/bundle.jsonl"
      - TRUSTED_ROOT_PATH="/path/to/your/trusted_root.jsonl"
    volumes:
      - /path/to/your/bundle.jsonl:/path/to/your/bundle.jsonl
      - /path/to/your/trusted_root.jsonl:/path/to/your/trusted_root.jsonl
    entrypoint: ["/entrypoint.sh"]
    command: ["/usr/local/bin/blocklist-client"]
```

This will:
1. **Set up the Docker container** with the required environment variables for attestation.
2. **Use `/entrypoint.sh`**: The entry point script checks the attestation and proceeds if verified.
3. **Run the signer application** with the provided config file and migration option.

To start the service with Docker Compose, use:

```bash
docker-compose up
```
---

## **Additional Information**

The image requires the GitHub CLI (`gh`) to verify the attestation.