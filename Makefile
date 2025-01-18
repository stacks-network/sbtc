# The absolute path to the directory containing the Makefile.
WORKING_DIR := $(realpath $(shell dirname $(firstword $(MAKEFILE_LIST))))

# Common Folders.
AUTOGENERATED_SOURCES := .generated-sources

# Don't use the install target here so you can rerun install without
# Makefile complaints.
export DATABASE_URL=postgres://user:password@localhost:5432/signer

# The package flags for cargo commands. If we do not specify
CARGO_FLAGS := --workspace --exclude emily-openapi-spec --exclude blocklist-openapi-gen

# ##############################################################################
# MAIN TARGETS
# ##############################################################################

install:
	pnpm install

build: blocklist-client-codegen emily-client-codegen
	cargo build --all-targets $(CARGO_FLAGS) ${CARGO_BUILD_ARGS}

test:
	cargo nextest run --lib $(CARGO_FLAGS) --no-fail-fast ${CARGO_BUILD_ARGS}
	pnpm --recursive test

test-build:
	cargo test build $(CARGO_FLAGS) --no-run --locked ${CARGO_BUILD_ARGS}

lint:
	cargo fmt --all -- --check
	cargo clippy -- -D warnings
	pnpm --recursive run lint

format:
	cargo fmt

contracts:
	pnpm --prefix contracts run build

clean:
	cargo clean
	pnpm --recursive clean

.PHONY: install build test test-build lint format contracts clean

# ##############################################################################
# NEXTEST
# ##############################################################################

NEXTEST_ARCHIVE_FILE := target/nextest/nextest-archive.tar.zst
NEXTEST_SERIAL_ARCHIVE_FILE := target/nextest/nextest-archive-serial.tar.zst

# Creates nextest archives
nextest-archive:
	cargo nextest archive $(CARGO_FLAGS) --lib --archive-file $(NEXTEST_ARCHIVE_FILE) ${CARGO_BUILD_ARGS}
	cargo nextest archive $(CARGO_FLAGS) --archive-file $(NEXTEST_SERIAL_ARCHIVE_FILE) --test integration ${CARGO_BUILD_ARGS}

# Runs nextest archives
nextest-archive-run:
	cargo nextest run --no-fail-fast --retries 2 --archive-file $(NEXTEST_ARCHIVE_FILE)
	cargo nextest run --no-fail-fast --test-threads 1 --retries 2 --archive-file $(NEXTEST_SERIAL_ARCHIVE_FILE)

nextest-archive-clean:
	rm -f $(NEXTEST_ARCHIVE_FILE) $(NEXTEST_SERIAL_ARCHIVE_FILE)

.PHONY: nextest-archive nextest-archive-run nextest-archive-clean

# ##############################################################################
# INTEGRATION TESTS
# ##############################################################################

integration-env-up: emily-cdk-synth
	docker compose --file docker/docker-compose.test.yml up -d

integration-test:
	cargo nextest run $(CARGO_FLAGS) --test integration --no-fail-fast --test-threads 1

integration-test-build:
	cargo test build $(CARGO_FLAGS) --test integration --no-run --locked

integration-env-down:
	docker compose --file docker/docker-compose.test.yml down -v

integration-env-build:
	docker compose --file docker/docker-compose.test.yml build

integration-test-full: integration-env-down integration-env-up integration-test integration-env-down

integration-env-up-ci: emily-cdk-synth
	docker compose --file docker/docker-compose.ci.yml up --detach --quiet-pull
	DYNAMODB_ENDPOINT=http://localhost:8000 \
		INPUT_CDK_TEMPLATE=./emily/cdk/cdk.out/EmilyStack.template.json \
		OUTPUT_CDK_TEMPLATE=./emily/cdk/cdk.out/EmilyStack.devenv.template.json \
		LOCAL_LAMBDA_PATH=empty.zip \
		TRUSTED_REORG_API_KEY=testApiKey \
		python3 docker/sbtc/emily-aws-setup/initialize.py
	cargo build --bin emily-server
	AWS_ACCESS_KEY_ID=xxxxxxxxxxxx \
		AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx \
		AWS_REGION=us-west-2 \
		TRUSTED_REORG_API_KEY=testApiKey \
		cargo run --bin emily-server -- \
			--host 127.0.0.1 --port 3031 --dynamodb-endpoint http://localhost:8000 > ./target/emily-server.log 2>&1 &

integration-env-down-ci:
	docker compose --file docker/docker-compose.ci.yml down
	@echo "killing emily server process..."
	ps -ef | awk  '/[e]mily-server/{print $$2}' | xargs kill -9

.PHONY: integration-env-up integration-test integration-test-build integration-env-up integration-test-full

# ##############################################################################
# DEVENV (development testing environment)
# ##############################################################################

devenv-no-sbtc-up:
	docker compose -f docker/docker-compose.yml --profile default --profile bitcoin-mempool up

devenv-no-sbtc-down:
	docker compose -f docker/docker-compose.yml --profile default --profile bitcoin-mempool down

devenv-up:
	docker compose -f docker/docker-compose.yml --profile default --profile bitcoin-mempool --profile sbtc-signer up --detach

devenv-down:
	docker compose -f docker/docker-compose.yml --profile default --profile bitcoin-mempool --profile sbtc-signer down

devenv-sbtc-up:
	docker compose -f docker/docker-compose.yml --profile sbtc-signer up --build

devenv-sbtc-down:
	docker compose -f docker/docker-compose.yml --profile sbtc-signer down

# ##############################################################################
# EMILY
# ##############################################################################

# ------------------------------------------------------------------------------
# - EMILY CDK TEMPLATE
# ------------------------------------------------------------------------------

# Variables
EMILY_CDK_TEMPLATE := emily/cdk/cdk.out/EmilyStack.template.json
EMILY_CDK_PROJECT_NAME := emily-cdk
EMILY_CDK_SOURCE_FILES := $(shell find emily/cdk/lib -type f)

# Generates the CloudFormation template for the Emily CDK project if any of the
# source files are older than the template.
$(EMILY_CDK_TEMPLATE): $(EMILY_CDK_SOURCE_FILES)
	AWS_STAGE=local \
	TABLES_ONLY=true \
	TRUSTED_REORG_API_KEY=testApiKey \
	pnpm --filter $(EMILY_CDK_PROJECT_NAME) run synth

emily-cdk-synth: $(EMILY_CDK_TEMPLATE)

.PHONY: emily-cdk-synth

# ------------------------------------------------------------------------------
# - EMILY HANDLER
# ------------------------------------------------------------------------------

# Variables
EMILY_HANDLER_PROJECT_NAME := emily-handler
EMILY_HANDLER_SOURCE_FILES := $(shell find emily/handler -type f)
EMILY_LAMBDA_BINARY := target/lambda/emily-handler/bootstrap.zip

# Build the zipped binary for the Emily Handler that AWS Lambda can deploy.
#
# Date: 10-18-2024
# The Emily lamdba binary cannot be built on aarm64 Machines because the `cargo lambda`
# compiler cannot compile an assembly library that is used in the `stacks-common`
# crate that is a downstream dependency of the `emily-handler` crate.
#
# aarm64 machines can still create the x86_64 binary by running the following command, but
# it will not be runnable using the SAM CLI on aarm64 machines.
$(EMILY_LAMBDA_BINARY): $(EMILY_HANDLER_SOURCE_FILES)
	cargo lambda build \
		--release \
		--package $(EMILY_HANDLER_PROJECT_NAME) \
		--output-format zip

emily-as-lambda: $(EMILY_LAMBDA_BINARY)

.PHONY: emily-as-lambda

# ------------------------------------------------------------------------------
# - EMILY CLIENT
# ------------------------------------------------------------------------------

# Variables
EMILY_OPENAPI_DIR := emily/openapi-gen
EMILY_OPENAPI_SPECS_DIR := $(EMILY_OPENAPI_DIR)/generated-specs
EMILY_OPENAPI_SPEC_PROJECT_NAME := emily-openapi-spec
EMILY_OPENAPI_SPEC_PATHS := $(shell find $(EMILY_OPENAPI_SPECS_DIR) -type f -name '*.json')
EMILY_OPENAPI_SOURCE_FILES := $(shell find $(EMILY_OPENAPI_DIR) -type f -not -path '$(EMILY_OPENAPI_SPECS_DIR)/*')
EMILY_CLIENTS_DIR := $(AUTOGENERATED_SOURCES)/emily/client/rust
EMILY_CLIENT_SOURCE_FILES := $(shell find $(EMILY_CLIENTS_DIR) -type f -name 'lib.rs')

# Generates the OpenAPI specs for the Emily API if any of the spec files are
# older than any of the source files. Note that this generates three spec files,
# one for each of the Emily API variants (public, private, testing).
$(EMILY_OPENAPI_SPEC_PATHS): $(EMILY_OPENAPI_SOURCE_FILES)
	@echo "Generating Emily OpenAPI spec"
	cargo build --package $(EMILY_OPENAPI_SPEC_PROJECT_NAME) --target-dir ./target/emily-spec-gen ${CARGO_BUILD_ARGS}

# Generate Rust client code for the Emily APIs if any of the generated source
# files are older than any of the spec files. Note that this generates the code
# for all three Emily API variants (public, private, testing).
$(EMILY_CLIENT_SOURCE_FILES): $(EMILY_OPENAPI_SPEC_PATHS)
	@echo "Generating Emily client from OpenAPI spec"
	EMILY_CLIENTS_DIR=$(WORKING_DIR)/$(EMILY_CLIENTS_DIR) pnpm --prefix $(EMILY_OPENAPI_DIR) run build
	cargo fmt \
		-p testing-emily-client \
		-p private-emily-client \
		-p emily-client

emily-api-specgen: $(EMILY_OPENAPI_SPEC_PATHS)
emily-client-codegen: emily-api-specgen $(EMILY_CLIENT_SOURCE_FILES)
emily-client-build: emily-client-codegen
	cargo build --package emily-client ${CARGO_BUILD_ARGS}

.PHONY: emily-api-specgen emily-client-codegen emily-client-build

# ##############################################################################
# - BLOCKLIST API
# ##############################################################################

# Variables
BLOCKLIST_OPENAPI_DIR := blocklist-openapi-gen
BLOCKLIST_OPENAPI_SPEC_PATH := $(BLOCKLIST_OPENAPI_DIR)/blocklist-client-openapi.json
BLOCKLIST_OPENAPI_SPEC_PROJECT_NAME := blocklist-openapi-gen
BLOCKLIST_OPENAPI_SOURCE_FILES := $(shell find $(BLOCKLIST_OPENAPI_DIR) -type f ! -name $(notdir $(BLOCKLIST_OPENAPI_SPEC_PATH)))
BLOCKLIST_CLIENT_SOURCE_DIR := $(AUTOGENERATED_SOURCES)/blocklist-api
BLOCKLIST_CLIENT_SOURCE_FILES := $(BLOCKLIST_CLIENT_SOURCE_DIR)/src/lib.rs

# Generates the OpenAPI spec for the Blocklist API if the spec file is older
# than any of the source files.
$(BLOCKLIST_OPENAPI_SPEC_PATH): $(BLOCKLIST_OPENAPI_SOURCE_FILES)
	@echo "Generating Blocklist OpenAPI spec"
	cargo build --package $(BLOCKLIST_OPENAPI_SPEC_PROJECT_NAME) --target-dir ./target/blocklist-spec-gen ${CARGO_BUILD_ARGS}

# Geneate Rust client code for the Blocklist API if any of the generated source
# files are older than the OpenAPI spec file.
$(BLOCKLIST_CLIENT_SOURCE_FILES): $(BLOCKLIST_OPENAPI_SPEC_PATH)
	@echo "Generating blocklist client from openapi spec"
	pnpm --prefix $(BLOCKLIST_OPENAPI_DIR) run build
	cargo fmt -p blocklist-api

blocklist-api-specgen: $(BLOCKLIST_OPENAPI_SPEC_PATH)
blocklist-client-codegen: blocklist-api-specgen $(BLOCKLIST_CLIENT_SOURCE_FILES)

# Build the generated Rust client code for the Blocklist API. This target will
# also build the OpenAPI spec (if needed) and generate the client.
blocklist-client-build: blocklist-client-codegen
	cargo build --package blocklist-api ${CARGO_BUILD_ARGS}

.PHONY: blocklist-api-specgen blocklist-client-codegen blocklist-client-build

# ##############################################################################
# GIT HOOKS
# ##############################################################################

install-git-hooks:
	mkdir -p .git/hooks
	ln -s ../../devenv/hooks/pre-commit-make-lint.sh .git/hooks/

.PHONY: install-git-hooks

