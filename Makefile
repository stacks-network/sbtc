# Convenience data so we can run the following and include
# sources from three directories deep.
#
# Example:
# $(subst dir, emily/cdk/lib, $(THREE_DIRS_DEEP))
# becomes
# emily/cdk/lib/*  emily/cdk/lib/*/*  emily/cdk/lib/*/*/*
THREE_DIRS_DEEP := dir/* dir/*/* dir/*/*/*
TWO_DIRS_DEEP := dir/* dir/*/*

AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT := .generated-sources/blocklist-api/src/lib.rs
BLOCKLIST_OPENAPI_PATH=./.generated-sources/blocklist-openapi-gen
BLOCKLIST_OPENAPI_SPEC=$(BLOCKLIST_OPENAPI_PATH)/blocklist-client-openapi.json

AUTOGENERATED_EMILY_CLIENT := .generated-sources/emily/src/lib.rs
EMILY_LAMBDA_BINARY := target/lambda/emily-lambda/bootstrap.zip
EMILY_CDK_TEMPLATE := emily/cdk/cdk.out/EmilyStack.template.json
EMILY_DOCKER_COMPOSE := docker-compose.emily.yml
INSTALL_TARGET := pnpm-lock.yaml

# Don't use the install target here so you can rerun install without
# Makefile complaints.
include .env

install:
	pnpm install
	touch pnpm-lock.yaml

build: $(INSTALL_TARGET) $(AUTOGENERATED_EMILY_CLIENT) $(AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT)
	cargo build
	pnpm --recursive build

test: $(INSTALL_TARGET) $(AUTOGENERATED_EMILY_CLIENT) $(AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT)
	cargo test
	pnpm --recursive test

integration-test: $(INSTALL_TARGET) $(AUTOGENERATED_EMILY_CLIENT) $(AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT)
	docker compose --file docker-compose.test.yml up --detach

	cd signer && sqlx migrate run

	cargo test --test integration --all-features -- --test-threads=1
	pnpm --recursive test
	docker compose --file docker-compose.test.yml down

lint: $(INSTALL_TARGET) $(AUTOGENERATED_EMILY_CLIENT) $(AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT)
	SQLX_OFFLINE=true cargo clippy -- -D warnings
	pnpm --recursive run lint

clean:
	cargo clean
	pnpm --recursive clean
	rm -rf devenv/dynamodb/data/*
	@touch package.json

.PHONY: install build test integration-test lint clean

$(INSTALL_TARGET): $(wildcard package* */package* */*/package*)
	pnpm install
	touch pnpm-lock.yaml

# Emily API
# ----------------------------------------------------

EMILY_DEVENV_PATH=emily/devenv
EMILY_LAMBDA_PATH=emily/lambda
EMILY_API_PROJECT_NAME=emily-api
EMILY_CDK_PROJECT_NAME=emily-cdk
CONTAINER_HOST=host.docker.internal

ifeq ($(findstring Linux, $(shell uname)), Linux)
_CONTAINER_HOST := localhost
else
_CONTAINER_HOST := host.docker.internal
endif

# Launches Emily dev environment.
emily-integration-test: devenv $(EMILY_LAMBDA_BINARY) $(EMILY_CDK_TEMPLATE) $(EMILY_DOCKER_COMPOSE)
	CONTAINER_HOST=$(_CONTAINER_HOST) docker compose --file docker-compose.emily.yml up \
		--remove-orphans
.PHONY: emily-integration-test

# Builds all dockerfiles that need to be built for the dev environment.
devenv: $(wildcard $(subst dir, devenv, $(TWO_DIRS_DEEP)))
	docker compose -f docker-compose.emily.yml build
	@touch devenv

ifneq ($(filter arm64 aarch64, $(shell uname -m)),)
_LAMBDA_FLAGS := --arm64
endif

$(EMILY_CDK_TEMPLATE): $(INSTALL_TARGET) $(wildcard $(subst dir, emily/cdk/lib, $(THREE_DIRS_DEEP)) $(subst dir, emily/cdk/bin, $(THREE_DIRS_DEEP)))
	AWS_STAGE=local \
	pnpm --filter $(EMILY_CDK_PROJECT_NAME) run synth

$(EMILY_LAMBDA_BINARY): $(AUTOGENERATED_EMILY_CLIENT)
	cd $(EMILY_LAMBDA_PATH) && cargo lambda build \
		--release \
		--package emily-lambda \
		--output-format zip \
		$(_LAMBDA_FLAGS)

$(AUTOGENERATED_EMILY_CLIENT): $(INSTALL_TARGET) $(wildcard emily/api-definition/* emily/api-definition/models/* emily/api-definition/models/*/*)
	pnpm --filter $(EMILY_API_PROJECT_NAME) run build

# Blocklist Client API
# ----------------------------------------------------

# Generate the client code using the OpenAPI spec
$(AUTOGENERATED_BLOCKLIST_CLIENT_CLIENT): $(BLOCKLIST_OPENAPI_SPEC)
	pnpm --prefix $(BLOCKLIST_OPENAPI_PATH) run build

# Generate the OpenAPI spec for Blocklist Client
$(BLOCKLIST_OPENAPI_SPEC): $(INSTALL_TARGET) $(filter-out $(BLOCKLIST_OPENAPI_SPEC), $(wildcard $(subst dir, $(BLOCKLIST_OPENAPI_PATH), $(THREE_DIRS_DEEP))))
	cd ./.generated-sources/blocklist-openapi-gen && cargo build
