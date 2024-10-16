#!/usr/bin/env sh

# Encoding
LC_CTYPE=en_US.UTF-8

# Colors
GRAY='\e[0;90m'        # Gray
RED='\e[0;31m'          # Red
NC='\e[0m' # No Color
BOLD='\e[1m' # Bold

DEVENV="$PWD/devenv/local"

exec_run() {
  if [ "$1" -eq 1 ]; then
    printf "${RED}ERROR:${NC} At least 2 signers are required\n"
    exit 1
  fi

  printf "${GRAY}Running ${NC}${BOLD}$@${NC} signers\n"
  SIGNER1_KEY=$(. $DEVENV/envs/signer-1.env; echo "$SIGNER_PUBKEY")
  SIGNER2_KEY=$(. $DEVENV/envs/signer-2.env; echo "$SIGNER_PUBKEY")
  SIGNER3_KEY=$(. $DEVENV/envs/signer-3.env; echo "$SIGNER_PUBKEY")

  docker compose -f $DEVENV/docker-compose/docker-compose.yml down postgres-1 postgres-2 postgres-3 -v
  docker compose -f $DEVENV/docker-compose/docker-compose.yml up -d postgres-1 postgres-2 postgres-3

  if [ "$1" -eq 2 ]; then
    BOOTSTRAP_SIGNER_SET="$SIGNER1_KEY,$SIGNER2_KEY"
  elif [ "$1" -eq 3 ]; then
    BOOTSTRAP_SIGNER_SET="$SIGNER1_KEY,$SIGNER2_KEY,$SIGNER3_KEY"
  fi

  RESULT1=$(. $DEVENV/envs/signer-1.env && SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" && cargo run --bin sbtc-signer -- --config $DEVENV/docker-compose/sbtc-signer/signer-config.toml --migrate-db > $PWD/target/signer-1.log 2>&1 &)
  if [ "$1" -ge 2 ]; then
    RESULT2=$(. $DEVENV/envs/signer-2.env && SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" && cargo run --bin sbtc-signer -- --config $DEVENV/docker-compose/sbtc-signer/signer-config.toml --migrate-db > $PWD/target/signer-2.log 2>&1 &)
  fi
  if [ "$1" -ge 3 ]; then
    RESULT3=$(. $DEVENV/envs/signer-3.env && SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" && cargo run --bin sbtc-signer -- --config $DEVENV/docker-compose/sbtc-signer/signer-config.toml --migrate-db > $PWD/target/signer-3.log 2>&1 &)
  fi

  printf "${GRAY}$* signers started${NC}\n"
}

main() {
  if [ "$#" -eq 0 ]; then
    printf "${RED}ERROR:${NC} No command provided\n"
    exit 0
  fi

  # Parse the command line arguments
  case "$1" in
    "run")
      shift # Shift the command off the argument list
      exec_run "$@"
    ;;
    "stop")
      ps -ef | awk  '/[s]btc-signer/{print $2}' | xargs kill -9
    ;;
  esac
}

main "$@"