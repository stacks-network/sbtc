#!/usr/bin/env sh

# shellcheck disable=SC2059
# shellcheck source=/dev/null

# Encoding
LC_CTYPE=en_US.UTF-8

# Colors
GRAY='\e[0;90m'        # Gray
RED='\e[0;31m'          # Red
NC='\e[0m' # No Color
BOLD='\e[1m' # Bold

PROJECT_ROOT="$PWD"
SIGNER_CONFIG="$PROJECT_ROOT/docker/sbtc/signer/signer-config.toml"
ENV_PATH="$PROJECT_ROOT/envs"
DOCKER_COMPOSE_PATH="$PROJECT_ROOT/docker/docker-compose.yml"

LOG_SETTINGS="debug" # Default log level
LOG_SETTINGS="$LOG_SETTINGS,signer::stacks::api=info" # Stacks API
LOG_SETTINGS="$LOG_SETTINGS,hyper=info" # Hyper
LOG_SETTINGS="$LOG_SETTINGS,sqlx=info" # SQLx
LOG_SETTINGS="$LOG_SETTINGS,reqwest=info" # Reqwest
# LibP2P
LOG_SETTINGS="$LOG_SETTINGS,netlink_proto=info,libp2p_autonat=info,libp2p_gossipsub=info,multistream_select=info,yamux=info,libp2p_ping=info,libp2p_kad=info,libp2p_swarm=info,libp2p_tcp=info,libp2p_identify=info,libp2p_dns=info"

# Run the specified number of signers
exec_run() {
  echo "here!"

  if [ "$1" -eq 1 ]; then
    printf "${RED}ERROR:${NC} At least 2 signers are required\n"
    exit 1
  fi

  printf "${GRAY}Running ${NC}${BOLD}$*${NC} signers\n"

  # Turn all the relevant postgres instances off and on.
  i=1
  while [ $i -le "$1" ]
  do
    docker compose -f "$DOCKER_COMPOSE_PATH" down postgres-"$i"
    docker compose -f "$DOCKER_COMPOSE_PATH" up postgres-"$i -d"
    i=$((i + 1))
  done

  # Setup the bootstrap signer set.
  i=1
  BOOTSTRAP_SIGNER_SET=""
  while [ $i -le "$1" ]
  do
    SIGNER_KEY=$(. "$ENV_PATH/signer-$i.env"; echo "$SIGNER_PUBKEY")
    if [ "$BOOTSTRAP_SIGNER_SET" = "" ]; then
      export BOOTSTRAP_SIGNER_SET="$SIGNER_KEY"
    else
      export BOOTSTRAP_SIGNER_SET="$BOOTSTRAP_SIGNER_SET,$SIGNER_KEY"
    fi
    i=$((i + 1))
  done

  printf "${BOLD}Using bootstrap signer set:${NC} $BOOTSTRAP_SIGNER_SET\n"

  # Spin up the specified number of signers.
  i=1
  while [ $i -le "$1" ]
  do
    (
      . "$ENV_PATH/signer-$i.env" \
      && export RUST_LOG="$LOG_SETTINGS" \
      && export SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" \
      && cargo run --bin sbtc-signer -- --config "$SIGNER_CONFIG" --migrate-db > "$PWD/target/signer-$i.log" 2>&1 \
      &
    )
    i=$((i + 1))
  done

  printf "${GRAY}$* signers started${NC}\n"
}

# The main function
main() {
  if [ "$#" -eq 0 ]; then
    printf "${RED}ERROR:${NC} No command provided\n"
    exit 0
  fi

  # Parse the command line arguments
  case "$1" in
    # Run the specified number of signers. Valid values are 2 or 3.
    "run")
      shift # Shift the command off the argument list
      exec_run "$@"
    ;;
    # Stop all running signers by killing the processes.
    "stop")
      ps -ef | awk  '/[s]btc-signer/{print $2}' | xargs kill -9
    ;;
    *)
      printf "${RED}ERROR:${NC} Unknown command: $1\n"
      exit 1
  esac
}

# Run the main function with all the command line arguments
main "$@"
