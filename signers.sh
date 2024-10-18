#!/usr/bin/env sh

# shellcheck disable=SC2059
# shellcheck source=/dev/null

# Encoding
LC_CTYPE=en_US.UTF-8

# Colors
GRAY='\e[0;90m' # Gray
RED='\e[0;31m'  # Red
NC='\e[0m'      # No Color
BOLD='\e[1m'    # Bold

DEVENV="$PWD/devenv/local"

LOG_SETTINGS="debug"                                  # Default log level
LOG_SETTINGS="$LOG_SETTINGS,signer::stacks::api=info" # Stacks API
LOG_SETTINGS="$LOG_SETTINGS,hyper=info"               # Hyper
LOG_SETTINGS="$LOG_SETTINGS,sqlx=info"                # SQLx
LOG_SETTINGS="$LOG_SETTINGS,reqwest=info"             # Reqwest
# LibP2P
LOG_SETTINGS="$LOG_SETTINGS,netlink_proto=info,libp2p_autonat=info,libp2p_gossipsub=info,multistream_select=info,yamux=info,libp2p_ping=info,libp2p_kad=info,libp2p_swarm=info,libp2p_tcp=info,libp2p_identify=info,libp2p_dns=info"

# Run the specified number of signers
exec_run() {
	if [ "$1" -eq 1 ]; then
		printf "${RED}ERROR:${NC} At least 2 signers are required\n"
		exit 1
	fi

	printf "${GRAY}Running ${NC}${BOLD}$*${NC} signers\n"
	SIGNER1_KEY=$(
		. "$DEVENV/envs/signer-1.env"
		echo "$SIGNER_PUBKEY"
	)
	SIGNER2_KEY=$(
		. "$DEVENV/envs/signer-2.env"
		echo "$SIGNER_PUBKEY"
	)
	SIGNER3_KEY=$(
		. "$DEVENV/envs/signer-3.env"
		echo "$SIGNER_PUBKEY"
	)

	docker compose -f "$DEVENV/docker-compose/docker-compose.yml" down postgres-1 postgres-2 postgres-3 -v
	docker compose -f "$DEVENV/docker-compose/docker-compose.yml" up -d postgres-1 postgres-2 postgres-3

	if [ "$1" -eq 2 ]; then
		BOOTSTRAP_SIGNER_SET="$SIGNER1_KEY,$SIGNER2_KEY"
	elif [ "$1" -eq 3 ]; then
		BOOTSTRAP_SIGNER_SET="$SIGNER1_KEY,$SIGNER2_KEY,$SIGNER3_KEY"
	fi

	printf "${BOLD}Using bootstrap signer set:${NC} $BOOTSTRAP_SIGNER_SET\n"

	# Run the first signer (always).
	(
		. "$DEVENV/envs/signer-1.env" \
			&& RUST_LOG="$LOG_SETTINGS" \
			&& SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" \
			&& cargo run --bin sbtc-signer -- --config "$DEVENV/docker-compose/sbtc-signer/signer-config.toml" --migrate-db >"$PWD/target/signer-1.log" 2>&1 \
			&
	)
	# Run the second signer if the requested signer count >= 2.
	if [ "$1" -ge 2 ]; then
		(
			. "$DEVENV/envs/signer-2.env" \
				&& RUST_LOG="$LOG_SETTINGS" \
				&& SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" \
				&& cargo run --bin sbtc-signer -- --config "$DEVENV/docker-compose/sbtc-signer/signer-config.toml" --migrate-db >"$PWD/target/signer-2.log" 2>&1 \
				&
		)
	fi
	# Run the third signer if the requested signer count >= 3.
	if [ "$1" -ge 3 ]; then
		(
			. "$DEVENV/envs/signer-3.env" \
				&& RUST_LOG="$LOG_SETTINGS" \
				&& SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" \
				&& cargo run --bin sbtc-signer -- --config "$DEVENV/docker-compose/sbtc-signer/signer-config.toml" --migrate-db >"$PWD/target/signer-3.log" 2>&1 \
				&
		)
	fi

	printf "${GRAY}$* signers started${NC}\n"
}

# Clean db
exec_clean_db() {
	docker compose -f "$DEVENV/docker-compose/docker-compose.yml" down postgres-1 postgres-2 postgres-3 -v
	docker compose -f "$DEVENV/docker-compose/docker-compose.yml" up -d postgres-1 postgres-2 postgres-3
}

exec_demo() {
	cargo run -p signer --bin demo-cli deposit --amount 42 --max-fee 20000 --lock-time 50 --stacks-addr ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039 --signer-key "$1"
	cargo run -p signer --bin demo-cli donation --amount 2000000 --signer-key "$1"
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
		# Clean db
		"clean")
			shift # Shift the command off the argument list
			exec_clean_db "$@"
			;;
		# Run demo things
		"demo")
			shift # Shift the command off the argument list
			exec_demo "$@"
			;;
		# Stop all running signers by killing the processes.
		"stop")
			ps -ef | awk '/[s]btc-signer/{print $2}' | xargs kill -9
			;;
		*)
			printf "${RED}ERROR:${NC} Unknown command: $1\n"
			exit 1
			;;
	esac
}

# Run the main function with all the command line arguments
main "$@"
