FROM rust:bookworm AS build
# Taken from the clarinet repository here:
# https://github.com/hirosystems/clarinet/blob/0cce4d8302a786114fd6efaad31aeab81e27f071/dockerfiles/components/clarinet-dev.dockerfile#L1

WORKDIR /src

RUN apt update && apt install -y ca-certificates pkg-config libssl-dev libclang-dev

RUN rustup update stable && rustup default stable && rustup toolchain install stable --component rustfmt

# Altered portion.
ARG GIT_BRANCH=v2.10.0
RUN git clone https://github.com/hirosystems/clarinet
WORKDIR /src/clarinet
RUN git checkout $(GIT_BRANCH)
# Altered portion.

RUN mkdir /out

RUN cargo build --features=telemetry --release --locked

RUN cp target/release/clarinet /out

FROM debian:bookworm-slim

RUN apt update && apt install -y libssl-dev

COPY --from=build /out/ /bin/

WORKDIR /workspace

ENV CLARINET_MODE_CI=1

ENTRYPOINT ["clarinet"]
