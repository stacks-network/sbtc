FROM ubuntu:jammy

MAINTAINER Joey Yandle

RUN apt-get update
RUN apt-get install -y wget pkg-config gcc automake autoconf autotools-dev libtool man gdb git screen sudo rsync
RUN apt-get install -y cargo
RUN cargo install --locked cargo-lambda

COPY .screenrc /root/

ENTRYPOINT /bin/bash
