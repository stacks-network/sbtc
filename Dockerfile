FROM ubuntu:jammy

LABEL org.opencontainers.image.authors="Joey Yandle <joey@trustmachines.co>"

RUN apt-get update
RUN apt-get install -y curl wget unzip pkg-config gcc automake autoconf autotools-dev libtool man gdb git screen sudo rsync cargo protobuf-compiler libssl-dev make libclang-dev

RUN cargo install --locked cargo-lambda

RUN wget -qO- https://get.pnpm.io/install.sh | bash -

RUN mkdir -p /tmp/smithy-install/smithy
RUN curl -L https://github.com/smithy-lang/smithy/releases/download/1.49.0/smithy-cli-linux-aarch64.zip -o /tmp/smithy-install/smithy-cli-linux-aarch64.zip
RUN unzip -qo /tmp/smithy-install/smithy-cli-linux-aarch64.zip -d /tmp/smithy-install
RUN mv /tmp/smithy-install/smithy-cli-linux-aarch64/* /tmp/smithy-install/smithy
RUN /tmp/smithy-install/smithy/install
RUN rm -rf /tmp/smithy-install

RUN cargo install sqlx-cli

RUN mkdir -p /tmp/node-install
RUN curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/node-install/nodesource_setup.sh
RUN bash /tmp/node-install/nodesource_setup.sh
RUN apt-get -y install nodejs

RUN mkdir -p /tmp/rustup-install
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-install/rustup-install.sh
RUN chmod +x /tmp/rustup-install/rustup-install.sh
RUN /tmp/rustup-install/rustup-install.sh -y

RUN rm -rf /tmp/smithy-install
RUN rm -rf /tmp/node-install
RUN rm -rf /tmp/rustup-install

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

ENTRYPOINT /bin/bash
