FROM ubuntu:jammy

MAINTAINER Joey Yandle

RUN apt-get update
RUN apt-get install -y curl wget unzip pkg-config gcc automake autoconf autotools-dev libtool man gdb git screen sudo rsync cargo

RUN cargo install --locked cargo-lambda

RUN wget -qO- https://get.pnpm.io/install.sh | bash -

RUN mkdir -p /tmp/smithy-install/smithy
RUN curl -L https://github.com/smithy-lang/smithy/releases/download/1.49.0/smithy-cli-linux-x86_64.zip -o /tmp/smithy-install/smithy-cli-linux-x86_64.zip
RUN unzip -qo /tmp/smithy-install/smithy-cli-linux-x86_64.zip -d /tmp/smithy-install
RUN mv /tmp/smithy-install/smithy-cli-linux-x86_64/* /tmp/smithy-install/smithy
RUN /tmp/smithy-install/smithy/install
RUN rm -rf /tmp/smithy-install

COPY .screenrc /root/

ENTRYPOINT /bin/bash
