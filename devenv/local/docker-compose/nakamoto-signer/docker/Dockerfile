FROM blockstack/stacks-core:2.5.0.0.3
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"
COPY . .

ARG SIGNER_ENDPOINT
ARG MY_HTTP_AUTH_TOKEN
ARG STACKS_PRIVATE_KEY
ARG STACKS_NODE_RPC_HOST
ARG STACKS_NODE_RPC_PORT
ARG RUST_BACKTRACE

ENV SIGNER_ENDPOINT=$SIGNER_ENDPOINT
ENV MY_HTTP_AUTH_TOKEN=$MY_HTTP_AUTH_TOKEN
ENV STACKS_PRIVATE_KEY=$STACKS_PRIVATE_KEY
ENV STACKS_NODE_RPC_HOST=$STACKS_NODE_RPC_HOST
ENV STACKS_NODE_RPC_PORT=$STACKS_NODE_RPC_PORT
ENV RUST_BACKTRACE=$RUST_BACKTRACE

# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# --------------------------------------------
RUN chmod +rwx ./entrypoint.sh

EXPOSE 30000
CMD ["./entrypoint.sh"]