FROM blockstack/stacks-core:2.5.0.0.3
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"
COPY . .

ARG STACKS_LOG_DEBUG
ARG STACKS_LOG_JSON


ENV STACKS_LOG_DEBUG=$STACKS_LOG_DEBUG
ENV STACKS_LOG_JSON=$STACKS_LOG_JSON


# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo jq curl
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY config.toml .
# --------------------------------------------
# The container creates this the config.toml internally
RUN chmod +rwx ./entrypoint.sh
# --------------------------------------------


# COPY node-config.toml /config.toml
EXPOSE 20444
EXPOSE 20443
CMD ["./entrypoint.sh"]