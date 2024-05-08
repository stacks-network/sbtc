FROM blockstack/stacks-core:2.5.0.0.3
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
COPY . .
# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo

# RUN adduser --disabled-password --gecos '' docker
# RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# --------------------------------------------
# The container creates this the config.toml internally
RUN chmod +rwx ./entrypoint.sh
RUN sudo ./entrypoint.sh 
# --------------------------------------------


# COPY node-config.toml /config.toml
EXPOSE 20444
EXPOSE 20443
CMD ["stacks-node", "start", "--config", "/config.toml"]