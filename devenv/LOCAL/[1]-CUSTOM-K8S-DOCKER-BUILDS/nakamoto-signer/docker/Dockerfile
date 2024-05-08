# Needed ENV Variables:

# - SINGER_ENDPOINT
# - MY_HTTP_AUTH_TOKEN
# - STACKS_PRIVATE_KEY

FROM blockstack/stacks-core:2.5.0.0.3
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
COPY . .

# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo

# RUN adduser --disabled-password --gecos '' docker
# RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# USER docker
# --------------------------------------------

# The container creates this the config.toml internally
RUN chmod +rwx ./entrypoint.sh
RUN sudo ./entrypoint.sh 

EXPOSE 30000
CMD ["stacks-signer", "run", "--config", "/config.toml"]