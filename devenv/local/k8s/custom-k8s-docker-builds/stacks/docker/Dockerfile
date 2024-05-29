FROM blockstack/stacks-core:2.5.0.0.3
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
WORKDIR /

COPY . .

# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo jq curl


RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# --------------------------------------------
RUN chmod +rwx ./entrypoint.sh
# --------------------------------------------


EXPOSE 20444
EXPOSE 20443
CMD ["./entrypoint.sh"]