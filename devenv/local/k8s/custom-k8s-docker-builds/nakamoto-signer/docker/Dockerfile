FROM blockstack/stacks-core:2.5.0.0.3
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
COPY . .

# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# -------------ENTRYPOINT---------------------
RUN chmod +rwx ./entrypoint.sh

EXPOSE 30000
CMD ["./entrypoint.sh"]