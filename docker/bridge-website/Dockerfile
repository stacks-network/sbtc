FROM debian:bookworm-slim

RUN apt-get update
RUN apt-get install -y \
    git \
    npm

RUN mkdir /code
WORKDIR /code
RUN git clone https://github.com/stacks-network/sbtc-bridge
WORKDIR /code/sbtc-bridge
RUN npm install

ENV NEXT_TELEMETRY_DISABLED="1"
CMD [ "npm", "run", "dev" ]
