FROM node:20-bookworm as builder
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"


ARG GIT_URI='https://github.com/hirosystems/stacks-regtest-env.git'
ARG GIT_BRANCH='feat/signer'

WORKDIR /root

# Download the stacks-regtest-env code
RUN mkdir /root/stacks-regtest-env
RUN git clone ${GIT_URI} -b ${GIT_BRANCH} /root/stacks-regtest-env
RUN pwd
RUN ls




FROM node:20-bookworm

RUN apt-get update && apt-get install -y curl gettext-base jq

WORKDIR /root

# Copy over the stacking typescript project into workdir
COPY --from=builder /root/stacks-regtest-env/stacking/package.json /root/
RUN npm i

COPY --from=builder /root/stacks-regtest-env/stacking/stacking.ts /root/
COPY --from=builder /root/stacks-regtest-env/stacking/common.ts /root/
COPY --from=builder /root/stacks-regtest-env/stacking/monitor.ts /root/
COPY --from=builder /root/stacks-regtest-env/stacking/tx-broadcaster.ts /root/


CMD ["npx", "tsx", "/root/stacking.ts"]