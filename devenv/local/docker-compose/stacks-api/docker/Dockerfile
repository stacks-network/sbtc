FROM node:16-alpine
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"

ARG GIT_URI='https://github.com/hirosystems/stacks-blockchain-api.git'
ARG GIT_BRANCH='46e1ae256e474eac98979d0a3df685fe3fa48d6d'

WORKDIR /app

RUN apk add --no-cache --virtual .build-deps alpine-sdk python3 git openjdk8-jre cmake
RUN git clone ${GIT_URI} -b ${GIT_BRANCH} .
RUN echo "GIT_TAG=$(git tag --points-at HEAD)" >> .env
RUN npm config set unsafe-perm true && npm ci && npm run build && npm run build:docs && npm prune --production
RUN apk del .build-deps

EXPOSE 3999
EXPOSE 3700
CMD ["node", "./lib/index.js"]
