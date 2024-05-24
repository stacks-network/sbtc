# --------------------------------------------------------
FROM node:18-alpine AS build
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>


ARG GIT_URI='https://github.com/hirosystems/explorer.git'
ARG GIT_BRANCH='v1.170.1'

WORKDIR /app
RUN apk add --no-cache git python3 make g++
RUN git clone ${GIT_URI} -b ${GIT_BRANCH} .
RUN npm config set registry http://registry.npmjs.org
RUN npm install -g pnpm
RUN pnpm i
RUN pnpm build

# --------------------------------------------------------
FROM node:18-alpine
WORKDIR /app

COPY --from=build /app/next.config.js /app/next.config.js
COPY --from=build /app/public /app/public
COPY --from=build /app/.next/static /app/.next/static
COPY --from=build /app/.next/standalone /app

EXPOSE 3020
EXPOSE 3000
CMD [ "node", "server.js" ]