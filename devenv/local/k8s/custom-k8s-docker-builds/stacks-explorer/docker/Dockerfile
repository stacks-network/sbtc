# --------------------------------------------------------
FROM node:18-alpine
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>


ARG GIT_URI='https://github.com/hirosystems/explorer.git'
ARG GIT_BRANCH='v1.179.0'

WORKDIR /app
RUN apk add --no-cache git python3 make g++
RUN git clone ${GIT_URI} -b ${GIT_BRANCH} .
RUN npm config set registry http://registry.npmjs.org
RUN npm install -g pnpm
RUN pnpm i
RUN pnpm build



EXPOSE 3020
EXPOSE 3000
CMD [ "npm", "run" , "start" ]