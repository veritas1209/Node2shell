ARG NODE_IMAGE=mirror.gcr.io/library/node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5
FROM ${NODE_IMAGE}

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

COPY server.js ./server.js
COPY n2s /n2s
COPY supervise.sh /usr/local/bin/node2shell-supervise
RUN chmod 0555 /n2s /usr/local/bin/node2shell-supervise \
    && chown -R node:node /app

USER node
EXPOSE 3000
ENV UV_THREADPOOL_SIZE=1
ENTRYPOINT ["/usr/local/bin/node2shell-supervise"]
