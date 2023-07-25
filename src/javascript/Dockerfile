ARG VERSION=20
FROM node:${VERSION} AS builder

LABEL org.opencontainers.image.source https://github.com/chukmunnlee/dov-bear

WORKDIR /app

ADD package.json .
ADD package-lock.json .

RUN npm ci

ADD main.js .
ADD metrics.js .
ADD public public
ADD views views


ENV PORT=3000 METRICS_PORT=3100

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
	CMD curl -f http://localhost:${PORT}/healthz || exit 1

EXPOSE ${PORT} ${METRICS_PORT}

CMD node main
