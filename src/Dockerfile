ARG VERSION=18
FROM node:${VERSION} AS builder

WORKDIR /app

ADD package.json .
ADD package-lock.json .

RUN npm ci

ADD main.js .
ADD metrics.js .
ADD public public
ADD views views


FROM gcr.io/distroless/nodejs:${VERSION}

LABEL org.opencontainers.image.source https://github.com/chukmunnlee/dov-bear

ENV PORT=3000 METRICS_PORT=3100

WORKDIR /app

COPY --from=builder /app /app

EXPOSE ${PORT} ${METRICS_PORT}

CMD [ "main" ]
