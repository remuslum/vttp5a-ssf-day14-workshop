FROM node@sha256:d885885ad8e100d27b65e7837075afea042cc8515ec066cd82cdf34e26fc9fb8

LABEL org.opencontainers.image.source https://github.com/chukmunnlee/dov-bear

WORKDIR /app

ADD package.json .
ADD package-lock.json .

RUN npm ci --omit=dev

ADD main.js .
ADD metrics.js .
ADD public public
ADD views views

ENV PORT=3000 METRICS_PORT=3100

USER 1000

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
	CMD curl -f http://localhost:${PORT}/healthz || exit 1

EXPOSE ${PORT} ${METRICS_PORT}

CMD node main
