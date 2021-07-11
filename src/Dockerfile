FROM node:16

ENV PORT=3000 APP_ROOT=/app

WORKDIR ${APP_ROOT}

ADD main.js .
ADD package.json .
ADD package-lock.json .
ADD public public
ADD views views

RUN npm ci

EXPOSE ${PORT}

ENTRYPOINT [ "node", "main.js" ]

CMD []
