FROM node:22-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

RUN corepack enable

COPY lib/credo-ts-askar-0.5.3.tgz lib/
COPY lib/credo-ts-core-0.5.3.tgz lib/
COPY lib/digitalcredentials-vc-7.0.0.tgz lib/
COPY lib/sphereon-pex-3.3.3.tgz lib/
COPY lib/sphereon-pex-models-2.2.4.tgz lib/

WORKDIR /app/demo-user

COPY demo-user/package.json ./
RUN yarn install

COPY demo-user/app.js ./
COPY demo-user/public ./public
COPY demo-user/config ./config

EXPOSE 3006 3007

CMD ["sh", "-c", "if [ ! -f config/default.json ] && [ -f config/custom.json ]; then cp config/custom.json config/default.json; fi; node app.js"]
