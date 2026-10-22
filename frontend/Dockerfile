FROM node:20-alpine AS build

WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 600000

COPY . .

# Vazio = chamadas /api relativas (mesmo domínio via Nginx). Para API em outro domínio: --build-arg REACT_APP_BACKEND_URL=https://api.seudominio.com
ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL \
    GENERATE_SOURCEMAP=false \
    INLINE_RUNTIME_CHUNK=false

RUN yarn build

FROM nginx:1.27-alpine

RUN apk add --no-cache openssl && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/certs

# PUBLIC_HOST: CN do certificado autoassinado da porta 443
# TRUSTED_PROXY: rede do proxy reverso cujo X-Forwarded-For é aceito
ENV PUBLIC_HOST=localhost \
    TRUSTED_PROXY=127.0.0.1/32

COPY --from=build /app/build /usr/share/nginx/html
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf nginx/proxy-backend.conf /etc/nginx/snippets/
COPY nginx/10-self-signed-cert.sh /docker-entrypoint.d/

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1
