# The dashboard: built once with Node, served by nginx.
#
# nginx also proxies /api (and the alert WebSocket under it) to the API container, so
# the browser only ever talks to one origin - the same arrangement the Vite dev server
# reproduces, and the reason the API ships no CORS middleware.

FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# A self-signed certificate, made fresh for each image so no key is ever in the
# repository. It encrypts the localhost/SSH-tunnel deployment; a real host name
# would replace it with a CA-issued one.
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -keyout /etc/nginx/tls/dashboard.key -out /etc/nginx/tls/dashboard.crt \
 && apk del openssl
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 443
