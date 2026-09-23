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
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
