# Frontend image: build the Vite/React app, then serve the static bundle with
# nginx. nginx also reverse-proxies /api (REST + WebSocket) to the backend, so
# the browser talks to a single origin — no CORS, and relative URLs "just work".
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Empty API base => relative /api URLs, resolved by nginx (see nginx.conf).
ENV VITE_API_BASE=""
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
