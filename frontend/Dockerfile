FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY gen-cert.sh /docker-entrypoint.d/05-gen-cert.sh
RUN sed -i 's/\r$//' /docker-entrypoint.d/05-gen-cert.sh && chmod +x /docker-entrypoint.d/05-gen-cert.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
