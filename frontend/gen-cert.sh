#!/bin/sh
# Gera um certificado TLS autoassinado no primeiro start (ambiente de laboratório).
# Em produção, substitua por um certificado válido (ex.: Let's Encrypt, gratuito).
set -e
mkdir -p /etc/nginx/certs
if [ ! -f /etc/nginx/certs/server.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  echo "Certificado autoassinado gerado."
fi
