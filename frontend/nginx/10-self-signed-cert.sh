#!/bin/sh
# Hook do entrypoint do nginx:alpine: cria um certificado autoassinado para a
# porta 443 se nenhum foi montado em /etc/nginx/certs.
set -e
dir=/etc/nginx/certs
[ -f "$dir/cert.pem" ] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -subj "/CN=${PUBLIC_HOST:-localhost}" \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
echo "10-self-signed-cert: certificado autoassinado gerado para ${PUBLIC_HOST:-localhost}"
