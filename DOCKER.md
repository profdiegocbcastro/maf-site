# MAF — Implantação com Docker

Sistema completo (React + FastAPI + MongoDB) em três contêineres, com deploy automático a cada push na `main`.

## Arquitetura
```
https://maf.testbeds.rnp.br
  │  proxy da RNP (200.133.57.x): termina o TLS com o certificado *.testbeds.rnp.br
  ▼  443 → NAT 14343 → VM:443 (HTTPS, certificado autoassinado interno)
frontend (Nginx) ──/api──▶ backend (FastAPI) ──▶ mongo
  React estático     rede "web"          rede "db" (interna, sem internet)
  headers de segurança, rate limit
  site servido na :80 e na :443 (o proxy da RNP pode usar qualquer uma)
```
| Serviço   | Imagem                                         | Função                                         |
|-----------|------------------------------------------------|------------------------------------------------|
| frontend  | `ghcr.io/profdiegocbcastro/maf-site-frontend`   | Nginx: serve o React, proxy `/api`, segurança  |
| backend   | `ghcr.io/profdiegocbcastro/maf-site-backend`    | FastAPI (uvicorn) na porta interna 8001        |
| mongo     | `mongo:7`                                      | Banco com autenticação, volume `mongo_data`    |

O Nginx do contêiner `frontend` já é o proxy reverso: não é preciso instalar outro Nginx no host.
O HTTPS público é feito pelo proxy da RNP, então não há Certbot/Let's Encrypt na VM.

## CI/CD (GitHub Actions)
`.github/workflows/deploy.yml`, a cada push na `main`:
1. Builda as imagens do backend e do frontend e publica no GHCR (tags `latest` e `<sha do commit>`).
2. Conecta por SSH no servidor como usuário `deploy`, copia o `docker-compose.yml` para `/opt/maf`,
   grava `IMAGE_TAG=<sha>` no `.env`, faz `docker compose pull` e `up -d --wait`.
3. Confere se o site e a API respondem.

Em pull requests só roda o build (sem publicar nem implantar).

Secrets do repositório: `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS`.

### Rollback
No servidor, volte para um commit anterior:
```bash
cd /opt/maf
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=<sha-anterior>/' .env
docker compose up -d
```
Ou rode de novo o workflow de um commit antigo em Actions → "Re-run jobs".

## Servidor de produção
- `ssh -p 14322 cristiano.fuschilo@usuario.df.testbeds.rnp.br` (Ubuntu 22.04, atrás de NAT da RNP)
- Site público: **https://maf.testbeds.rnp.br**
- NAT da RNP (IP 200.130.101.117): 14322 → 22 (SSH), 14380 → 80, 14343 → 443
- Arquivos em `/opt/maf` (dono `deploy`, modo 600 nos `.env`):
  - `/opt/maf/.env` — variáveis do compose (portas, `PUBLIC_HOST`, `TRUSTED_PROXY`, credenciais do Mongo, `IMAGE_TAG`)
  - `/opt/maf/backend/.env` — segredos da aplicação (`JWT_SECRET`, `ADMIN_PASSWORD`...)
- Segurança do host: UFW (só 22, 80 e 443 abertas), fail2ban no SSH, SSH só por chave,
  atualizações automáticas (`unattended-upgrades`).

Para trocar a senha do painel: edite `ADMIN_PASSWORD` em `/opt/maf/backend/.env` e rode
`docker compose up -d --force-recreate backend` (a senha é aplicada na inicialização).

## Rodar localmente
```bash
cp .env.example .env                  # preencha MONGO_PASSWORD
cp backend/.env.example backend/.env  # preencha JWT_SECRET e ADMIN_*
docker compose up -d --build
```
Site em `https://localhost` (certificado autoassinado; aceite o aviso do navegador). Sem HTTPS,
use `COOKIE_SECURE=false` no `backend/.env` para o login funcionar. Swagger: `ENABLE_DOCS=true` → `/api/docs`.

## Segurança aplicada
- Contêineres com `no-new-privileges`, capabilities removidas, sistema de arquivos somente leitura,
  limite de memória e rotação de logs; backend roda como usuário não-root.
- MongoDB com usuário/senha e numa rede Docker interna, sem porta publicada.
- Nginx: CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`; versão oculta;
  bloqueio de arquivos ocultos; limite de corpo 1 MB; rate limit no login (10/min), no formulário
  de contato (5/min) e na API em geral.
- Backend: Swagger desligado em produção, cookies `HttpOnly` + `SameSite=Lax`, sem senha padrão
  (a aplicação não sobe sem `ADMIN_PASSWORD` de 12+ caracteres), bloqueio por IP real após 5 erros de login.

## HTTPS e IP real dos visitantes
- O proxy da RNP termina o TLS e fala HTTPS com a porta 443 da VM. O Nginx gera um certificado
  autoassinado ao iniciar (`frontend/nginx/10-self-signed-cert.sh`), suficiente para esse trecho interno.
- O proxy envia o IP do visitante em `X-Forwarded-For`. O Nginx só confia nesse cabeçalho quando a
  conexão vem de `TRUSTED_PROXY` (200.133.57.0/24), então o rate limit e o bloqueio de login usam o
  IP real e ninguém consegue forjá-lo acessando a VM direto.
- O site responde na 80 (HTTP) e na 443 (HTTPS). `COOKIE_SECURE=true` e HSTS ativos: o login do
  painel só funciona pelo endereço HTTPS público.

## Comandos úteis (em /opt/maf)
```bash
docker compose ps
docker compose logs -f backend
docker compose restart backend
docker compose down                   # para tudo (dados do Mongo ficam no volume)
```

## Backup do banco
```bash
. ./.env
docker compose exec -T mongo mongodump -u "$MONGO_USER" -p "$MONGO_PASSWORD" --authenticationDatabase admin \
  --db maf_database --archive > backup-maf.archive
docker compose exec -T mongo mongorestore -u "$MONGO_USER" -p "$MONGO_PASSWORD" --authenticationDatabase admin \
  --archive < backup-maf.archive
```
