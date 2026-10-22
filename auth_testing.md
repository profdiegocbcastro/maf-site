# Auth Testing Playbook — MAF

## 1) Email/senha (JWT custom)

Admin seeded at startup from env: ADMIN_EMAIL=admin@maf.ufrj.br / ADMIN_PASSWORD=<ADMIN_PASSWORD>

### MongoDB
```
mongosh
use test_database
db.users.find({role: "admin"}).pretty()
```
Verify: bcrypt hash starts with `$2b$`, unique index on users.email, index on login_attempts.identifier.

### API
```
API=$(grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d '=' -f2)
curl -c /tmp/cookies.txt -X POST $API/api/auth/login -H "Content-Type: application/json" -d '{"email":"admin@maf.ufrj.br","password":"<ADMIN_PASSWORD>"}'
curl -b /tmp/cookies.txt $API/api/auth/me
```
Login returns the user object and sets access_token + refresh_token cookies; /me returns the same user.

### Protected CRUD
```
curl -b /tmp/cookies.txt -X POST $API/api/news -H "Content-Type: application/json" -d '{"title_pt":"T","title_en":"T","summary_pt":"S","summary_en":"S","date":"2026-07-01","tag":"LAB","featured":false}'
```
Unauthenticated POST/PUT/DELETE must return 401.

## 2) Google Sign-In (Emergent-managed OAuth)

- Botão "Entrar com Google" em /admin/login redireciona para `https://auth.emergentagent.com/?redirect=<window.location.origin>/admin` (NUNCA hardcodar a URL de redirect).
- Retorno: `<app>/#session_id=...` → AppRouter renderiza AuthCallback (checagem síncrona via useLocation().hash) → POST /api/auth/google {session_id} → backend troca em `https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data` (header X-Session-ID) → allowlist: somente o e-mail ADMIN_EMAIL é aceito (403 caso contrário) → cookies JWT httpOnly emitidos (mesmos do login por senha).
- AuthProvider pula o /auth/me quando o hash contém session_id (evita race condition).

### Testes possíveis sem conta Google real
```
API=$(grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d '=' -f2)
curl -s -X POST $API/api/auth/google -H "Content-Type: application/json" -d '{"session_id":"invalid"}'   # esperado: 401
```
### Teste completo (requer conta Google)
1. Logar com a conta Google cujo e-mail == ADMIN_EMAIL → deve entrar no painel.
2. Logar com outra conta Google → deve voltar ao login com erro "não autorizada".
3. Após login Google, GET /api/auth/me com cookies deve retornar o usuário admin.
