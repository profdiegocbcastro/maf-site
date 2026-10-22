# PRD — MAF · Mundos Artificiais em Finanças

## Problema original (resumo)
Criar um site completo e navegável do laboratório de pesquisa "Mundos Artificiais em Finanças (MAF)", do PPGI/UFRJ em colaboração com o CEFET/RJ — Campus Maria da Graça (BSI), com dados reais extraídos dos currículos Lattes anexados (Eber Schmitz, Sildenir Ribeiro, Gilberto Passos, Cristiano Fuschilo, Raphael Jesus) + mestrando Hugo Fraga. Temas: ABMS, Gêmeos Digitais Financeiros, Finanças Comportamentais, Protocolo ODD, Simulação Computacional. Referências: LAMFO, LIFT, LAB, Quantum PUC-IA, IAG PUC-Rio, LAFIM.

## Escolhas do usuário
- Bilíngue PT/EN com seletor no topo
- Dados reais dos currículos (bio, formação, publicações, projetos)
- Seções: Início, Sobre, Pesquisa, Equipe, Publicações, Projetos, Notícias, Parceiros, Contato
- Painel administrativo com login para editar notícias e publicações

## Arquitetura
- Frontend: React 19 + Tailwind + framer-motion + lenis + shadcn/ui + sonner
- Backend: FastAPI + motor (MongoDB async), rotas sob /api, Swagger em /api/docs
- Auth: JWT (access 60min + refresh 7d) em cookies httpOnly, bcrypt, proteção contra brute force (5 tentativas → 15min), admin semeado via .env
- Banco: MongoDB (coleções: users, publications, news, contacts, login_attempts)

## Personas
- Visitante/pesquisador: conhece o lab, equipe, publicações e projetos
- Estudante: interesse em PPGI/OBInvest, usa o contato
- Admin (equipe do lab): gerencia notícias e publicações

## Implementado (2026-07-14)
- Hero cinético com revelação mascarada + simulação ABM em canvas (140 agentes, botão "Choque de Liquidez"/"Restaurar Confiança", gráfico de preço sintético)
- Seções: Sobre, Pesquisa (6 pilares), Equipe (6 membros reais com modal: bio, formação, áreas, Lattes/ORCID/LinkedIn), Publicações (10 reais extraídas dos CVs, busca + filtro por tag + copiar BibTeX), Projetos (5: MAF-Brasil, OBInvest, Gêmeo Digital de Liquidez, HumânITas, Gestão Estratégica de TI), Notícias (destaque + grid), Parceiros (marquee + cards com links), Contato (form → MongoDB)
- i18n PT/EN completo via contexto
- Admin: /admin/login + /admin (stats, CRUD notícias, CRUD publicações, caixa de mensagens de contato)
- Logo SVG original + favicon, tema Obsidian/Esmeralda, fontes Playfair Display / JetBrains Mono / Plus Jakarta Sans

## Verificado
- curl: root, login, /me, publications (10), news (4), contact POST, 401 sem auth
- screenshots: hero (PT/EN), choque de liquidez, equipe + modal, publicações, mobile 375px, login admin → dashboard

## Credenciais
- admin@maf.ufrj.br / <ADMIN_PASSWORD> (ver /app/memory/test_credentials.md)

## Implementado (2026-07-14 — rodada 2)
- Página dedicada /simulacao: micromercado artificial com sliders (população de agentes 40–400, volatilidade 0.2–2.5×), 5 cenários (Calmo, Bolha, Choque, Pânico, Recuperação) e telemetria ao vivo (preço, variação %, regime)
- Simulação mais realista: regimes de alta/baixa/lateral que alternam sozinhos, clusters de volatilidade, momentum e reversão à média; fundamentalistas/chartistas/ruído reagem diferente
- Notícias com imagem de capa (campo image_url no modelo + admin com preview; 4 seeds migradas com imagens curadas)
- Fotos da equipe: nova aba "Equipe" no admin para colar URL da foto de cada membro; site exibe foto ou iniciais como fallback
- Alerta de contato por e-mail: pipeline Resend (Emergent) implementado e dormente — aguarda NOTIFY_EMAIL real da coordenação (escolha do usuário); mensagens continuam salvas no painel

## Backlog
- P0: definir ADMIN_EMAIL com o Gmail real do coordenador para o login Google funcionar com a conta certa (allowlist)
- P0: informar e-mail real da coordenação para ativar alertas de novo contato (NOTIFY_EMAIL)
- P1: páginas individuais de publicação com DOI/PDF; feed de notícias paginado
- P2: exportar publicações em BibTeX completo; integração com API Lattes; SEO/OG tags

## Implementado (2026-07-14 — rodada 4: Google Sign-In)
- Login com Google (Emergent-managed OAuth) adicionado à tela /admin/login, convivendo com e-mail/senha
- Fluxo: botão → auth.emergentagent.com (redirect dinâmico via window.location.origin) → callback #session_id → POST /api/auth/google → troca server-side → allowlist (só ADMIN_EMAIL entra; demais contas recebem 403) → cookies JWT httpOnly compartilhados com o login por senha
- AuthCallback com detecção síncrona de hash + proteção contra race condition no AuthProvider
- Verificado: session_id inválido → 401; login por senha segue funcionando; botão monta URL OAuth correta. Fluxo completo com conta Google real não testado (requer a conta)
- ADMIN_EMAIL atualizado para fuschilo@gmail.com (Gmail real do coordenador); conta admin de teste removida do banco; login por senha validado com o novo e-mail
- Código commitado localmente; push ao GitHub CONCLUÍDO: https://github.com/prof-fuschilo/maf-site (privado, branch main, 116 arquivos, sem .env — segredos fora do repo)

## Implementado (2026-07-14 — rodada 3: painel admin completo)
- Notícias e Publicações: toggle Publicada/Rascunho (badge + botão na lista + checkbox no formulário); rotas públicas só exibem itens publicados; rotas /api/admin/* listam tudo
- Mensagens: responder pelo painel (e-mail real ao remetente via Resend/Emergent, template fixo com escape), status Nova/Respondida automático ao responder + toggle manual, exclusão de mensagem, histórico da resposta exibido no card
- Equipe migrada para o MongoDB: CRUD completo no admin (criar, editar todos os campos bilíngues, excluir, publicar/ocultar, ordenar, foto por URL); site público lê de /api/team com fallback estático
