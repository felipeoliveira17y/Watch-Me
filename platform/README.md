# ResQ Wear — plataforma operacional

Aplicação independente do site institucional WATCH ME V6. Esta primeira base corre em Node.js 24, usa `node:http` e `node:sqlite` nativos e não precisa de instalar dependências externas. A migração `migrations/001_initial_schema.sql` cria o esquema versionado na inicialização. A base de dados SQLite fica em `data/resq.sqlite`.

A interface operacional compartilha a identidade visual do institucional: fundo off-white, azul-marinho `#1f3358`, roxo `#8a4cc2`, lavanda `#eee5f7`, tipografia DM Sans e Manrope e cartões arredondados. Veja `public/theme.css`; a aplicação não importa conteúdo institucional.

## Executar localmente

1. Instale Node.js 24 ou superior.
2. Copie `.env.example` para `.env`, defina uma palavra-passe forte em `RESQ_ADMIN_PASSWORD` e um valor aleatório de pelo menos 32 caracteres em `RESQ_ROOM_SECRET`.
3. Execute `npm start` e abra <http://127.0.0.1:3000>.
4. Inicie a gestão pelo ícone junto ao perfil. Sem palavra-passe configurada, só o simulador fica disponível.
5. Execute `npm test` para validar as regras principais.

O servidor da API local escuta apenas em `127.0.0.1` e não está pronto para exposição pública. A publicação estática demonstrativa na Vercel é uma alternativa separada e não hospeda a API nem recebe eventos reais.

## Publicar uma demonstração estática na Vercel

O `vercel.json` configura o diretório `public/` e as rotas de salas para uma publicação **somente demonstrativa**. Nela, o simulador usa `localStorage` do navegador: cada visitante mantém dados próprios, e o link da sala só funciona no navegador que criou a simulação. A API Node/SQLite não é publicada nessa configuração. O site mostra esse limite e não aceita SOS reais.

Para publicar pelo CLI, instale e autentique a Vercel CLI; depois execute na pasta `platform/`:

```powershell
npm install --global vercel
vercel login
vercel --prod
```

Também é possível importar um repositório Git no painel Vercel e definir `platform/` como Root Directory. Não configure credenciais de dispositivo nesse deploy demonstrativo. Para a API real, primeiro migrar as funções para Vercel Functions e conectar uma base PostgreSQL persistente; nunca usar o arquivo SQLite local como banco de produção.

## O que funciona nesta versão

- Painel com estados desconhecidos explícitos quando não há dados.
- Registo e revogação de dispositivos com credencial aleatória, apresentada apenas uma vez e armazenada como hash.
- Cinco posições de contacto; as posições 1 e 2 são imutáveis por APIs comuns. As três posições pessoais validam formato internacional e duplicações.
- API de eventos autenticada por token de dispositivo, validação de dados e chave de idempotência.
- Ocorrências persistidas, histórico, transições de estado limitadas e salas privadas com token aleatório de 256 bits armazenado como hash.
- Links de sala revogáveis e com expiração de 24 horas. Qualquer pessoa com o link tem acesso; o link não verifica identidade.
- Simulador local de SOS, possível queda, teste e evento de sistema. Os eventos são inequívoca e permanentemente marcados como simulados e não enviam SMS nem contactam ninguém.
- Sala atualizada por consulta periódica a cada 15 segundos; a localização inicial não é chamada de localização em tempo real.
- Cabeçalhos básicos de segurança, conteúdo não indexável, limite temporário de pedidos por IP em memória e limite de tentativas de login.

## Limitações e configuração operacional

- Não há serviço de envio de SMS, gateway SMS, confirmação de entrega, autenticação de utilizadores por e-mail, recuperação de palavra-passe, mapa cartográfico, múltiplos utilizadores ou multi-tenancy.
- A sessão administrativa é uma única palavra-passe local configurada por ambiente e sessão opaca de 8 horas. Configure `RESQ_ADMIN_PASSWORD` antes de registar dispositivos. Não partilhe `.env`.
- O identificador do proprietário é implícito nesta instalação local de operador único. Antes de uso por várias pessoas, implementar identidade de utilizador, propriedade e autorização por recurso.
- Os contactos oficiais são semeados como referências brasileiras 190 e 197. Confirme os números e serviços para a região antes de qualquer utilização real; não se presume que aceitem SMS.
- As salas reais expõem apenas dados de evento e localização a quem possui o link. Esse acesso por posse não prova a identidade de quem abre o link. Uma sala pode ser revogada pelo endpoint administrativo.
- Não existe mapa de rua nesta versão; a localização é mostrada como coordenadas e marcador esquemático. Não há recolha de geolocalização pelo browser.
- A aplicação não garante segurança física e não substitui os serviços oficiais de emergência.

## API e autenticação

As respostas JSON têm `Cache-Control: no-store`. A administração autentica com `POST /api/session` e cookie `HttpOnly; SameSite=Strict`; `DELETE /api/session` encerra a sessão. Endpoints de gestão requerem essa sessão. Rotas do dispositivo exigem `Authorization: Bearer <credencial>`.

### Registar evento no dispositivo

`POST /api/device/events`

```json
{
  "eventId": "boot-17-event-0042",
  "type": "sos_manual",
  "occurredAt": "2026-10-20T14:10:00.000Z",
  "latitude": -23.5505,
  "longitude": -46.6333,
  "accuracy": 20
}
```

Tipos aceites: `sos_manual`, `possible_fall`, `fall_confirmed`, `test`, `system`. A resposta confirma apenas a receção e persistência pelo servidor. O link de sala é devolvido uma vez; SMS não é enviado e a entrega é desconhecida/não configurada. Repetições com a mesma chave para o mesmo dispositivo não criam nova ocorrência.

### Atualizar localização

`POST /api/device/events/{eventId}/location` com credencial Bearer e `{ "latitude": -23.55, "longitude": -46.63, "accuracy": 20 }`.

### Contactos, estados e salas

- `GET /api/devices/{deviceId}/contacts` — administrativo.
- `PUT /api/devices/{deviceId}/contacts` — aceita até três contactos pessoais em ordem nas posições 3–5; a API não aceita alterações a posições oficiais.
- `POST /api/devices` e `PATCH /api/devices/{deviceId}/status` — administrativo; revogar invalida imediatamente a credencial.
- `POST /api/devices/{deviceId}/rotate-token` — administrativo; revoga a credencial antiga e apresenta a nova apenas uma vez.
- `GET /api/device/configuration` — Bearer do dispositivo; devolve os cinco contactos e metadados permitidos, nunca a credencial.
- `GET /api/events` — administrativo.
- `PATCH /api/events/{eventId}/status` — transições: `received → open/cancelled`; `open → monitoring/resolved/cancelled/closed`; `monitoring → resolved/cancelled/closed`; `resolved/cancelled → closed`.
- `DELETE /api/events/{eventId}/room` — revogar o link da sala.
- `GET /room/{token}` — sala via link secreto; para navegação de browser, a mesma rota entrega a aplicação Web.
- `POST /api/demo/events` — cria exclusivamente dados simulados, sem notificações externas.

## Privacidade, retenção e backup

Os eventos e contactos ficam na base SQLite local até remoção manual do ficheiro de dados. Defina uma política de retenção e processo de eliminação antes de recolher dados reais; proteja e faça backup cifrado da pasta `data` se necessário. Não use dados reais em demonstrações ou screenshots. Segredos de dispositivos são mostrados uma vez, guardados como hash e revogáveis; os tokens de sala também são guardados como hash. Evite logs de URLs de sala no alojamento futuro.

## Integração futura com ESP32/SIM800L

Fluxo preferido: ESP32 deteta o evento → obtém coordenadas disponíveis → POST autenticado à API sobre GPRS → servidor persiste evento e cria sala → dispositivo recebe o link → firmware poderá enviar o SMS. `RESQ_ROOM_SECRET` deve permanecer secreto; o token idempotente da sala é derivado por HMAC deste segredo e da chave do evento, e a base guarda apenas o seu hash. A rotação desse segredo invalida links existentes. O SIM800L não faz a hospedagem nem encaminha automaticamente SMS ao site. Se GPRS não estiver disponível, é necessário um gateway SMS autorizado. A API atual implementa a receção do evento e atualização de coordenadas, mas não firmware, encaminhamento SMS, rate limit persistente, rotação automatizada, atestado do dispositivo ou gateway.

## Evolução recomendada antes da publicação

1. Adicionar utilizadores, autenticação com provedor, papéis e autorização por proprietário.
2. Migrar SQLite para PostgreSQL gerido com migrations e backups.
3. Migrar limites em memória para rate limits persistentes, implementar proteção CSRF adequada ao domínio, limites de sessão e política de retenção.
4. Adicionar serviço SMS autorizado, estado de entrega sem falsas confirmações e tratamento de LGPD.
5. Configurar HTTPS, logging minimizado, monitoração, CSP sem exceções e revisão de segurança.
6. Validar números de emergência, montagem, firmware, alimentação e fluxo físico com especialistas e equipa.
