# ResQ Wear — Plataforma operacional

Este repositório contém apenas a plataforma ResQ Wear do protótipo WATCH ME V6. O antigo site institucional foi removido.

## Executar localmente

Requer Node.js 24 ou superior. Na pasta `platform/`:

```powershell
npm start
```

Consulte [platform/README.md](platform/README.md) para configuração, funcionamento e limites do protótipo.

## Publicação no Vercel

Para publicar a demonstração estática, configure `platform/` como **Root Directory** do projeto Vercel. A versão estática é apenas demonstrativa; não recebe SOS reais, e os dados simulados ficam no navegador local.
