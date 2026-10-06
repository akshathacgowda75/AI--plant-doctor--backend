# PlantCare AI — Backend (Express + SQLite + Claude)

API for accounts, per-user garden data, AI diagnosis (`/api/analyze`) and the assistant (`/api/chat`). Also serves `public/` if you want one-link hosting.

## Run locally
```bash
npm install
cp .env.example .env     # fill in ANTHROPIC_API_KEY, JWT_SECRET, ALLOWED_ORIGIN
npm run dev              # http://localhost:3000
```
## Deploy (Render)
New → Web Service → connect repo · Build `npm install` · Start `npm start` · set env vars from `.env.example` plus `NODE_ENV=production`.
SQLite persistence needs a disk: mount at `/var/data` and set `DB_PATH=/var/data/plantcare.db` (otherwise data resets on restart).
`ALLOWED_ORIGIN` must be your GitHub Pages origin, e.g. `https://yourname.github.io` (no path).
