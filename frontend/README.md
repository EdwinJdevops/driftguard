# DriftGuard frontend

React 19 + TypeScript + Vite + Tailwind v4. Landing page plus a dashboard wired to the real DriftGuard API — no mock data.

## Structure

```
src/
  lib/api.ts          — API client, mirrors backend/api/main.py schemas exactly
  components/
    DriftDiff.tsx      — signature hero element: animated declared-vs-actual HCL diff
    Gauge.tsx          — posture score radial gauge
    Nav.tsx / Footer.tsx
  pages/
    Landing.tsx        — marketing page, copy grounded in actual README/codebase facts
    Dashboard.tsx       — sign in/up, workspace list, scan trigger + poll, findings table
```

Routing is a ~15-line `usePath()` hook in `App.tsx` (pushState + popstate) — two routes doesn't justify a router dependency.

## Local dev

```bash
npm install
npm run dev          # http://localhost:5173
```

Set `VITE_API_URL` (see `.env.example`) to point at a local backend. CORS: set `ALLOWED_ORIGINS=http://localhost:5173` on the backend.

## Build

```bash
npm run build         # tsc -b && vite build -> dist/
npx oxlint             # lint
node smoke_test.mjs    # jsdom render check — no browser required, catches runtime errors tsc can't
```

## Deploy

See `render.yaml` at the repo root — this is one of two services in the Blueprint.
