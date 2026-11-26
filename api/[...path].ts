import type { IncomingMessage, ServerResponse } from 'http';
import { createApp } from '../server/app.ts';

export const config = {
  maxDuration: 300,
};

let appPromise: Promise<import('express').Express> | null = null;

function getApp() {
  if (!appPromise) {
    appPromise = createApp({ serveStatic: false });
  }
  return appPromise;
}

function withApiPrefix(url: string | undefined): string {
  const raw = url || '/';
  if (raw.startsWith('/api/') || raw === '/api') return raw;
  const pathOnly = raw.startsWith('/') ? raw : `/${raw}`;
  return `/api${pathOnly}`;
}

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  const app = await getApp();
  const original = req.url || '/';
  // After a rewrite or catch-all, the path may be stripped of the /api prefix.
  if (!original.startsWith('/api')) {
    req.url = withApiPrefix(original);
  }
  return app(req, res);
}
