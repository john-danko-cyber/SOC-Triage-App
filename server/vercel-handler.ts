import type { IncomingMessage, ServerResponse } from 'http';
import { createApp } from './app.ts';

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

function headerValue(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function withApiPrefix(url: string | undefined): string {
  const raw = url || '/';
  if (raw.startsWith('/api/') || raw === '/api') return raw;
  const pathOnly = raw.startsWith('/') ? raw : `/${raw}`;
  return `/api${pathOnly}`;
}

function restoreUrl(req: IncomingMessage): string {
  const candidates = [
    req.url,
    headerValue(req, 'x-forwarded-uri'),
    headerValue(req, 'x-invoke-path'),
    headerValue(req, 'x-matched-path'),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const path = candidate.split('?')[0];
    if (path.startsWith('/api/')) {
      const qsIndex = (req.url || '').indexOf('?');
      const qs = qsIndex >= 0 ? (req.url || '').slice(qsIndex) : (candidate.includes('?') ? candidate.slice(candidate.indexOf('?')) : '');
      return `${path}${qs}`;
    }
  }
  return withApiPrefix(req.url);
}

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  const app = await getApp();
  req.url = restoreUrl(req);
  return app(req, res);
}
