#!/usr/bin/env node
// Post Secret Storage API — zero dependencies, Node.js built-ins only
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const MAX_CIPHERTEXT_BYTES = 64 * 1024; // 64 KB
const DEFAULT_TTL = 86400;              // 24 hours
const MAX_TTL = 7 * 86400;             // 7 days

// In-memory store: id -> { ciphertext, expiresAt }
const store = new Map();

// Sweep expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of store) {
    if (entry.expiresAt < now) store.delete(id);
  }
}, 5 * 60 * 1000).unref();

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...CORS_HEADERS,
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_CIPHERTEXT_BYTES + 512) {
        reject(new Error('Payload too large'));
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  // POST /create
  if (method === 'POST' && url === '/create') {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return send(res, 400, { error: 'Invalid JSON or payload too large' });
    }

    const { ciphertext, ttl } = body;
    if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
      return send(res, 400, { error: 'ciphertext is required' });
    }
    if (Buffer.byteLength(ciphertext) > MAX_CIPHERTEXT_BYTES) {
      return send(res, 413, { error: 'ciphertext exceeds 64 KB limit' });
    }

    const ttlSec = Math.min(
      Math.max(1, Number.isFinite(ttl) ? Math.floor(ttl) : DEFAULT_TTL),
      MAX_TTL
    );

    const id = crypto.randomUUID();
    store.set(id, { ciphertext, expiresAt: Date.now() + ttlSec * 1000 });
    return send(res, 201, { id });
  }

  // GET /secret/:id
  const match = url.match(/^\/secret\/([0-9a-f-]{36})$/i);
  if (method === 'GET' && match) {
    const id = match[1];
    const entry = store.get(id);

    if (!entry || entry.expiresAt < Date.now()) {
      store.delete(id);
      return send(res, 404, { error: 'Secret not found or already read' });
    }

    const { ciphertext } = entry;
    store.delete(id); // burn after reading
    return send(res, 200, { ciphertext });
  }

  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Post Secret API listening on http://localhost:${PORT}`);
});
