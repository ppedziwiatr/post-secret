#!/usr/bin/env node
// Post Secret Storage API — zero dependencies, Node.js built-ins only
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = parseInt(process.env.PORT || "3000", 10);
const DB_PATH = process.env.DB_PATH || "./secrets.db";
const MAX_CIPHERTEXT_BYTES = 64 * 1024; // 64 KB per secret
const MAX_IP_STORE_BYTES = 1024 * 1024; // 1 MB per IP
const DEFAULT_TTL = 86400; // 24 hours
const MAX_TTL = 7 * 86400; // 7 days

const db = new DatabaseSync(DB_PATH);

db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA synchronous = NORMAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id         TEXT    PRIMARY KEY,
    ciphertext TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    ip         TEXT    NOT NULL
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_secrets_ip ON secrets (ip)");
db.exec(
  "CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at)",
);

const stmtInsert = db.prepare(
  "INSERT INTO secrets (id, ciphertext, expires_at, bytes, ip) VALUES (?, ?, ?, ?, ?)",
);
const stmtSelect = db.prepare(
  "SELECT ciphertext, expires_at, bytes, ip FROM secrets WHERE id = ?",
);
const stmtDelete = db.prepare("DELETE FROM secrets WHERE id = ?");
const stmtIpBytes = db.prepare(
  "SELECT COALESCE(SUM(bytes), 0) AS total FROM secrets WHERE ip = ?",
);
const stmtExpired = db.prepare("DELETE FROM secrets WHERE expires_at < ?");

function transaction(fn) {
  db.exec("BEGIN");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

// Atomic check-quota-and-insert
function checkAndInsert(id, ciphertext, expiresAt, bytes, ip) {
  return transaction(() => {
    const { total } = stmtIpBytes.get(ip);
    if (total + bytes > MAX_IP_STORE_BYTES) return false;
    stmtInsert.run(id, ciphertext, expiresAt, bytes, ip);
    return true;
  });
}

// Atomic read-and-delete (burn after reading)
function readAndDelete(id, now) {
  return transaction(() => {
    const entry = stmtSelect.get(id);
    if (!entry || entry.expires_at < now) {
      if (entry) stmtDelete.run(id);
      return null;
    }
    stmtDelete.run(id);
    return entry;
  });
}

// Sweep expired entries every 5 minutes
setInterval(
  () => {
    stmtExpired.run(Date.now());
  },
  5 * 60 * 1000,
).unref();

function getIp(req) {
  // fly-client-ip is set by Fly.io's proxy and cannot be spoofed by clients
  return req.headers["fly-client-ip"] || req.socket.remoteAddress || "unknown";
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...CORS_HEADERS,
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_CIPHERTEXT_BYTES + 512) {
        req.destroy();
        reject(new Error("Payload too large"));
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  // CORS preflight
  if (method === "OPTIONS") {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  // POST /create
  if (method === "POST" && url === "/create") {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return send(res, 400, { error: "Invalid JSON or payload too large" });
    }

    const { ciphertext, ttl } = body;
    if (typeof ciphertext !== "string" || ciphertext.length === 0) {
      return send(res, 400, { error: "ciphertext is required" });
    }
    const ctBytes = Buffer.byteLength(ciphertext);
    if (ctBytes > MAX_CIPHERTEXT_BYTES) {
      return send(res, 413, { error: "ciphertext exceeds 64 KB limit" });
    }

    const ttlSec = Math.min(
      Math.max(1, Number.isFinite(ttl) ? Math.floor(ttl) : DEFAULT_TTL),
      MAX_TTL,
    );

    const ip = getIp(req);
    const id = crypto.randomUUID();
    const ok = checkAndInsert(
      id,
      ciphertext,
      Date.now() + ttlSec * 1000,
      ctBytes,
      ip,
    );
    if (!ok) {
      return send(res, 429, {
        error:
          "Storage limit reached — read or wait for your existing secrets to expire",
      });
    }
    return send(res, 201, { id });
  }

  // GET /secret/:id
  const match = url.match(/^\/secret\/([0-9a-f-]{36})$/i);
  if (method === "GET" && match) {
    const entry = readAndDelete(match[1], Date.now());
    if (!entry) {
      return send(res, 404, { error: "Secret not found or already read" });
    }
    return send(res, 200, { ciphertext: entry.ciphertext });
  }

  send(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`Post Secret API listening on http://localhost:${PORT}`);
});
