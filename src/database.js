const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

// ─── Boot-time secret validation ─────────────────────────────────────────────
// FIXED SEC-6: Crash early if secrets are missing or use insecure defaults
const REQUIRED_SECRETS = ["JWT_SECRET", "LOADER_SECRET", "SESSION_SECRET"];
for (const key of REQUIRED_SECRETS) {
  const val = process.env[key] || "";
  if (!val || val.startsWith("CHANGE_ME") || val.length < 32) {
    console.error(`[FATAL] ${key} is missing or too short (min 32 chars). Set it in your .env`);
    process.exit(1);
  }
}
if (process.env.NODE_ENV === "production") {
  const ap = process.env.ADMIN_PASSWORD || "";
  if (!ap || ap === "admin123" || ap.startsWith("CHANGE_ME")) {
    console.error("[FATAL] ADMIN_PASSWORD must be changed from default in production.");
    process.exit(1);
  }
}

// ─── DB setup ─────────────────────────────────────────────────────────────────
const DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  process.env.DATA_DIR ||
  path.join(__dirname, "../data");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, "surfix.db"));

// FIXED BUG-5: Expose a ready gate so routes wait for schema before serving
let _dbReady = false;
const _readyQ = [];
function onReady(fn) {
  if (_dbReady) return fn();
  _readyQ.push(fn);
}
function _markReady() {
  _dbReady = true;
  _readyQ.forEach((fn) => fn());
}

db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA foreign_keys = ON");
  db.run("PRAGMA synchronous = NORMAL");

  // Users — supports local + OAuth logins
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE,
    email         TEXT UNIQUE,
    password      TEXT,
    role          TEXT NOT NULL DEFAULT 'user',
    plan          TEXT NOT NULL DEFAULT 'free',
    avatar_url    TEXT,
    verified      INTEGER NOT NULL DEFAULT 0,
    verify_token  TEXT,
    reset_token   TEXT,
    reset_expires INTEGER,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_login    INTEGER
  )`);

  // OAuth provider identities — one user can link multiple providers
  db.run(`CREATE TABLE IF NOT EXISTS oauth_accounts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(provider, provider_id)
  )`);

  // Projects — FIXED BUG-4: obfuscate is in the initial schema, no ALTER TABLE
  db.run(`CREATE TABLE IF NOT EXISTS projects (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    script           TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '1.0.0',
    script_version   INTEGER NOT NULL DEFAULT 1,
    protection_level TEXT NOT NULL DEFAULT 'max',
    lightning        INTEGER NOT NULL DEFAULT 0,
    silent           INTEGER NOT NULL DEFAULT 0,
    ffa              INTEGER NOT NULL DEFAULT 0,
    heartbeat        INTEGER NOT NULL DEFAULT 0,
    verified         INTEGER NOT NULL DEFAULT 0,
    source_locker    INTEGER NOT NULL DEFAULT 0,
    obfuscate        INTEGER NOT NULL DEFAULT 1,
    downloads        INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at       INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key_value       TEXT UNIQUE NOT NULL,
    hwid            TEXT,
    discord_id      TEXT,
    key_days        INTEGER,
    auth_expire     INTEGER,
    max_activations INTEGER,
    activations     INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER,
    paused          INTEGER NOT NULL DEFAULT 0,
    note            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_used       INTEGER
  )`);

  // FIXED: added UNIQUE(license_id, session_id) to prevent duplicate sessions
  db.run(`CREATE TABLE IF NOT EXISTS active_sessions (
    id         TEXT PRIMARY KEY,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    last_ping  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    ip         TEXT,
    UNIQUE(license_id, session_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS auth_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT,
    project_id TEXT NOT NULL,
    hwid       TEXT,
    ip         TEXT,
    platform   TEXT NOT NULL DEFAULT 'unknown',
    status     TEXT NOT NULL,
    reason     TEXT,
    ts         INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  )`);

  // Indexes — FIXED BUG-11: added index on last_ping for stale-session cleanup
  const indexes = [
    "CREATE INDEX IF NOT EXISTS idx_lic_key      ON licenses(key_value)",
    "CREATE INDEX IF NOT EXISTS idx_lic_project  ON licenses(project_id)",
    "CREATE INDEX IF NOT EXISTS idx_lic_hwid     ON licenses(hwid)",
    "CREATE INDEX IF NOT EXISTS idx_sess_license ON active_sessions(license_id)",
    "CREATE INDEX IF NOT EXISTS idx_sess_ping    ON active_sessions(last_ping)",
    "CREATE INDEX IF NOT EXISTS idx_log_ts       ON auth_logs(ts)",
    "CREATE INDEX IF NOT EXISTS idx_log_status   ON auth_logs(status)",
    "CREATE INDEX IF NOT EXISTS idx_log_project  ON auth_logs(project_id)",
    "CREATE INDEX IF NOT EXISTS idx_log_ip       ON auth_logs(ip)",
    "CREATE INDEX IF NOT EXISTS idx_oauth_user   ON oauth_accounts(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_email   ON users(email)",
    "CREATE INDEX IF NOT EXISTS idx_proj_user    ON projects(user_id)",
  ];
  indexes.forEach((sql) => db.run(sql));

  // Seed admin user — runs after all CREATE TABLE statements in serialize block
  db.get("SELECT id FROM users WHERE username = 'admin'", (err, row) => {
    if (row) return _markReady();
    const pass = process.env.ADMIN_PASSWORD || "admin123";
    const hash = bcrypt.hashSync(pass, 12);
    db.run(
      `INSERT INTO users (id, username, email, password, role, verified)
       VALUES ('admin-1', 'admin', 'admin@surfix.local', ?, 'admin', 1)`,
      [hash],
      (e) => {
        if (e && !e.message.includes("UNIQUE")) console.error("[DB] seed:", e.message);
        _markReady();
      }
    );
  });
});

function get(sql, params = []) {
  return new Promise((res, rej) => db.get(sql, params, (e, r) => (e ? rej(e) : res(r))));
}
function all(sql, params = []) {
  return new Promise((res, rej) => db.all(sql, params, (e, r) => (e ? rej(e) : res(r))));
}
function run(sql, params = []) {
  return new Promise((res, rej) =>
    db.run(sql, params, function (e) {
      if (e) rej(e);
      else res({ lastID: this.lastID, changes: this.changes });
    })
  );
}

module.exports = { db, get, all, run, onReady };
