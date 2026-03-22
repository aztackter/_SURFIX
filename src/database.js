const sqlite3 = require("sqlite3").verbose();
const path    = require("path");
const fs      = require("fs");
const bcrypt  = require("bcryptjs");

// ─── Boot-time secret validation ─────────────────────────────────────────────
const REQUIRED_SECRETS = ["JWT_SECRET", "LOADER_SECRET", "SESSION_SECRET"];
for (const key of REQUIRED_SECRETS) {
  const val = process.env[key] || "";
  if (!val || val.startsWith("CHANGE_ME") || val.length < 32) {
    console.error(`[FATAL] ${key} is missing or too short (min 32 chars).`);
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

// ─── DB path ──────────────────────────────────────────────────────────────────
const DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  process.env.DATA_DIR ||
  path.join(__dirname, "../data");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, "surfix.db"));

// ─── Ready gate ───────────────────────────────────────────────────────────────
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

// ─── Schema + migrations ─────────────────────────────────────────────────────
// Everything inside one db.serialize() call so statements run in strict order.
// ALTER TABLE statements are safe to re-run — errors for duplicate columns are ignored.
db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA foreign_keys = OFF"); // OFF during migrations to avoid FK errors
  db.run("PRAGMA synchronous = NORMAL");

  // ── Core tables ─────────────────────────────────────────────────────────────
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT UNIQUE,
    password   TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS projects (
    id               TEXT PRIMARY KEY,
    user_id          TEXT,
    name             TEXT NOT NULL,
    description      TEXT DEFAULT '',
    script           TEXT NOT NULL DEFAULT '',
    version          TEXT DEFAULT '1.0.0',
    script_version   INTEGER DEFAULT 1,
    protection_level TEXT DEFAULT 'max',
    lightning        INTEGER DEFAULT 0,
    silent           INTEGER DEFAULT 0,
    ffa              INTEGER DEFAULT 0,
    heartbeat        INTEGER DEFAULT 0,
    verified         INTEGER DEFAULT 0,
    source_locker    INTEGER DEFAULT 0,
    downloads        INTEGER DEFAULT 0,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
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

  db.run(`CREATE TABLE IF NOT EXISTS active_sessions (
    id         TEXT PRIMARY KEY,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    last_ping  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    ip         TEXT
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

  db.run(`CREATE TABLE IF NOT EXISTS oauth_accounts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(provider, provider_id)
  )`);

  // ── Migrations — add new columns to existing tables ──────────────────────
  // Each one silently no-ops if the column already exists.
  const migrations = [
    "ALTER TABLE users ADD COLUMN email         TEXT",
    "ALTER TABLE users ADD COLUMN role          TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE users ADD COLUMN plan          TEXT NOT NULL DEFAULT 'free'",
    "ALTER TABLE users ADD COLUMN avatar_url    TEXT",
    "ALTER TABLE users ADD COLUMN verified      INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN verify_token  TEXT",
    "ALTER TABLE users ADD COLUMN reset_token   TEXT",
    "ALTER TABLE users ADD COLUMN reset_expires INTEGER",
    "ALTER TABLE users ADD COLUMN last_login    INTEGER",
    "ALTER TABLE users ADD COLUMN api_key       TEXT",
    "ALTER TABLE projects ADD COLUMN obfuscate  INTEGER NOT NULL DEFAULT 1",
  ];

  for (const sql of migrations) {
    db.run(sql, (err) => {
      if (err && !err.message.includes("duplicate column")) {
        console.warn("[DB migration]", err.message);
      }
    });
  }

  // ── Indexes ──────────────────────────────────────────────────────────────
  db.run("CREATE INDEX IF NOT EXISTS idx_lic_key      ON licenses(key_value)");
  db.run("CREATE INDEX IF NOT EXISTS idx_lic_project  ON licenses(project_id)");
  db.run("CREATE INDEX IF NOT EXISTS idx_lic_hwid     ON licenses(hwid)");
  db.run("CREATE INDEX IF NOT EXISTS idx_sess_license ON active_sessions(license_id)");
  db.run("CREATE INDEX IF NOT EXISTS idx_sess_ping    ON active_sessions(last_ping)");
  db.run("CREATE INDEX IF NOT EXISTS idx_log_ts       ON auth_logs(ts)");
  db.run("CREATE INDEX IF NOT EXISTS idx_log_status   ON auth_logs(status)");
  db.run("CREATE INDEX IF NOT EXISTS idx_log_project  ON auth_logs(project_id)");
  db.run("CREATE INDEX IF NOT EXISTS idx_log_ip       ON auth_logs(ip)");
  db.run("CREATE INDEX IF NOT EXISTS idx_oauth_user   ON oauth_accounts(user_id)");
  db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email ON users(email) WHERE email IS NOT NULL");
  db.run("CREATE INDEX IF NOT EXISTS idx_proj_user    ON projects(user_id)");

  // ── Re-enable FK enforcement after migrations ────────────────────────────
  db.run("PRAGMA foreign_keys = ON");

  // ── Backfill existing rows with new column values ────────────────────────
  db.run(`UPDATE users SET
    role     = 'admin',
    verified = 1,
    email    = COALESCE(email, 'admin@surfix.local')
  WHERE username = 'admin' AND (role IS NULL OR role = '')`);

  db.run("UPDATE projects SET obfuscate = 1 WHERE obfuscate IS NULL");
  db.run("UPDATE projects SET user_id = 'admin-1' WHERE user_id IS NULL");

  // ── Seed admin user if missing ───────────────────────────────────────────
  db.get("SELECT id FROM users WHERE username = 'admin'", (err, row) => {
    if (row) {
      // Ensure existing admin has all required fields
      const pass = process.env.ADMIN_PASSWORD || "admin123";
      db.get("SELECT password FROM users WHERE username = 'admin'", (e, r) => {
        if (r && !r.password) {
          const hash = bcrypt.hashSync(pass, 12);
          db.run("UPDATE users SET password = ?, role = 'admin', verified = 1, email = COALESCE(email,'admin@surfix.local') WHERE username = 'admin'", [hash]);
        }
      });
      return _markReady();
    }
    const pass = process.env.ADMIN_PASSWORD || "admin123";
    const hash = bcrypt.hashSync(pass, 12);
    db.run(
      `INSERT INTO users (id, username, email, password, role, verified)
       VALUES ('admin-1', 'admin', 'admin@surfix.local', ?, 'admin', 1)`,
      [hash],
      (e) => {
        if (e && !e.message.includes("UNIQUE")) console.error("[DB] seed error:", e.message);
        _markReady();
      }
    );
  });
});

// ─── Promise helpers ──────────────────────────────────────────────────────────
function get(sql, params = []) {
  return new Promise((res, rej) =>
    db.get(sql, params, (e, r) => (e ? rej(e) : res(r)))
  );
}
function all(sql, params = []) {
  return new Promise((res, rej) =>
    db.all(sql, params, (e, r) => (e ? rej(e) : res(r)))
  );
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
