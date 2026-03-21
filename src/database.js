const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || path.join(__dirname, "../data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "surfix.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    api_key TEXT UNIQUE,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    script TEXT NOT NULL DEFAULT '',
    version TEXT DEFAULT '1.0.0',
    script_version INTEGER DEFAULT 1,
    protection_level TEXT DEFAULT 'max',
    lightning INTEGER DEFAULT 0,
    silent INTEGER DEFAULT 0,
    ffa INTEGER DEFAULT 0,
    heartbeat INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    source_locker INTEGER DEFAULT 0,
    downloads INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key_value TEXT UNIQUE NOT NULL,
    hwid TEXT,
    discord_id TEXT,
    key_days INTEGER,
    auth_expire INTEGER,
    max_activations INTEGER DEFAULT NULL,
    activations INTEGER DEFAULT 0,
    expires_at INTEGER,
    paused INTEGER DEFAULT 0,
    note TEXT DEFAULT '',
    created_at INTEGER DEFAULT (unixepoch()),
    last_used INTEGER
  );

  CREATE TABLE IF NOT EXISTS active_sessions (
    id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    last_ping INTEGER DEFAULT (unixepoch()),
    ip TEXT
  );

  CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT,
    project_id TEXT NOT NULL,
    hwid TEXT,
    ip TEXT,
    platform TEXT DEFAULT 'unknown',
    status TEXT NOT NULL,
    reason TEXT,
    ts INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key_value);
  CREATE INDEX IF NOT EXISTS idx_licenses_project ON licenses(project_id);
  CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid);
  CREATE INDEX IF NOT EXISTS idx_sessions_license ON active_sessions(license_id);
  CREATE INDEX IF NOT EXISTS idx_logs_ts ON auth_logs(ts);
  CREATE INDEX IF NOT EXISTS idx_logs_status ON auth_logs(status);
  CREATE INDEX IF NOT EXISTS idx_logs_project ON auth_logs(project_id);
  CREATE INDEX IF NOT EXISTS idx_logs_ip ON auth_logs(ip);
`);

const adminExists = db.prepare("SELECT id FROM users WHERE username = ?").get("admin");
if (!adminExists) {
  const pass = process.env.ADMIN_PASSWORD || "admin123";
  const hash = bcrypt.hashSync(pass, 12);
  db.prepare("INSERT INTO users (id, username, password, api_key) VALUES (?, ?, ?, ?)").run(
    "admin-1", "admin", hash,
    "surfix-" + crypto.randomBytes(24).toString("hex")
  );
}

module.exports = db;
