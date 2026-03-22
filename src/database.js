var sqlite3 = require("sqlite3").verbose();
var path = require("path");
var fs = require("fs");
var bcrypt = require("bcryptjs");
var crypto = require("crypto");

var JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("[FATAL] JWT_SECRET is missing or too short (min 32 chars).");
  process.exit(1);
}

process.env.LOADER_SECRET = process.env.LOADER_SECRET ||
  crypto.createHmac("sha256", JWT_SECRET).update("loader").digest("hex");
process.env.SESSION_SECRET = process.env.SESSION_SECRET ||
  crypto.createHmac("sha256", JWT_SECRET).update("session").digest("hex");

if (process.env.NODE_ENV === "production") {
  var ap = process.env.ADMIN_PASSWORD || "";
  if (!ap || ap === "admin123" || ap.startsWith("CHANGE_ME")) {
    console.error("[FATAL] ADMIN_PASSWORD must be changed from default in production.");
    process.exit(1);
  }
}

var DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  process.env.DATA_DIR ||
  path.join(__dirname, "../data");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

var db = new sqlite3.Database(path.join(DATA_DIR, "surfix.db"));

db.on("error", function(err) {
  if (err && err.message && (
    err.message.includes("_users_old_rebuild") ||
    err.message.includes("no such table")
  )) return;
  console.error("[DB] error:", err.message);
});

var _dbReady = false;
var _readyQ = [];
function onReady(fn) {
  if (_dbReady) return fn();
  _readyQ.push(fn);
}
function _markReady() {
  _dbReady = true;
  _readyQ.forEach(function(fn) { fn(); });
}

function execSQL(sql) {
  return new Promise(function(resolve) {
    db.exec(sql, function(err) {
      if (err &&
          !err.message.includes("already exists") &&
          !err.message.includes("duplicate column") &&
          !err.message.includes("no such table")) {
        console.warn("[DB exec]", sql.slice(0, 60), err.message);
      }
      resolve();
    });
  });
}

function get(sql, params) {
  return new Promise(function(res, rej) {
    db.get(sql, params || [], function(e, r) { if (e) rej(e); else res(r); });
  });
}

function all(sql, params) {
  return new Promise(function(res, rej) {
    db.all(sql, params || [], function(e, r) { if (e) rej(e); else res(r); });
  });
}

function run(sql, params) {
  return new Promise(function(res, rej) {
    db.run(sql, params || [], function(e) {
      if (e) rej(e);
      else res({ lastID: this.lastID, changes: this.changes });
    });
  });
}

var USERS_DDL = [
  "CREATE TABLE IF NOT EXISTS users (",
  "id TEXT PRIMARY KEY,",
  "username TEXT UNIQUE,",
  "email TEXT,",
  "password TEXT,",
  "role TEXT NOT NULL DEFAULT 'user',",
  "plan TEXT NOT NULL DEFAULT 'free',",
  "avatar_url TEXT,",
  "verified INTEGER NOT NULL DEFAULT 0,",
  "verify_token TEXT,",
  "reset_token TEXT,",
  "reset_expires INTEGER,",
  "api_key TEXT,",
  "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),",
  "last_login INTEGER)"
].join(" ");

async function setup() {
  await execSQL("PRAGMA journal_mode = WAL");
  await execSQL("PRAGMA foreign_keys = OFF");
  await execSQL("PRAGMA synchronous = NORMAL");

  await execSQL("DROP TABLE IF EXISTS _users_old_rebuild");

  var usersRow = await get("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'");
  if (!usersRow) {
    await execSQL(USERS_DDL);
  } else {
    var lines = (usersRow.sql || "").split("\n");
    var pwLine = lines.find(function(l) { return l.trim().toLowerCase().startsWith("password"); });
    if (pwLine && pwLine.toUpperCase().includes("NOT NULL")) {
      console.log("[DB] Rebuilding users table to remove NOT NULL from password...");
      await execSQL("ALTER TABLE users RENAME TO _users_old_rebuild");
      await execSQL(USERS_DDL);
      await execSQL(
        "INSERT INTO users (id, username, password, created_at) " +
        "SELECT id, username, password, COALESCE(created_at, strftime('%s','now')) " +
        "FROM _users_old_rebuild"
      );
      await execSQL("DROP TABLE IF EXISTS _users_old_rebuild");
      console.log("[DB] Rebuild complete.");
    }
  }

  await execSQL("CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, user_id TEXT, name TEXT NOT NULL, description TEXT DEFAULT '', script TEXT NOT NULL DEFAULT '', version TEXT DEFAULT '1.0.0', script_version INTEGER DEFAULT 1, protection_level TEXT DEFAULT 'max', lightning INTEGER DEFAULT 0, silent INTEGER DEFAULT 0, ffa INTEGER DEFAULT 0, heartbeat INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, source_locker INTEGER DEFAULT 0, obfuscate INTEGER DEFAULT 1, downloads INTEGER DEFAULT 0, created_at INTEGER DEFAULT (strftime('%s','now')), updated_at INTEGER DEFAULT (strftime('%s','now')))");
  await execSQL("CREATE TABLE IF NOT EXISTS licenses (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, key_value TEXT UNIQUE NOT NULL, hwid TEXT, discord_id TEXT, key_days INTEGER, auth_expire INTEGER, max_activations INTEGER, activations INTEGER NOT NULL DEFAULT 0, expires_at INTEGER, paused INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), last_used INTEGER)");
  await execSQL("CREATE TABLE IF NOT EXISTS active_sessions (id TEXT PRIMARY KEY, license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE, session_id TEXT NOT NULL, last_ping INTEGER NOT NULL DEFAULT (strftime('%s','now')), ip TEXT, UNIQUE(license_id, session_id))");
  await execSQL("CREATE TABLE IF NOT EXISTS auth_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, license_id TEXT, project_id TEXT NOT NULL, hwid TEXT, ip TEXT, platform TEXT NOT NULL DEFAULT 'unknown', status TEXT NOT NULL, reason TEXT, ts INTEGER NOT NULL DEFAULT (strftime('%s','now')))");
  await execSQL("CREATE TABLE IF NOT EXISTS oauth_accounts (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, provider_id TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), UNIQUE(provider, provider_id))");

  var migrations = [
    "ALTER TABLE users ADD COLUMN email TEXT",
    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'",
    "ALTER TABLE users ADD COLUMN avatar_url TEXT",
    "ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN verify_token TEXT",
    "ALTER TABLE users ADD COLUMN reset_token TEXT",
    "ALTER TABLE users ADD COLUMN reset_expires INTEGER",
    "ALTER TABLE users ADD COLUMN last_login INTEGER",
    "ALTER TABLE users ADD COLUMN api_key TEXT",
    "ALTER TABLE projects ADD COLUMN obfuscate INTEGER NOT NULL DEFAULT 1"
  ];
  for (var i = 0; i < migrations.length; i++) {
    await execSQL(migrations[i]);
  }

  await execSQL("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email ON users(email) WHERE email IS NOT NULL");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_lic_key ON licenses(key_value)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_lic_project ON licenses(project_id)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_sess_license ON active_sessions(license_id)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_sess_ping ON active_sessions(last_ping)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_log_ts ON auth_logs(ts)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_log_project ON auth_logs(project_id)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_accounts(user_id)");
  await execSQL("CREATE INDEX IF NOT EXISTS idx_proj_user ON projects(user_id)");
  await execSQL("PRAGMA foreign_keys = ON");
  await execSQL("UPDATE projects SET obfuscate = 1 WHERE obfuscate IS NULL");
  await execSQL("UPDATE projects SET user_id = 'admin-1' WHERE user_id IS NULL");

  var adminRow = await get("SELECT id FROM users WHERE username = 'admin'");
  if (adminRow) {
    await run("UPDATE users SET role = 'admin', verified = 1, email = COALESCE(NULLIF(email,''), 'admin@surfix.local') WHERE username = 'admin'");
  } else {
    var hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "admin123", 12);
    try {
      await run("INSERT INTO users (id, username, email, password, role, verified) VALUES ('admin-1', 'admin', 'admin@surfix.local', ?, 'admin', 1)", [hash]);
    } catch (e) {
      if (!e.message.includes("UNIQUE")) console.error("[DB] seed error:", e.message);
    }
  }

  _markReady();
  console.log("[DB] Ready.");
}

setup().catch(function(err) {
  console.error("[DB] Setup failed:", err.message);
  process.exit(1);
});

module.exports = { db: db, get: get, all: all, run: run, onReady: onReady };
