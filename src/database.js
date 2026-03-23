async function setup() {
  await execSQL("PRAGMA journal_mode = WAL");
  await execSQL("PRAGMA foreign_keys = OFF");
  await execSQL("PRAGMA synchronous = NORMAL");

  // Create users table if not exists
  await execSQL(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    plan TEXT NOT NULL DEFAULT 'free',
    avatar_url TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT,
    reset_token TEXT,
    reset_expires INTEGER,
    api_key TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_login INTEGER
  )`);

  // Create other tables
  await execSQL(`CREATE TABLE IF NOT EXISTS projects (
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
    obfuscate INTEGER DEFAULT 1,
    downloads INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    updated_at INTEGER DEFAULT (strftime('%s','now'))
  )`);

  await execSQL(`CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key_value TEXT UNIQUE NOT NULL,
    hwid TEXT,
    discord_id TEXT,
    key_days INTEGER,
    auth_expire INTEGER,
    max_activations INTEGER,
    activations INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    paused INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_used INTEGER
  )`);

  await execSQL(`CREATE TABLE IF NOT EXISTS active_sessions (
    id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    last_ping INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    ip TEXT,
    UNIQUE(license_id, session_id)
  )`);

  await execSQL(`CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT,
    project_id TEXT NOT NULL,
    hwid TEXT,
    ip TEXT,
    platform TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL,
    reason TEXT,
    ts INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  )`);

  await execSQL(`CREATE TABLE IF NOT EXISTS oauth_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(provider, provider_id)
  )`);

  // Add missing columns (safe to run even if they exist)
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
    try {
      await execSQL(migrations[i]);
    } catch (e) {
      // Column already exists - ignore
    }
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
