const validator = require(“validator”);
const router  = require(“express”).Router();
const db      = require(”../database”);
const bcrypt  = require(“bcryptjs”);
const jwt     = require(“jsonwebtoken”);
const { v4: uuidv4 } = require(“uuid”);
const crypto  = require(“crypto”);
const { invalidate: bustCache } = require(”../obf_cache”);

const JWT_SECRET = process.env.JWT_SECRET;

// FIXED CRIT-5: allowlist for protection_level
const VALID_LEVELS = new Set([“light”, “medium”, “max”]);

function sanitizeText(str, maxLen = 200) {
if (str === null || str === undefined) return “”;
return String(str).trim().slice(0, maxLen);
}

// FIXED CRIT-14: admin tokens require role:‘admin’ AND the token must have
// been issued by the admin login endpoint (audience claim).
// User tokens use audience:‘user’ so they can NEVER pass this check even
// if someone crafts a payload with role:‘admin’.
async function auth(req, res, next) {
const h = req.headers.authorization || “”;
const t = h.startsWith(“Bearer “) ? h.slice(7) : null;
if (!t) return res.status(401).json({ error: “No token” });
try {
const payload = jwt.verify(t, JWT_SECRET, { audience: “admin” });
if (payload.role !== “admin”) return res.status(403).json({ error: “Admin access required” });
req.user = payload;
next();
} catch {
res.status(401).json({ error: “Invalid or expired token” });
}
}

function genKey() {
return Array.from({ length: 5 }, () =>
crypto.randomBytes(3).toString(“hex”).toUpperCase()
).join(”-”);
}

function lockerEncrypt(script, existingSeed = null) {
const seed = existingSeed || crypto.randomBytes(16).toString(“hex”).toUpperCase();
const key  = Buffer.from(seed.padEnd(32, “0”).slice(0, 32));
const iv   = crypto.randomBytes(12);
const cipher = crypto.createCipheriv(“aes-256-gcm”, key, iv);
let enc = cipher.update(script, “utf8”, “hex”);
enc += cipher.final(“hex”);
const tag = cipher.getAuthTag().toString(“hex”);
return { stored: `${iv.toString("hex")}:${enc}:${tag}`, seed };
}

// – Admin login —————————————————————
router.post(”/login”,
(req, res, next) => req.app.locals.limiters.adminLoginLimiter(req, res, next),
async (req, res) => {
const { username, password } = req.body || {};
if (!username || !password) return res.status(400).json({ error: “Username and password required” });
try {
const user = await db.get(
“SELECT id, username, role, password FROM users WHERE username = ? AND role = ‘admin’”,
[username]
);
if (!user) return res.status(401).json({ error: “Invalid credentials” });

```
  // FIXED CRIT-13: async bcrypt
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [user.id]);

  // FIXED CRIT-14: audience:'admin' so user tokens can never pass admin auth()
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h", audience: "admin" }
  );
  res.json({ token });
} catch (err) {
  console.error("[ADMIN-LOGIN]", err.message);
  res.status(500).json({ error: "Login failed" });
}
```

}
);

router.get(”/verify”, auth, async (req, res) => {
try {
const user = await db.get(“SELECT id, username, role FROM users WHERE id = ?”, [req.user.id]);
if (!user) return res.status(401).json({ error: “User not found” });
res.json({ valid: true, user: { id: user.id, username: user.username, role: user.role } });
} catch (err) {
console.error(”[ADMIN-VERIFY]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

router.get(”/stats”, auth, async (req, res) => {
try {
const [projects, keys, active_keys, auths_today, auths_ok, auths_fail, active_sessions] =
await Promise.all([
db.get(“SELECT COUNT(*) as c FROM projects”),
db.get(“SELECT COUNT(*) as c FROM licenses”),
db.get(“SELECT COUNT(*) as c FROM licenses WHERE paused = 0”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE status = ‘ok’  AND ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE status = ‘fail’ AND ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM active_sessions WHERE last_ping > strftime(’%s’,‘now’) - 120”),
]);
res.json({
projects: projects.c, keys: keys.c, active_keys: active_keys.c,
auths_today: auths_today.c, auths_ok: auths_ok.c, auths_fail: auths_fail.c,
active_sessions: active_sessions.c,
});
} catch (err) {
console.error(”[ADMIN-STATS]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

// – Projects ——————————————————————
router.get(”/projects”, auth, async (req, res) => {
try {
const projects = await db.all(`SELECT p.*, (SELECT COUNT(*) FROM licenses  l WHERE l.project_id = p.id) as key_count, (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths FROM projects p ORDER BY p.created_at DESC`);
res.json(projects);
} catch (err) {
console.error(”[ADMIN-PROJECTS]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

router.get(”/projects/:id”, auth, async (req, res) => {
try {
const p = await db.get(“SELECT * FROM projects WHERE id = ?”, [req.params.id]);
if (!p) return res.status(404).json({ error: “Not found” });
res.json(p);
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.post(”/projects”, auth, async (req, res) => {
const { name, description, script, version, protection_level,
lightning, silent, ffa, heartbeat, source_locker, obfuscate } = req.body || {};
if (!name || !script) return res.status(400).json({ error: “name and script required” });

// FIXED CRIT-5: validate protection_level
const safeLevel = VALID_LEVELS.has(protection_level) ? protection_level : “max”;
// FIXED CRIT-6: validate heartbeat is a safe integer
const safeHeartbeat = Math.min(Math.max(0, parseInt(heartbeat) || 0), 100);

const id = uuidv4();
let finalScript = script;
let seedToReturn = null;

if (source_locker) {
const { stored, seed } = lockerEncrypt(script);
finalScript = stored;
seedToReturn = seed;
}

try {
await db.run(
`INSERT INTO projects (id, user_id, name, description, script, version, script_version, protection_level, lightning, silent, ffa, heartbeat, source_locker, obfuscate) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
[
id, req.user.id,
sanitizeText(name, 100),
sanitizeText(description, 500),
finalScript,
sanitizeText(version, 20) || “1.0.0”,
safeLevel,
lightning ? 1 : 0, silent ? 1 : 0, ffa ? 1 : 0,
safeHeartbeat,
source_locker ? 1 : 0,
obfuscate !== undefined ? (obfuscate ? 1 : 0) : 1,
]
);
const proj = await db.get(“SELECT * FROM projects WHERE id = ?”, [id]);
if (seedToReturn) proj.locker_seed = seedToReturn;
res.json(proj);
} catch (err) {
console.error(”[ADMIN-CREATE-PROJECT]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

router.put(”/projects/:id”, auth, async (req, res) => {
const { name, description, script, version, protection_level, lightning, silent,
ffa, heartbeat, verified, locker_seed, obfuscate } = req.body || {};
try {
const p = await db.get(“SELECT * FROM projects WHERE id = ?”, [req.params.id]);
if (!p) return res.status(404).json({ error: “Not found” });

```
let finalScript  = null;
let versionBumped = false;

if (script !== undefined && script !== null) {
  if (p.source_locker) {
    if (!locker_seed) return res.status(400).json({ error: "Provide locker_seed to update a Source Locker project." });
    const { stored } = lockerEncrypt(script, locker_seed);
    finalScript = stored;
  } else {
    finalScript = script;
  }
  versionBumped = true;
}

const updates = [], values = [];
if (name        !== undefined) { updates.push("name = ?");             values.push(sanitizeText(name, 100)); }
if (description !== undefined) { updates.push("description = ?");      values.push(sanitizeText(description, 500)); }
if (finalScript !== null)      { updates.push("script = ?");           values.push(finalScript); }
if (version     !== undefined) { updates.push("version = ?");          values.push(sanitizeText(version, 20)); }
if (protection_level !== undefined) {
  // FIXED CRIT-5
  updates.push("protection_level = ?");
  values.push(VALID_LEVELS.has(protection_level) ? protection_level : "max");
}
if (lightning !== undefined) { updates.push("lightning = ?"); values.push(lightning ? 1 : 0); }
if (silent    !== undefined) { updates.push("silent = ?");    values.push(silent    ? 1 : 0); }
if (ffa       !== undefined) { updates.push("ffa = ?");       values.push(ffa       ? 1 : 0); }
if (heartbeat !== undefined) {
  // FIXED CRIT-6
  updates.push("heartbeat = ?");
  values.push(Math.min(Math.max(0, parseInt(heartbeat) || 0), 100));
}
if (verified  !== undefined) { updates.push("verified = ?");  values.push(verified  ? 1 : 0); }
if (obfuscate !== undefined) { updates.push("obfuscate = ?"); values.push(obfuscate ? 1 : 0); }
if (versionBumped) updates.push("script_version = script_version + 1");
updates.push("updated_at = strftime('%s','now')");
values.push(req.params.id);

if (updates.length > 1) {
  await db.run(`UPDATE projects SET ${updates.join(", ")} WHERE id = ?`, values);
}

if (versionBumped) bustCache(req.params.id);
res.json(await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]));
```

} catch (err) {
console.error(”[ADMIN-UPDATE-PROJECT]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

router.delete(”/projects/:id”, auth, async (req, res) => {
try {
bustCache(req.params.id);
await db.run(“DELETE FROM projects WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

// – Keys –––––––––––––––––––––––––––––––––––
router.get(”/projects/:id/keys”, auth, async (req, res) => {
try {
res.json(await db.all(
“SELECT * FROM licenses WHERE project_id = ? ORDER BY created_at DESC”,
[req.params.id]
));
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.post(”/projects/:id/keys”, auth, async (req, res) => {
try {
const proj = await db.get(“SELECT id FROM projects WHERE id = ?”, [req.params.id]);
if (!proj) return res.status(404).json({ error: “Project not found” });

```
const { note, expires_in_days, max_activations, count = 1, key_days, auth_expire, discord_id } = req.body || {};
const expires_at      = expires_in_days ? Math.floor(Date.now() / 1000) + Number(expires_in_days) * 86400 : null;
const auth_expire_ts  = auth_expire     ? Math.floor(Date.now() / 1000) + Number(auth_expire)     * 86400 : null;
const batchSize = Math.min(Math.max(1, Number(count) || 1), 500);
const generated = [];

for (let i = 0; i < batchSize; i++) {
  const id  = uuidv4();
  const key = genKey();
  await db.run(
    `INSERT INTO licenses (id, project_id, key_value, max_activations, expires_at, note, key_days, auth_expire, discord_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, req.params.id, key, max_activations || null, expires_at,
     sanitizeText(note, 200), key_days || null, auth_expire_ts, discord_id || null]
  );
  generated.push({ id, key, expires_at, auth_expire: auth_expire_ts });
}
res.json(generated);
```

} catch (err) {
console.error(”[ADMIN-GEN-KEYS]”, err.message);
res.status(500).json({ error: “Internal server error” });
}
});

router.delete(”/keys/:id”, auth, async (req, res) => {
try {
const key = await db.get(“SELECT id FROM licenses WHERE id = ?”, [req.params.id]);
if (!key) return res.status(404).json({ error: “Key not found” });
await db.run(“DELETE FROM licenses WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.patch(”/keys/:id/pause”, auth, async (req, res) => {
try {
const k = await db.get(“SELECT paused FROM licenses WHERE id = ?”, [req.params.id]);
if (!k) return res.status(404).json({ error: “Not found” });
await db.run(“UPDATE licenses SET paused = ? WHERE id = ?”, [k.paused ? 0 : 1, req.params.id]);
res.json({ success: true, paused: !k.paused });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.patch(”/keys/:id/reset-hwid”, auth, async (req, res) => {
try {
await db.run(“UPDATE licenses SET hwid = NULL WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.patch(”/keys/:id/reset-discord”, auth, async (req, res) => {
try {
await db.run(“UPDATE licenses SET discord_id = NULL WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

// – Logs –––––––––––––––––––––––––––––––––––
router.get(”/logs”, auth, async (req, res) => {
const { project_id, status, limit = 200 } = req.query;
let sql = “SELECT * FROM auth_logs WHERE 1=1”;
const params = [];
if (project_id) { sql += “ AND project_id = ?”; params.push(project_id); }
if (status)     { sql += “ AND status = ?”;     params.push(status); }
sql += “ ORDER BY ts DESC LIMIT ?”;
params.push(Math.min(Number(limit) || 200, 1000));
try {
res.json(await db.all(sql, params));
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.get(”/sessions”, auth, async (req, res) => {
try {
res.json(await db.all(
“SELECT * FROM active_sessions WHERE last_ping > strftime(’%s’,‘now’) - 120”
));
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.get(”/verify-queue”, auth, async (req, res) => {
try {
res.json(await db.all(“SELECT * FROM projects WHERE verified = 0 ORDER BY created_at DESC”));
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

router.post(”/verify/:id”, auth, async (req, res) => {
const { approved } = req.body;
try {
if (approved) await db.run(“UPDATE projects SET verified = 1 WHERE id = ?”, [req.params.id]);
else          await db.run(“DELETE FROM projects WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: “Internal server error” });
}
});

module.exports = router;
