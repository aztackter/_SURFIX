var validator = require(“validator”);
var router = require(“express”).Router();
var db = require(”../database”);
var bcrypt = require(“bcryptjs”);
var jwt = require(“jsonwebtoken”);
var uuidv4 = require(“uuid”).v4;
var crypto = require(“crypto”);
var bustCache = require(”../obf_cache”).invalidate;

var JWT_SECRET = process.env.JWT_SECRET;
var VALID_LEVELS = new Set([“light”, “medium”, “max”]);

function sanitizeText(str, maxLen) {
maxLen = maxLen || 200;
if (str === null || str === undefined) return “”;
return String(str).trim().slice(0, maxLen);
}

async function auth(req, res, next) {
var h = req.headers.authorization || “”;
var t = h.startsWith(“Bearer “) ? h.slice(7) : null;
if (!t) return res.status(401).json({ error: “No token” });
try {
var payload = jwt.verify(t, JWT_SECRET, { audience: “admin” });
if (payload.role !== “admin”) return res.status(403).json({ error: “Admin access required” });
req.user = payload;
next();
} catch (e) {
res.status(401).json({ error: “Invalid or expired token” });
}
}

function genKey() {
return Array.from({ length: 5 }, function() {
return crypto.randomBytes(3).toString(“hex”).toUpperCase();
}).join(”-”);
}

function lockerEncrypt(script, existingSeed) {
var seed = existingSeed || crypto.randomBytes(16).toString(“hex”).toUpperCase();
var key = Buffer.from(seed.padEnd(32, “0”).slice(0, 32));
var iv = crypto.randomBytes(12);
var cipher = crypto.createCipheriv(“aes-256-gcm”, key, iv);
var enc = cipher.update(script, “utf8”, “hex”);
enc += cipher.final(“hex”);
var tag = cipher.getAuthTag().toString(“hex”);
return { stored: iv.toString(“hex”) + “:” + enc + “:” + tag, seed: seed };
}

// Admin login
router.post(”/login”,
function(req, res, next) { req.app.locals.limiters.adminLoginLimiter(req, res, next); },
async function(req, res) {
var body = req.body || {};
var username = body.username;
var password = body.password;
if (!username || !password) return res.status(400).json({ error: “Username and password required” });
try {
var user = await db.get(
“SELECT id, username, role, password FROM users WHERE username = ? AND role = ‘admin’”,
[username]
);
if (!user) return res.status(401).json({ error: “Invalid credentials” });
var ok = await bcrypt.compare(password, user.password);
if (!ok) return res.status(401).json({ error: “Invalid credentials” });
await db.run(“UPDATE users SET last_login = strftime(’%s’,‘now’) WHERE id = ?”, [user.id]);
var token = jwt.sign(
{ id: user.id, username: user.username, role: user.role },
JWT_SECRET,
{ expiresIn: “12h”, audience: “admin” }
);
res.json({ token: token });
} catch (err) {
console.error(”[ADMIN LOGIN]”, err.message);
res.status(500).json({ error: “Login failed” });
}
}
);

router.get(”/verify”, auth, async function(req, res) {
try {
var user = await db.get(“SELECT id, username, role FROM users WHERE id = ?”, [req.user.id]);
if (!user) return res.status(401).json({ error: “User not found” });
res.json({ valid: true, user: { id: user.id, username: user.username, role: user.role } });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/stats”, auth, async function(req, res) {
try {
var results = await Promise.all([
db.get(“SELECT COUNT(*) as c FROM projects”),
db.get(“SELECT COUNT(*) as c FROM licenses”),
db.get(“SELECT COUNT(*) as c FROM licenses WHERE paused = 0”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE status = ‘ok’ AND ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM auth_logs WHERE status = ‘fail’ AND ts > strftime(’%s’,‘now’) - 86400”),
db.get(“SELECT COUNT(*) as c FROM active_sessions WHERE last_ping > strftime(’%s’,‘now’) - 120”)
]);
res.json({
projects: results[0].c, keys: results[1].c, active_keys: results[2].c,
auths_today: results[3].c, auths_ok: results[4].c, auths_fail: results[5].c,
active_sessions: results[6].c
});
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/projects”, auth, async function(req, res) {
try {
var projects = await db.all(
“SELECT p.*, (SELECT COUNT(*) FROM licenses l WHERE l.project_id = p.id) as key_count, (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths FROM projects p ORDER BY p.created_at DESC”
);
res.json(projects);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/projects/:id”, auth, async function(req, res) {
try {
var p = await db.get(“SELECT * FROM projects WHERE id = ?”, [req.params.id]);
if (!p) return res.status(404).json({ error: “Not found” });
res.json(p);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.post(”/projects”, auth, async function(req, res) {
var body = req.body || {};
var name = body.name;
var script = body.script;
if (!name || !script) return res.status(400).json({ error: “name and script required” });

var id = uuidv4();
var finalScript = script;
var seedToReturn = null;

if (body.source_locker) {
var encrypted = lockerEncrypt(script);
finalScript = encrypted.stored;
seedToReturn = encrypted.seed;
}

try {
await db.run(
“INSERT INTO projects (id, user_id, name, description, script, version, script_version, protection_level, lightning, silent, ffa, heartbeat, source_locker, obfuscate) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)”,
[id, req.user.id, sanitizeText(name, 100), sanitizeText(body.description, 500), finalScript,
sanitizeText(body.version, 20) || “1.0.0”, VALID_LEVELS.has(body.protection_level) ? body.protection_level : “max”,
body.lightning ? 1 : 0, body.silent ? 1 : 0, body.ffa ? 1 : 0,
body.heartbeat || 0, body.source_locker ? 1 : 0,
body.obfuscate !== undefined ? (body.obfuscate ? 1 : 0) : 1]
);
var proj = await db.get(“SELECT * FROM projects WHERE id = ?”, [id]);
if (seedToReturn) proj.locker_seed = seedToReturn;
res.json(proj);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.put(”/projects/:id”, auth, async function(req, res) {
var body = req.body || {};
try {
var p = await db.get(“SELECT * FROM projects WHERE id = ?”, [req.params.id]);
if (!p) return res.status(404).json({ error: “Not found” });

```
var finalScript = null;
var versionBumped = false;

if (body.script !== undefined && body.script !== null) {
  if (p.source_locker) {
    if (!body.locker_seed) return res.status(400).json({ error: "This project uses Source Locker. Provide locker_seed to update the script." });
    var re = lockerEncrypt(body.script, body.locker_seed);
    finalScript = re.stored;
    versionBumped = true;
  } else {
    finalScript = body.script;
    versionBumped = true;
  }
}

var updates = [];
var values = [];
if (body.name !== undefined)             { updates.push("name = ?");             values.push(sanitizeText(body.name, 100)); }
if (body.description !== undefined)      { updates.push("description = ?");      values.push(sanitizeText(body.description, 500)); }
if (finalScript !== null)                { updates.push("script = ?");           values.push(finalScript); }
if (body.version !== undefined)          { updates.push("version = ?");          values.push(sanitizeText(body.version, 20)); }
if (body.protection_level !== undefined) { updates.push("protection_level = ?"); values.push(VALID_LEVELS.has(body.protection_level) ? body.protection_level : "max"); }
if (body.lightning !== undefined)        { updates.push("lightning = ?");        values.push(body.lightning ? 1 : 0); }
if (body.silent !== undefined)           { updates.push("silent = ?");           values.push(body.silent ? 1 : 0); }
if (body.ffa !== undefined)              { updates.push("ffa = ?");              values.push(body.ffa ? 1 : 0); }
if (body.heartbeat !== undefined)        { updates.push("heartbeat = ?");        values.push(body.heartbeat); }
if (body.verified !== undefined)         { updates.push("verified = ?");         values.push(body.verified ? 1 : 0); }
if (body.obfuscate !== undefined)        { updates.push("obfuscate = ?");        values.push(body.obfuscate ? 1 : 0); }
if (versionBumped) updates.push("script_version = script_version + 1");
updates.push("updated_at = strftime('%s','now')");
values.push(req.params.id);

if (updates.length > 1) {
  await db.run("UPDATE projects SET " + updates.join(", ") + " WHERE id = ?", values);
}
if (versionBumped) bustCache(req.params.id);

var updated = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
res.json(updated);
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.delete(”/projects/:id”, auth, async function(req, res) {
try {
bustCache(req.params.id);
await db.run(“DELETE FROM projects WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/projects/:id/keys”, auth, async function(req, res) {
try {
var keys = await db.all(“SELECT * FROM licenses WHERE project_id = ? ORDER BY created_at DESC”, [req.params.id]);
res.json(keys);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.post(”/projects/:id/keys”, auth, async function(req, res) {
try {
var proj = await db.get(“SELECT id FROM projects WHERE id = ?”, [req.params.id]);
if (!proj) return res.status(404).json({ error: “Project not found” });
var body = req.body || {};
var count = Math.min(Math.max(1, Number(body.count) || 1), 500);
var expires_at = body.expires_in_days ? Math.floor(Date.now() / 1000) + Number(body.expires_in_days) * 86400 : null;
var auth_expire_ts = body.auth_expire ? Math.floor(Date.now() / 1000) + Number(body.auth_expire) * 86400 : null;
var generated = [];
for (var i = 0; i < count; i++) {
var id = uuidv4();
var key = genKey();
await db.run(
“INSERT INTO licenses (id, project_id, key_value, max_activations, expires_at, note, key_days, auth_expire, discord_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)”,
[id, req.params.id, key, body.max_activations || null, expires_at,
sanitizeText(body.note, 200), body.key_days || null, auth_expire_ts, body.discord_id || null]
);
generated.push({ id: id, key: key, expires_at: expires_at, auth_expire: auth_expire_ts });
}
res.json(generated);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.delete(”/keys/:id”, auth, async function(req, res) {
try {
var key = await db.get(“SELECT id FROM licenses WHERE id = ?”, [req.params.id]);
if (!key) return res.status(404).json({ error: “Key not found” });
await db.run(“DELETE FROM licenses WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.patch(”/keys/:id/pause”, auth, async function(req, res) {
try {
var k = await db.get(“SELECT paused FROM licenses WHERE id = ?”, [req.params.id]);
if (!k) return res.status(404).json({ error: “Not found” });
await db.run(“UPDATE licenses SET paused = ? WHERE id = ?”, [k.paused ? 0 : 1, req.params.id]);
res.json({ success: true, paused: !k.paused });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.patch(”/keys/:id/reset-hwid”, auth, async function(req, res) {
try {
await db.run(“UPDATE licenses SET hwid = NULL WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.patch(”/keys/:id/reset-discord”, auth, async function(req, res) {
try {
await db.run(“UPDATE licenses SET discord_id = NULL WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/logs”, auth, async function(req, res) {
var project_id = req.query.project_id;
var status = req.query.status;
var limit = Math.min(Number(req.query.limit) || 200, 1000);
var sql = “SELECT * FROM auth_logs WHERE 1=1”;
var params = [];
if (project_id) { sql += “ AND project_id = ?”; params.push(project_id); }
if (status)     { sql += “ AND status = ?”;     params.push(status); }
sql += “ ORDER BY ts DESC LIMIT ?”;
params.push(limit);
try {
res.json(await db.all(sql, params));
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/sessions”, auth, async function(req, res) {
try {
res.json(await db.all(“SELECT * FROM active_sessions WHERE last_ping > strftime(’%s’,‘now’) - 120”));
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.get(”/verify-queue”, auth, async function(req, res) {
try {
res.json(await db.all(“SELECT * FROM projects WHERE verified = 0 ORDER BY created_at DESC”));
} catch (err) {
res.status(500).json({ error: err.message });
}
});

router.post(”/verify/:id”, auth, async function(req, res) {
try {
if (req.body.approved) await db.run(“UPDATE projects SET verified = 1 WHERE id = ?”, [req.params.id]);
else await db.run(“DELETE FROM projects WHERE id = ?”, [req.params.id]);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

module.exports = router;
