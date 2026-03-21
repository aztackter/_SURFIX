const router = require("express").Router();
const db = require("../database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const { invalidate: bustCache } = require("../obf_cache");

const JWT_SECRET = process.env.JWT_SECRET || "surfix-change-this-secret";

function genKey() {
  return Array.from({ length: 5 }, () => crypto.randomBytes(2).toString("hex").toUpperCase()).join("-");
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function lockerEncrypt(script) {
  const seed = crypto.randomBytes(16).toString("hex").toUpperCase();
  const iv = crypto.randomBytes(12);
  const key = Buffer.from(seed.padEnd(32, "0").slice(0, 32));
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let enc = cipher.update(script, "utf8", "hex");
  enc += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  const stored = `${iv.toString("hex")}:${enc}:${tag}`;
  return { stored, seed };
}

function lockerDecrypt(stored, seed) {
  const [ivHex, enc, tag] = stored.split(":");
  const key = Buffer.from(seed.padEnd(32, "0").slice(0, 32));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tag, "hex"));
  let out = decipher.update(enc, "hex", "utf8");
  out += decipher.final("utf8");
  return out;
}

router.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username || "admin");
  if (!user || !bcrypt.compareSync(password || "", user.password))
    return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "24h" });
  res.json({ token, api_key: user.api_key });
});

router.post("/rotate-api-key", auth, (req, res) => {
  const newKey = "surfix-" + crypto.randomBytes(24).toString("hex");
  db.prepare("UPDATE users SET api_key=? WHERE id=?").run(newKey, req.user.id);
  res.json({ api_key: newKey });
});

router.get("/stats", auth, (req, res) => {
  res.json({
    projects: db.prepare("SELECT COUNT(*) as c FROM projects").get().c,
    keys: db.prepare("SELECT COUNT(*) as c FROM licenses").get().c,
    active_keys: db.prepare("SELECT COUNT(*) as c FROM licenses WHERE paused=0").get().c,
    auths_today: db.prepare("SELECT COUNT(*) as c FROM auth_logs WHERE ts>unixepoch()-86400").get().c,
    auths_ok: db.prepare("SELECT COUNT(*) as c FROM auth_logs WHERE status='ok' AND ts>unixepoch()-86400").get().c,
    auths_fail: db.prepare("SELECT COUNT(*) as c FROM auth_logs WHERE status='fail' AND ts>unixepoch()-86400").get().c,
    active_sessions: db.prepare("SELECT COUNT(*) as c FROM active_sessions WHERE last_ping>unixepoch()-120").get().c,
  });
});

router.get("/projects", auth, (req, res) => {
  res.json(db.prepare(`
    SELECT p.*,
      (SELECT COUNT(*) FROM licenses l WHERE l.project_id=p.id) as key_count,
      (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id=p.id) as total_auths
    FROM projects p ORDER BY p.created_at DESC
  `).all());
});

router.get("/projects/:id", auth, (req, res) => {
  const p = db.prepare("SELECT * FROM projects WHERE id=?").get(req.params.id);
  if (!p) return res.status(404).json({ error: "Not found" });
  res.json(p);
});

router.post("/projects", auth, (req, res) => {
  const { name, description, script, version, protection_level, lightning, silent, ffa, heartbeat, source_locker } = req.body;
  if (!name || !script) return res.status(400).json({ error: "name and script required" });

  const id = uuidv4();
  let finalScript = script;
  let seedToReturn = null;

  if (source_locker) {
    const { stored, seed } = lockerEncrypt(script);
    finalScript = stored;
    seedToReturn = seed;
  }

  db.prepare(`INSERT INTO projects
    (id,user_id,name,description,script,version,script_version,protection_level,lightning,silent,ffa,heartbeat,source_locker)
    VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?)`)
    .run(id, req.user.id, name, description || "", finalScript, version || "1.0.0",
      protection_level || "max", lightning ? 1 : 0, silent ? 1 : 0, ffa ? 1 : 0, heartbeat || 0, source_locker ? 1 : 0);

  const proj = db.prepare("SELECT * FROM projects WHERE id=?").get(id);
  if (seedToReturn) proj.locker_seed = seedToReturn;
  res.json(proj);
});

router.put("/projects/:id", auth, (req, res) => {
  const { name, description, script, version, protection_level, lightning, silent, ffa, heartbeat, verified, locker_seed } = req.body;
  const p = db.prepare("SELECT * FROM projects WHERE id=?").get(req.params.id);
  if (!p) return res.status(404).json({ error: "Not found" });

  let finalScript = script || null;
  let versionBumped = false;

  if (script && p.source_locker && locker_seed) {
    try {
      const { stored } = lockerEncrypt(script);
      finalScript = stored;
      versionBumped = true;
    } catch {
      return res.status(400).json({ error: "Invalid locker seed or corrupted data" });
    }
  } else if (script && p.source_locker && !locker_seed) {
    return res.status(400).json({ error: "This project uses Source Locker. Provide locker_seed to update the script." });
  } else if (script && !p.source_locker) {
    finalScript = script;
    versionBumped = true;
  }

  const versionBumpSQL = versionBumped ? "script_version=script_version+1," : "";

  db.prepare(`UPDATE projects SET
    name=COALESCE(?,name), description=COALESCE(?,description),
    script=COALESCE(?,script), version=COALESCE(?,version),
    ${versionBumpSQL}
    protection_level=COALESCE(?,protection_level),
    lightning=COALESCE(?,lightning), silent=COALESCE(?,silent),
    ffa=COALESCE(?,ffa), heartbeat=COALESCE(?,heartbeat),
    verified=COALESCE(?,verified), updated_at=unixepoch()
    WHERE id=?`).run(
    name || null, description || null, finalScript, version || null, protection_level || null,
    lightning !== undefined ? (lightning ? 1 : 0) : null,
    silent !== undefined ? (silent ? 1 : 0) : null,
    ffa !== undefined ? (ffa ? 1 : 0) : null,
    heartbeat !== undefined ? heartbeat : null,
    verified !== undefined ? (verified ? 1 : 0) : null,
    req.params.id);

  const updated = db.prepare("SELECT * FROM projects WHERE id=?").get(req.params.id);
  if (versionBumped) bustCache(req.params.id, updated.script_version);
  res.json(updated);
});

router.delete("/projects/:id", auth, (req, res) => {
  const project = db.prepare("SELECT script_version FROM projects WHERE id=?").get(req.params.id);
  if (project) bustCache(req.params.id, project.script_version);
  db.prepare("DELETE FROM projects WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

router.get("/projects/:id/keys", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM licenses WHERE project_id=? ORDER BY created_at DESC").all(req.params.id));
});

router.post("/projects/:id/keys", auth, (req, res) => {
  const proj = db.prepare("SELECT id FROM projects WHERE id=?").get(req.params.id);
  if (!proj) return res.status(404).json({ error: "Project not found" });
  const { note, expires_in_days, max_activations, count = 1, key_days, auth_expire, discord_id } = req.body;
  const expires_at = expires_in_days ? Math.floor(Date.now() / 1000) + expires_in_days * 86400 : null;
  const auth_expire_ts = auth_expire ? Math.floor(Date.now() / 1000) + auth_expire * 86400 : null;
  const generated = [];
  const ins = db.prepare(`INSERT INTO licenses
    (id,project_id,key_value,max_activations,expires_at,note,key_days,auth_expire,discord_id)
    VALUES(?,?,?,?,?,?,?,?,?)`);
  db.transaction(() => {
    for (let i = 0; i < Math.min(count, 500); i++) {
      const id = uuidv4();
      const key = genKey();
      ins.run(id, req.params.id, key, max_activations || null, expires_at, note || "", key_days || null, auth_expire_ts, discord_id || null);
      generated.push({ id, key, expires_at, auth_expire: auth_expire_ts });
    }
  })();
  res.json(generated);
});

router.delete("/keys/:id", auth, (req, res) => {
  db.prepare("DELETE FROM licenses WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

router.patch("/keys/:id/pause", auth, (req, res) => {
  const k = db.prepare("SELECT paused FROM licenses WHERE id=?").get(req.params.id);
  if (!k) return res.status(404).json({ error: "Not found" });
  db.prepare("UPDATE licenses SET paused=? WHERE id=?").run(k.paused ? 0 : 1, req.params.id);
  res.json({ success: true, paused: !k.paused });
});

router.patch("/keys/:id/reset-hwid", auth, (req, res) => {
  db.prepare("UPDATE licenses SET hwid=NULL WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

router.patch("/keys/:id/reset-discord", auth, (req, res) => {
  db.prepare("UPDATE licenses SET discord_id=NULL WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

router.get("/logs", auth, (req, res) => {
  const { project_id, status, limit = 200 } = req.query;
  let q = "SELECT * FROM auth_logs WHERE 1=1";
  const p = [];
  if (project_id) { q += " AND project_id=?"; p.push(project_id); }
  if (status) { q += " AND status=?"; p.push(status); }
  q += " ORDER BY ts DESC LIMIT ?";
  p.push(Number(limit));
  res.json(db.prepare(q).all(...p));
});

router.get("/sessions", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM active_sessions WHERE last_ping>unixepoch()-120").all());
});

router.get("/verify-queue", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM projects WHERE verified=0 ORDER BY created_at DESC").all());
});

router.post("/verify/:id", auth, (req, res) => {
  const { approved } = req.body;
  if (approved) db.prepare("UPDATE projects SET verified=1 WHERE id=?").run(req.params.id);
  else db.prepare("DELETE FROM projects WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
