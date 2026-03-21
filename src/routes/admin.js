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

async function auth(req, res, next) {
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

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const user = await db.get("SELECT * FROM users WHERE username = ?", [username || "admin"]);
    if (!user || !bcrypt.compareSync(password || "", user.password))
      return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "24h" });
    res.json({ token, api_key: user.api_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/rotate-api-key", auth, async (req, res) => {
  try {
    const newKey = "surfix-" + crypto.randomBytes(24).toString("hex");
    await db.run("UPDATE users SET api_key = ? WHERE id = ?", [newKey, req.user.id]);
    res.json({ api_key: newKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/stats", auth, async (req, res) => {
  try {
    const projects = await db.get("SELECT COUNT(*) as c FROM projects");
    const keys = await db.get("SELECT COUNT(*) as c FROM licenses");
    const active_keys = await db.get("SELECT COUNT(*) as c FROM licenses WHERE paused = 0");
    const auths_today = await db.get("SELECT COUNT(*) as c FROM auth_logs WHERE ts > strftime('%s', 'now') - 86400");
    const auths_ok = await db.get("SELECT COUNT(*) as c FROM auth_logs WHERE status = 'ok' AND ts > strftime('%s', 'now') - 86400");
    const auths_fail = await db.get("SELECT COUNT(*) as c FROM auth_logs WHERE status = 'fail' AND ts > strftime('%s', 'now') - 86400");
    const active_sessions = await db.get("SELECT COUNT(*) as c FROM active_sessions WHERE last_ping > strftime('%s', 'now') - 120");
    
    res.json({
      projects: projects.c,
      keys: keys.c,
      active_keys: active_keys.c,
      auths_today: auths_today.c,
      auths_ok: auths_ok.c,
      auths_fail: auths_fail.c,
      active_sessions: active_sessions.c
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/projects", auth, async (req, res) => {
  try {
    const projects = await db.all(`
      SELECT p.*,
        (SELECT COUNT(*) FROM licenses l WHERE l.project_id = p.id) as key_count,
        (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths
      FROM projects p ORDER BY p.created_at DESC
    `);
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/projects/:id", auth, async (req, res) => {
  try {
    const p = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
    if (!p) return res.status(404).json({ error: "Not found" });
    res.json(p);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/projects", auth, async (req, res) => {
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

  try {
    await db.run(`INSERT INTO projects
      (id, user_id, name, description, script, version, script_version, protection_level, lightning, silent, ffa, heartbeat, source_locker)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
      [id, req.user.id, name, description || "", finalScript, version || "1.0.0",
        protection_level || "max", lightning ? 1 : 0, silent ? 1 : 0, ffa ? 1 : 0, heartbeat || 0, source_locker ? 1 : 0]);

    const proj = await db.get("SELECT * FROM projects WHERE id = ?", [id]);
    if (seedToReturn) proj.locker_seed = seedToReturn;
    res.json(proj);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put("/projects/:id", auth, async (req, res) => {
  const { name, description, script, version, protection_level, lightning, silent, ffa, heartbeat, verified, locker_seed } = req.body;
  
  try {
    const p = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
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

    const updates = [];
    const values = [];

    if (name !== undefined) { updates.push("name = ?"); values.push(name); }
    if (description !== undefined) { updates.push("description = ?"); values.push(description); }
    if (finalScript !== null) { updates.push("script = ?"); values.push(finalScript); }
    if (version !== undefined) { updates.push("version = ?"); values.push(version); }
    if (protection_level !== undefined) { updates.push("protection_level = ?"); values.push(protection_level); }
    if (lightning !== undefined) { updates.push("lightning = ?"); values.push(lightning ? 1 : 0); }
    if (silent !== undefined) { updates.push("silent = ?"); values.push(silent ? 1 : 0); }
    if (ffa !== undefined) { updates.push("ffa = ?"); values.push(ffa ? 1 : 0); }
    if (heartbeat !== undefined) { updates.push("heartbeat = ?"); values.push(heartbeat); }
    if (verified !== undefined) { updates.push("verified = ?"); values.push(verified ? 1 : 0); }
    if (versionBumped) { updates.push("script_version = script_version + 1"); }
    updates.push("updated_at = strftime('%s', 'now')");
    values.push(req.params.id);

    if (updates.length > 0) {
      await db.run(`UPDATE projects SET ${updates.join(", ")} WHERE id = ?`, values);
    }

    const updated = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
    if (versionBumped) bustCache(req.params.id, updated.script_version);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/projects/:id", auth, async (req, res) => {
  try {
    const project = await db.get("SELECT script_version FROM projects WHERE id = ?", [req.params.id]);
    if (project) bustCache(req.params.id, project.script_version);
    await db.run("DELETE FROM projects WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/projects/:id/keys", auth, async (req, res) => {
  try {
    const keys = await db.all("SELECT * FROM licenses WHERE project_id = ? ORDER BY created_at DESC", [req.params.id]);
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/projects/:id/keys", auth, async (req, res) => {
  try {
    const proj = await db.get("SELECT id FROM projects WHERE id = ?", [req.params.id]);
    if (!proj) return res.status(404).json({ error: "Project not found" });
    
    const { note, expires_in_days, max_activations, count = 1, key_days, auth_expire, discord_id } = req.body;
    const expires_at = expires_in_days ? Math.floor(Date.now() / 1000) + expires_in_days * 86400 : null;
    const auth_expire_ts = auth_expire ? Math.floor(Date.now() / 1000) + auth_expire * 86400 : null;
    const generated = [];
    
    for (let i = 0; i < Math.min(count, 500); i++) {
      const id = uuidv4();
      const key = genKey();
      await db.run(`INSERT INTO licenses
        (id, project_id, key_value, max_activations, expires_at, note, key_days, auth_expire, discord_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, req.params.id, key, max_activations || null, expires_at, note || "", key_days || null, auth_expire_ts, discord_id || null]);
      generated.push({ id, key, expires_at, auth_expire: auth_expire_ts });
    }
    res.json(generated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/keys/:id", auth, async (req, res) => {
  try {
    await db.run("DELETE FROM licenses WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch("/keys/:id/pause", auth, async (req, res) => {
  try {
    const k = await db.get("SELECT paused FROM licenses WHERE id = ?", [req.params.id]);
    if (!k) return res.status(404).json({ error: "Not found" });
    await db.run("UPDATE licenses SET paused = ? WHERE id = ?", [k.paused ? 0 : 1, req.params.id]);
    res.json({ success: true, paused: !k.paused });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch("/keys/:id/reset-hwid", auth, async (req, res) => {
  try {
    await db.run("UPDATE licenses SET hwid = NULL WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch("/keys/:id/reset-discord", auth, async (req, res) => {
  try {
    await db.run("UPDATE licenses SET discord_id = NULL WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/logs", auth, async (req, res) => {
  const { project_id, status, limit = 200 } = req.query;
  let sql = "SELECT * FROM auth_logs WHERE 1=1";
  const params = [];
  if (project_id) { sql += " AND project_id = ?"; params.push(project_id); }
  if (status) { sql += " AND status = ?"; params.push(status); }
  sql += " ORDER BY ts DESC LIMIT ?";
  params.push(Number(limit));
  
  try {
    const logs = await db.all(sql, params);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/sessions", auth, async (req, res) => {
  try {
    const sessions = await db.all("SELECT * FROM active_sessions WHERE last_ping > strftime('%s', 'now') - 120");
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/verify-queue", auth, async (req, res) => {
  try {
    const projects = await db.all("SELECT * FROM projects WHERE verified = 0 ORDER BY created_at DESC");
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/verify/:id", auth, async (req, res) => {
  const { approved } = req.body;
  try {
    if (approved) {
      await db.run("UPDATE projects SET verified = 1 WHERE id = ?", [req.params.id]);
    } else {
      await db.run("DELETE FROM projects WHERE id = ?", [req.params.id]);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
