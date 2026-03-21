const router = require("express").Router();
const db = require("../database");
const { getObfuscated } = require("../obf_cache");
const { v4: uuidv4 } = require("uuid");

function clientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function log(licenseId, projectId, hwid, ip, platform, status, reason) {
  db.prepare("INSERT INTO auth_logs(license_id,project_id,hwid,ip,platform,status,reason) VALUES(?,?,?,?,?,?,?)")
    .run(licenseId || null, projectId, hwid || null, ip || null, platform || "unknown", status, reason || null);
}

router.post("/auth", (req, res) => {
  const { key, project, hwid, platform } = req.body || {};
  const ip = clientIp(req);

  if (!project) return res.status(400).json({ error: "Missing project ID" });

  const proj = db.prepare("SELECT * FROM projects WHERE id=?").get(project);
  if (!proj) return res.status(404).json({ error: "Project not found" });

  if (proj.ffa) {
    const code = getObfuscated(proj.id, proj.script_version || 1, proj.script, {
      level: proj.protection_level,
      lightning: proj.lightning,
      silent: proj.silent
    });
    log(null, project, hwid, ip, platform, "ok", "ffa");
    return res.json({ success: true, script: code, version: proj.version });
  }

  if (!key || !hwid) return res.status(400).json({ error: "Missing key or hwid" });

  const license = db.prepare(`
    SELECT l.*, p.script, p.version, p.script_version, p.protection_level, p.lightning, p.silent, p.heartbeat
    FROM licenses l JOIN projects p ON l.project_id = p.id
    WHERE l.key_value = ? AND l.project_id = ?
  `).get(key, project);

  if (!license) {
    log(null, project, hwid, ip, platform, "fail", "invalid_key");
    return res.status(403).json({ error: "Invalid license key" });
  }

  if (license.paused) {
    log(license.id, project, hwid, ip, platform, "fail", "key_paused");
    return res.status(403).json({ error: "This license key has been paused" });
  }

  const now = Math.floor(Date.now() / 1000);

  if (license.expires_at && now > license.expires_at) {
    log(license.id, project, hwid, ip, platform, "fail", "key_expired");
    return res.status(403).json({ error: "License key has expired" });
  }

  if (license.auth_expire && now > license.auth_expire) {
    log(license.id, project, hwid, ip, platform, "fail", "auth_expired");
    return res.status(403).json({ error: "Auth period has expired" });
  }

  if (license.max_activations !== null && license.activations >= license.max_activations) {
    log(license.id, project, hwid, ip, platform, "fail", "max_activations");
    return res.status(403).json({ error: "Maximum activations reached" });
  }

  if (!license.hwid) {
    db.prepare("UPDATE licenses SET hwid=?, activations=activations+1, last_used=? WHERE id=?")
      .run(hwid, now, license.id);
  } else if (license.hwid !== hwid) {
    log(license.id, project, hwid, ip, platform, "fail", "hwid_mismatch");
    return res.status(403).json({ error: "HWID mismatch — contact support to reset your key" });
  } else {
    db.prepare("UPDATE licenses SET activations=activations+1, last_used=? WHERE id=?").run(now, license.id);
  }

  log(license.id, project, hwid, ip, platform, "ok", null);

  const code = getObfuscated(proj.id, license.script_version || 1, license.script, {
    level: license.protection_level,
    lightning: license.lightning,
    silent: license.silent
  });

  const sessionId = uuidv4();
  db.prepare("INSERT INTO active_sessions(id,license_id,session_id,ip) VALUES(?,?,?,?)")
    .run(uuidv4(), license.id, sessionId, ip);

  res.json({ success: true, script: code, version: license.version, session_id: sessionId });
});

module.exports = router;
