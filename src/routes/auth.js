const router = require("express").Router();
const db = require("../database");
const { getObfuscated } = require("../obf_cache");
const { v4: uuidv4 } = require("uuid");

function clientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

async function log(licenseId, projectId, hwid, ip, platform, status, reason) {
  await db.run(
    "INSERT INTO auth_logs(license_id, project_id, hwid, ip, platform, status, reason) VALUES(?,?,?,?,?,?,?)",
    [licenseId || null, projectId, hwid || null, ip || null, platform || "unknown", status, reason || null]
  );
}

router.post("/auth", async (req, res) => {
  const { key, project, hwid, platform } = req.body || {};
  const ip = clientIp(req);

  if (!project) return res.status(400).json({ error: "Missing project ID" });

  try {
    const proj = await db.get("SELECT * FROM projects WHERE id = ?", [project]);
    if (!proj) return res.status(404).json({ error: "Project not found" });

    if (proj.ffa) {
      let scriptToSend;
      if (proj.obfuscate) {
        const code = getObfuscated(proj.id, proj.script_version || 1, proj.script, {
          level: proj.protection_level,
          lightning: proj.lightning,
          silent: proj.silent
        });
        scriptToSend = code;
      } else {
        scriptToSend = proj.script;
      }
      await log(null, project, hwid, ip, platform, "ok", "ffa");
      return res.json({ success: true, script: scriptToSend, version: proj.version });
    }

    if (!key || !hwid) return res.status(400).json({ error: "Missing key or hwid" });

    const license = await db.get(`
      SELECT l.*, p.script, p.version, p.script_version, p.protection_level, p.lightning, p.silent, p.heartbeat, p.obfuscate
      FROM licenses l JOIN projects p ON l.project_id = p.id
      WHERE l.key_value = ? AND l.project_id = ?
    `, [key, project]);

    if (!license) {
      await log(null, project, hwid, ip, platform, "fail", "invalid_key");
      return res.status(403).json({ error: "Invalid license key" });
    }

    if (license.paused) {
      await log(license.id, project, hwid, ip, platform, "fail", "key_paused");
      return res.status(403).json({ error: "This license key has been paused" });
    }

    const now = Math.floor(Date.now() / 1000);

    if (license.expires_at && now > license.expires_at) {
      await log(license.id, project, hwid, ip, platform, "fail", "key_expired");
      return res.status(403).json({ error: "License key has expired" });
    }

    if (license.auth_expire && now > license.auth_expire) {
      await log(license.id, project, hwid, ip, platform, "fail", "auth_expired");
      return res.status(403).json({ error: "Auth period has expired" });
    }

    if (license.max_activations !== null && license.activations >= license.max_activations) {
      await log(license.id, project, hwid, ip, platform, "fail", "max_activations");
      return res.status(403).json({ error: "Maximum activations reached" });
    }

    if (!license.hwid) {
      await db.run("UPDATE licenses SET hwid = ?, activations = activations + 1, last_used = ? WHERE id = ?",
        [hwid, now, license.id]);
    } else if (license.hwid !== hwid) {
      await log(license.id, project, hwid, ip, platform, "fail", "hwid_mismatch");
      return res.status(403).json({ error: "HWID mismatch — contact support to reset your key" });
    } else {
      await db.run("UPDATE licenses SET activations = activations + 1, last_used = ? WHERE id = ?", [now, license.id]);
    }

    await log(license.id, project, hwid, ip, platform, "ok", null);

    let scriptToSend;
    if (license.obfuscate) {
      const code = getObfuscated(proj.id, license.script_version || 1, license.script, {
        level: license.protection_level,
        lightning: license.lightning,
        silent: license.silent
      });
      scriptToSend = code;
    } else {
      scriptToSend = license.script;
    }

    const sessionId = uuidv4();
    await db.run("INSERT INTO active_sessions(id, license_id, session_id, ip) VALUES(?,?,?,?)",
      [uuidv4(), license.id, sessionId, ip]);

    res.json({ success: true, script: scriptToSend, version: license.version, session_id: sessionId });
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
