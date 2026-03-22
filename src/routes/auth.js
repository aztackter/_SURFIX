const router = require(“express”).Router();
const db     = require(”../database”);
const { getObfuscated } = require(”../obf_cache”);
const { v4: uuidv4 }   = require(“uuid”);

const ALLOWED_PLATFORMS = new Set([“roblox”, “fivem”, “auto”, “unknown”, “other”]);

function clientIp(req) {
return (req.headers[“x-forwarded-for”] || req.socket.remoteAddress || “”)
.split(”,”)[0]
.trim()
.slice(0, 45); // FIXED SEC-13: cap length
}

// FIXED SEC-13: validate and sanitize the platform field
function sanitizePlatform(raw) {
const p = (raw || “unknown”).toString().toLowerCase().trim().slice(0, 20);
return ALLOWED_PLATFORMS.has(p) ? p : “unknown”;
}

async function logAuth(licenseId, projectId, hwid, ip, platform, status, reason) {
await db.run(
“INSERT INTO auth_logs(license_id, project_id, hwid, ip, platform, status, reason) VALUES(?,?,?,?,?,?,?)”,
[licenseId || null, projectId, hwid || null, ip || null, platform, status, reason || null]
);
}

router.post(
“/auth”,
// Apply rate limiter from app.locals (set in index.js)
(req, res, next) => req.app.locals.limiters.authLimiter(req, res, next),
async (req, res) => {
const { key, project, hwid, platform } = req.body || {};
const ip  = clientIp(req);
const plat = sanitizePlatform(platform);

```
if (!project) return res.status(400).json({ error: "Missing project ID" });

try {
  const proj = await db.get("SELECT * FROM projects WHERE id = ?", [project]);
  if (!proj) return res.status(404).json({ error: "Project not found" });

  // -- FFA path ----------------------------------------------------------
  if (proj.ffa) {
    const scriptToSend = proj.obfuscate
      ? getObfuscated(proj.id, proj.script_version || 1, proj.script, {
          level: proj.protection_level,
          lightning: !!proj.lightning,
          silent: !!proj.silent,
        })
      : proj.script;
    await logAuth(null, project, hwid, ip, plat, "ok", "ffa");
    return res.json({ success: true, script: scriptToSend, version: proj.version });
  }

  // -- Licensed path -----------------------------------------------------
  if (!key || !hwid) return res.status(400).json({ error: "Missing key or hwid" });

  // Sanitize HWID - accept only printable ASCII, cap length
  const safeHwid = String(hwid).replace(/[^\x20-\x7E]/g, "").slice(0, 128);
  if (!safeHwid) return res.status(400).json({ error: "Invalid HWID" });

  const license = await db.get(
    `SELECT l.*, p.script, p.version, p.script_version, p.protection_level,
            p.lightning, p.silent, p.heartbeat, p.obfuscate
     FROM licenses l JOIN projects p ON l.project_id = p.id
     WHERE l.key_value = ? AND l.project_id = ?`,
    [key, project]
  );

  if (!license) {
    await logAuth(null, project, safeHwid, ip, plat, "fail", "invalid_key");
    return res.status(403).json({ error: "Invalid license key" });
  }
  if (license.paused) {
    await logAuth(license.id, project, safeHwid, ip, plat, "fail", "key_paused");
    return res.status(403).json({ error: "This license key has been paused" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (license.expires_at && now > license.expires_at) {
    await logAuth(license.id, project, safeHwid, ip, plat, "fail", "key_expired");
    return res.status(403).json({ error: "License key has expired" });
  }
  if (license.auth_expire && now > license.auth_expire) {
    await logAuth(license.id, project, safeHwid, ip, plat, "fail", "auth_expired");
    return res.status(403).json({ error: "Auth period has expired" });
  }
  if (license.max_activations !== null && license.activations >= license.max_activations) {
    await logAuth(license.id, project, safeHwid, ip, plat, "fail", "max_activations");
    return res.status(403).json({ error: "Maximum activations reached" });
  }

  if (!license.hwid) {
    await db.run(
      "UPDATE licenses SET hwid = ?, activations = activations + 1, last_used = ? WHERE id = ?",
      [safeHwid, now, license.id]
    );
  } else if (license.hwid !== safeHwid) {
    await logAuth(license.id, project, safeHwid, ip, plat, "fail", "hwid_mismatch");
    return res.status(403).json({ error: "HWID mismatch - contact support to reset your key" });
  } else {
    await db.run(
      "UPDATE licenses SET activations = activations + 1, last_used = ? WHERE id = ?",
      [now, license.id]
    );
  }

  await logAuth(license.id, project, safeHwid, ip, plat, "ok", null);

  const scriptToSend = license.obfuscate
    ? getObfuscated(proj.id, license.script_version || 1, license.script, {
        level: license.protection_level,
        lightning: !!license.lightning,
        silent: !!license.silent,
      })
    : license.script;

  const sessionId = uuidv4();
  // Use INSERT OR IGNORE to avoid duplicate session errors (UNIQUE constraint)
  await db.run(
    "INSERT OR IGNORE INTO active_sessions(id, license_id, session_id, ip) VALUES(?,?,?,?)",
    [uuidv4(), license.id, sessionId, ip]
  );

  res.json({ success: true, script: scriptToSend, version: license.version, session_id: sessionId });
} catch (err) {
  console.error("[AUTH]", err);
  res.status(500).json({ error: "Authentication failed" });
}
```

}
);

module.exports = router;
