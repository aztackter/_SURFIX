const router = require(“express”).Router();
const db     = require(”../database”);

router.post(
“/heartbeat”,
(req, res, next) => req.app.locals.limiters.heartbeatLimiter(req, res, next),
async (req, res) => {
const { key, project, session_id } = req.body || {};
if (!key || !project || !session_id) {
return res.status(400).json({ error: “Missing fields” });
}

```
try {
  const license = await db.get(
    "SELECT id FROM licenses WHERE key_value = ? AND project_id = ?",
    [key, project]
  );
  if (!license) return res.status(403).json({ error: "Invalid license" });

  // FIXED SEC-15: verify session_id belongs to THIS license, not just any license
  const session = await db.get(
    "SELECT * FROM active_sessions WHERE license_id = ? AND session_id = ?",
    [license.id, session_id]
  );
  if (!session) return res.status(404).json({ error: "Session not found - re-authenticate" });

  await db.run(
    "UPDATE active_sessions SET last_ping = strftime('%s','now') WHERE id = ?",
    [session.id]
  );

  // Check concurrent session limit
  const proj = await db.get("SELECT heartbeat FROM projects WHERE id = ?", [project]);
  if (proj && proj.heartbeat > 0) {
    // FIXED BUG-12: Use the same 120s window for both count and cleanup
    const active = await db.get(
      "SELECT COUNT(*) as c FROM active_sessions WHERE license_id = ? AND last_ping > strftime('%s','now') - 120",
      [license.id]
    );
    if (active.c > proj.heartbeat) {
      return res.json({ action: "kill", message: "Too many concurrent sessions" });
    }
  }

  // FIXED BUG-11: Stale session cleanup uses indexed last_ping column
  // Runs less frequently (every ~10 heartbeats) to reduce DB load
  if (Math.random() < 0.1) {
    await db.run(
      "DELETE FROM active_sessions WHERE last_ping < strftime('%s','now') - 120"
    );
  }

  res.json({ action: "continue" });
} catch (err) {
  console.error("[HEARTBEAT]", err);
  res.status(500).json({ error: err.message });
}
```

}
);

router.post(”/heartbeat/end”, async (req, res) => {
const { key, project, session_id } = req.body || {};
if (!key || !project || !session_id) {
return res.status(400).json({ error: “Missing fields” });
}
try {
const license = await db.get(
“SELECT id FROM licenses WHERE key_value = ? AND project_id = ?”,
[key, project]
);
if (!license) return res.status(403).json({ error: “Invalid license” });
await db.run(
“DELETE FROM active_sessions WHERE license_id = ? AND session_id = ?”,
[license.id, session_id]
);
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

module.exports = router;
