const router = require("express").Router();
const db = require("../database");

router.post("/heartbeat", (req, res) => {
  const { key, project, session_id } = req.body || {};
  if (!key || !project || !session_id) return res.status(400).json({ error: "Missing fields" });

  const license = db.prepare("SELECT id FROM licenses WHERE key_value=? AND project_id=?").get(key, project);
  if (!license) return res.status(403).json({ error: "Invalid license" });

  const session = db.prepare("SELECT * FROM active_sessions WHERE license_id=? AND session_id=?").get(license.id, session_id);
  if (!session) return res.status(404).json({ error: "Session not found — re-authenticate" });

  db.prepare("UPDATE active_sessions SET last_ping=unixepoch() WHERE id=?").run(session.id);

  const proj = db.prepare("SELECT heartbeat FROM projects WHERE id=?").get(project);
  if (proj && proj.heartbeat > 0) {
    const active = db.prepare(
      "SELECT COUNT(*) as c FROM active_sessions WHERE license_id=? AND last_ping > unixepoch()-120"
    ).get(license.id).c;
    if (active > proj.heartbeat) {
      return res.json({ action: "kill", message: "Too many concurrent sessions" });
    }
  }

  db.prepare("DELETE FROM active_sessions WHERE last_ping < unixepoch()-180").run();

  res.json({ action: "continue" });
});

router.post("/heartbeat/end", (req, res) => {
  const { key, project, session_id } = req.body || {};
  if (!key || !project || !session_id) return res.status(400).json({ error: "Missing fields" });
  const license = db.prepare("SELECT id FROM licenses WHERE key_value=? AND project_id=?").get(key, project);
  if (!license) return res.status(403).json({ error: "Invalid license" });
  db.prepare("DELETE FROM active_sessions WHERE license_id=? AND session_id=?").run(license.id, session_id);
  res.json({ success: true });
});

module.exports = router;
