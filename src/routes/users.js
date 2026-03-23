var router = require("express").Router();
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
var uuidv4 = require("uuid").v4;
var db = require("../database");

var JWT_SECRET = process.env.JWT_SECRET;

var rateLimit = require("express-rate-limit");
var loginLimiter = rateLimit({
  windowMs: 60000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again in a minute." }
});

function requireAuth(req, res, next) {
  var h = req.headers.authorization || "";
  var t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "Not authenticated" });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Session expired, please log in again" });
  }
}

function issueToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role || "user", plan: user.plan || "free" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

router.post("/signup",
  function(req, res, next) { req.app.locals.limiters.signupLimiter(req, res, next); },
  async function(req, res) {
    var body = req.body || {};
    var username = body.username;
    var password = body.password;

    if (!username || username.length < 3 || username.length > 32 || !/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: "Username must be 3-32 alphanumeric characters or underscores" });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    try {
      var existing = await db.get("SELECT id FROM users WHERE username = ?", [username]);
      if (existing) {
        return res.status(409).json({ error: "Username already taken" });
      }

      var hash = await bcrypt.hash(password, 10);
      var id = uuidv4();

      await db.run(
        "INSERT INTO users (id, username, password, role, plan, verified) VALUES (?, ?, ?, 'user', 'free', 1)",
        [id, username, hash]
      );

      var user = await db.get("SELECT id, username, role, plan FROM users WHERE id = ?", [id]);
      var token = issueToken(user);

      res.status(201).json({
        success: true,
        token: token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          plan: user.plan
        }
      });
    } catch (err) {
      console.error("[SIGNUP]", err.message);
      res.status(500).json({ error: "Signup failed, please try again" });
    }
  }
);

router.post("/login",
  loginLimiter,
  async function(req, res) {
    var body = req.body || {};
    var username = body.username;
    var password = body.password;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    try {
      var user = await db.get(
        "SELECT id, username, password, role, plan FROM users WHERE username = ?",
        [username]
      );
      if (!user) return res.status(401).json({ error: "Invalid username or password" });

      var ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: "Invalid username or password" });

      await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [user.id]);

      var token = issueToken(user);
      res.json({
        token: token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          plan: user.plan
        }
      });
    } catch (err) {
      console.error("[LOGIN]", err.message);
      res.status(500).json({ error: "Login failed" });
    }
  }
);

router.get("/me", requireAuth, async function(req, res) {
  try {
    var user = await db.get(
      "SELECT id, username, role, plan, created_at, last_login FROM users WHERE id = ?",
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("[ME]", err.message);
    res.status(500).json({ error: "Failed to load profile" });
  }
});

router.get("/projects", requireAuth, async function(req, res) {
  try {
    var projects = await db.all(
      "SELECT p.id, p.name, p.description, p.version, p.protection_level, p.lightning, p.silent, p.ffa, p.heartbeat, p.obfuscate, p.source_locker, p.downloads, p.created_at, p.updated_at, (SELECT COUNT(*) FROM licenses l WHERE l.project_id = p.id) as key_count, (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths FROM projects p WHERE p.user_id = ? ORDER BY p.created_at DESC",
      [req.user.id]
    );
    res.json(projects);
  } catch (err) {
    console.error("[USER-PROJECTS]", err.message);
    res.status(500).json({ error: "Failed to load projects" });
  }
});

module.exports = router;
module.exports.requireAuth = requireAuth;
module.exports.issueToken = issueToken;
