var router = require(“express”).Router();
var bcrypt = require(“bcryptjs”);
var jwt = require(“jsonwebtoken”);
var crypto = require(“crypto”);
var uuidv4 = require(“uuid”).v4;
var validator = require(“validator”);
var db = require(”../database”);
var mailer = require(”../mailer”);

var JWT_SECRET = process.env.JWT_SECRET;

// Login rate limiter - defined here because users.js needs its own limiter
// that is applied BEFORE the route handler runs
var rateLimit = require(“express-rate-limit”);
var loginLimiter = rateLimit({
windowMs: 60000,
max: 10,
standardHeaders: true,
legacyHeaders: false,
message: { error: “Too many login attempts. Try again in a minute.” }
});

// — Auth middleware —
function requireAuth(req, res, next) {
var h = req.headers.authorization || “”;
var t = h.startsWith(“Bearer “) ? h.slice(7) : null;
if (!t) return res.status(401).json({ error: “Not authenticated” });
try {
req.user = jwt.verify(t, JWT_SECRET);
next();
} catch (e) {
res.status(401).json({ error: “Session expired, please log in again” });
}
}

function issueToken(user) {
return jwt.sign(
{ id: user.id, email: user.email, role: user.role, plan: user.plan },
JWT_SECRET,
{ expiresIn: “7d” }
);
}

// — POST /api/user/signup —
router.post(”/signup”,
function(req, res, next) { req.app.locals.limiters.signupLimiter(req, res, next); },
async function(req, res) {
var body = req.body || {};
var email = body.email;
var password = body.password;
var username = body.username;

```
if (!email || !validator.isEmail(email)) {
  return res.status(400).json({ error: "Valid email is required" });
}
if (!password || password.length < 8) {
  return res.status(400).json({ error: "Password must be at least 8 characters" });
}
if (!username || username.length < 2 || username.length > 32 || !/^[a-zA-Z0-9_]+$/.test(username)) {
  return res.status(400).json({ error: "Username must be 2-32 alphanumeric characters or underscores" });
}

var normalizedEmail = email.toLowerCase().trim();

try {
  var exists = await db.get("SELECT id FROM users WHERE email = ? OR username = ?", [normalizedEmail, username]);
  if (exists) return res.status(409).json({ error: "Email or username already taken" });

  // FIX BUG-1: async bcrypt - never block the event loop
  var hash = await bcrypt.hash(password, 12);
  var id = uuidv4();
  var verifyToken = crypto.randomBytes(32).toString("hex");

  await db.run(
    "INSERT INTO users (id, username, email, password, verify_token, verified) VALUES (?, ?, ?, ?, ?, 0)",
    [id, username, normalizedEmail, hash, verifyToken]
  );

  mailer.sendVerificationEmail(normalizedEmail, username, verifyToken).catch(function(err) {
    console.error("[MAILER] Failed to send verification email:", err.message);
  });

  res.status(201).json({
    success: true,
    message: "Account created! Check your email to verify before logging in."
  });
} catch (err) {
  if (err.message.includes("UNIQUE")) {
    return res.status(409).json({ error: "Email or username already taken" });
  }
  console.error("[SIGNUP]", err.message);
  res.status(500).json({ error: "Signup failed, please try again" });
}
```

}
);

// — POST /api/user/login —
router.post(”/login”,
loginLimiter,
async function(req, res) {
var body = req.body || {};
var email = body.email;
var password = body.password;
if (!email || !password) return res.status(400).json({ error: “Email and password required” });

```
try {
  var user = await db.get(
    "SELECT id, username, email, password, role, plan, avatar_url, verified FROM users WHERE email = ?",
    [email.toLowerCase().trim()]
  );
  if (!user) return res.status(401).json({ error: "Invalid email or password" });
  if (!user.password) return res.status(401).json({ error: "This account uses social login. Use the Google or GitHub buttons." });
  if (!user.verified) return res.status(403).json({ error: "Please verify your email before logging in." });

  // FIX BUG-2: async bcrypt compare
  var ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });

  await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [user.id]);

  var token = issueToken(user);
  res.json({
    token: token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      plan: user.plan,
      avatar_url: user.avatar_url
    }
  });
} catch (err) {
  console.error("[LOGIN]", err.message);
  res.status(500).json({ error: "Login failed" });
}
```

}
);

// — GET /api/user/verify-email?token=… —
router.get(”/verify-email”, async function(req, res) {
var token = req.query.token;
if (!token || typeof token !== “string” || token.length > 128) {
return res.status(400).json({ error: “Invalid token” });
}
try {
var user = await db.get(“SELECT id FROM users WHERE verify_token = ?”, [token]);
if (!user) return res.status(400).json({ error: “Invalid or expired verification link” });
await db.run(“UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?”, [user.id]);
res.redirect(”/?verified=1”);
} catch (err) {
console.error(”[VERIFY]”, err.message);
res.status(500).json({ error: “Verification failed” });
}
});

// — POST /api/user/forgot-password —
router.post(”/forgot-password”,
function(req, res, next) { req.app.locals.limiters.forgotPwLimiter(req, res, next); },
async function(req, res) {
var email = (req.body || {}).email;
if (!email) return res.status(400).json({ error: “Email required” });

```
// Always respond immediately to prevent email enumeration
res.json({ success: true, message: "If that email exists, a reset link has been sent." });

try {
  var user = await db.get(
    "SELECT id, email, username, password FROM users WHERE email = ?",
    [email.toLowerCase().trim()]
  );
  if (!user || !user.password) return;

  var resetToken = crypto.randomBytes(32).toString("hex");
  var resetExpires = Math.floor(Date.now() / 1000) + 3600;

  await db.run("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?", [resetToken, resetExpires, user.id]);
  mailer.sendPasswordResetEmail(user.email, user.username, resetToken).catch(function(err) {
    console.error("[MAILER] Reset email failed:", err.message);
  });
} catch (err) {
  console.error("[FORGOT-PW]", err.message);
}
```

}
);

// — POST /api/user/reset-password —
router.post(”/reset-password”, async function(req, res) {
var body = req.body || {};
var token = body.token;
var password = body.password;
if (!token || !password) return res.status(400).json({ error: “Token and new password required” });
if (typeof token !== “string” || token.length > 128) return res.status(400).json({ error: “Invalid token” });
if (password.length < 8) return res.status(400).json({ error: “Password must be at least 8 characters” });

try {
var user = await db.get(
“SELECT id FROM users WHERE reset_token = ? AND reset_expires > strftime(’%s’,‘now’)”,
[token]
);
if (!user) return res.status(400).json({ error: “Invalid or expired reset link” });

```
// FIX BUG-3: async bcrypt
var hash = await bcrypt.hash(password, 12);
await db.run("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?", [hash, user.id]);
res.json({ success: true, message: "Password updated. You can now log in." });
```

} catch (err) {
console.error(”[RESET-PW]”, err.message);
res.status(500).json({ error: “Reset failed” });
}
});

// — GET /api/user/me —
router.get(”/me”, requireAuth, async function(req, res) {
try {
var user = await db.get(
“SELECT id, username, email, role, plan, avatar_url, created_at, last_login FROM users WHERE id = ?”,
[req.user.id]
);
if (!user) return res.status(404).json({ error: “User not found” });
var providers = await db.all(“SELECT provider FROM oauth_accounts WHERE user_id = ?”, [user.id]);
var result = Object.assign({}, user, { providers: providers.map(function(p) { return p.provider; }) });
res.json(result);
} catch (err) {
console.error(”[ME]”, err.message);
res.status(500).json({ error: “Failed to load profile” });
}
});

// — GET /api/user/projects —
router.get(”/projects”, requireAuth, async function(req, res) {
try {
var projects = await db.all(
“SELECT p.id, p.name, p.description, p.version, p.protection_level, p.lightning, p.silent, p.ffa, p.heartbeat, p.obfuscate, p.source_locker, p.downloads, p.created_at, p.updated_at, (SELECT COUNT(*) FROM licenses l WHERE l.project_id = p.id) as key_count, (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths FROM projects p WHERE p.user_id = ? ORDER BY p.created_at DESC”,
[req.user.id]
);
res.json(projects);
} catch (err) {
console.error(”[USER-PROJECTS]”, err.message);
res.status(500).json({ error: “Failed to load projects” });
}
});

module.exports = router;
module.exports.requireAuth = requireAuth;
module.exports.issueToken = issueToken;
