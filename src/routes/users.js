const router  = require(“express”).Router();
const bcrypt  = require(“bcryptjs”);
const jwt     = require(“jsonwebtoken”);
const crypto  = require(“crypto”);
const { v4: uuidv4 } = require(“uuid”);
const validator = require(“validator”);
const db      = require(”../database”);
const { sendVerificationEmail, sendPasswordResetEmail } = require(”../mailer”);

const JWT_SECRET = process.env.JWT_SECRET;

// — Auth middleware ———————————————————–
async function requireAuth(req, res, next) {
const h = req.headers.authorization || “”;
const t = h.startsWith(“Bearer “) ? h.slice(7) : req.session?.jwt;
if (!t) return res.status(401).json({ error: “Not authenticated” });
try {
req.user = jwt.verify(t, JWT_SECRET);
next();
} catch {
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

// — POST /api/user/signup ––––––––––––––––––––––––––
router.post(”/signup”, async (req, res) => {
const { email, password, username } = req.body || {};

if (!email || !validator.isEmail(email)) {
return res.status(400).json({ error: “Valid email is required” });
}
if (!password || password.length < 8) {
return res.status(400).json({ error: “Password must be at least 8 characters” });
}
if (!username || username.length < 2 || username.length > 32 || !/^[a-zA-Z0-9_]+$/.test(username)) {
return res.status(400).json({ error: “Username must be 2-32 alphanumeric characters or underscores” });
}

const normalizedEmail = email.toLowerCase().trim();

try {
const exists = await db.get(“SELECT id FROM users WHERE email = ? OR username = ?”, [normalizedEmail, username]);
if (exists) return res.status(409).json({ error: “Email or username already taken” });

```
const hash = bcrypt.hashSync(password, 12);
const id = uuidv4();
const verifyToken = crypto.randomBytes(32).toString("hex");

await db.run(
  `INSERT INTO users (id, username, email, password, verify_token, verified)
   VALUES (?, ?, ?, ?, ?, 0)`,
  [id, username, normalizedEmail, hash, verifyToken]
);

// Send verification email (non-blocking - don't fail signup if email fails)
sendVerificationEmail(normalizedEmail, username, verifyToken).catch((err) => {
  console.error("[MAILER] Failed to send verification email:", err.message);
});

res.status(201).json({
  success: true,
  message: "Account created! Check your email to verify before logging in.",
});
```

} catch (err) {
if (err.message.includes(“UNIQUE”)) {
return res.status(409).json({ error: “Email or username already taken” });
}
console.error(”[SIGNUP]”, err);
res.status(500).json({ error: “Signup failed, please try again” });
}
});

// — POST /api/user/login —————————————————–
router.post(”/login”, async (req, res) => {
const { email, password } = req.body || {};
if (!email || !password) return res.status(400).json({ error: “Email and password required” });

try {
const user = await db.get(“SELECT * FROM users WHERE email = ?”, [email.toLowerCase().trim()]);
if (!user) return res.status(401).json({ error: “Invalid email or password” });
if (!user.password) return res.status(401).json({ error: “This account uses social login. Use the Google or GitHub buttons.” });
if (!user.verified) return res.status(403).json({ error: “Please verify your email before logging in.” });
if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: “Invalid email or password” });

```
await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [user.id]);

const token = issueToken(user);
res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, plan: user.plan, avatar_url: user.avatar_url } });
```

} catch (err) {
console.error(”[LOGIN]”, err);
res.status(500).json({ error: “Login failed” });
}
});

// — GET /api/user/verify-email?token=… ————————————
router.get(”/verify-email”, async (req, res) => {
const { token } = req.query;
if (!token) return res.status(400).json({ error: “Missing token” });

try {
const user = await db.get(“SELECT id FROM users WHERE verify_token = ?”, [token]);
if (!user) return res.status(400).json({ error: “Invalid or expired verification link” });

```
await db.run("UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?", [user.id]);
res.redirect("/?verified=1");
```

} catch (err) {
res.status(500).json({ error: “Verification failed” });
}
});

// — POST /api/user/forgot-password ——————————————
router.post(”/forgot-password”, async (req, res) => {
const { email } = req.body || {};
if (!email) return res.status(400).json({ error: “Email required” });

// Always return success to prevent email enumeration
res.json({ success: true, message: “If that email exists, a reset link has been sent.” });

try {
const user = await db.get(“SELECT * FROM users WHERE email = ?”, [email.toLowerCase().trim()]);
if (!user || !user.password) return; // OAuth accounts can’t reset password

```
const resetToken = crypto.randomBytes(32).toString("hex");
const resetExpires = Math.floor(Date.now() / 1000) + 3600; // 1 hour

await db.run("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?", [resetToken, resetExpires, user.id]);
sendPasswordResetEmail(user.email, user.username, resetToken).catch((err) => {
  console.error("[MAILER] Reset email failed:", err.message);
});
```

} catch (err) {
console.error(”[FORGOT-PW]”, err);
}
});

// — POST /api/user/reset-password —————————————––
router.post(”/reset-password”, async (req, res) => {
const { token, password } = req.body || {};
if (!token || !password) return res.status(400).json({ error: “Token and new password required” });
if (password.length < 8) return res.status(400).json({ error: “Password must be at least 8 characters” });

try {
const user = await db.get(
“SELECT id FROM users WHERE reset_token = ? AND reset_expires > strftime(’%s’,‘now’)”,
[token]
);
if (!user) return res.status(400).json({ error: “Invalid or expired reset link” });

```
const hash = bcrypt.hashSync(password, 12);
await db.run("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?", [hash, user.id]);
res.json({ success: true, message: "Password updated. You can now log in." });
```

} catch (err) {
console.error(”[RESET-PW]”, err);
res.status(500).json({ error: “Reset failed” });
}
});

// — GET /api/user/me ———————————————————
router.get(”/me”, requireAuth, async (req, res) => {
try {
const user = await db.get(
“SELECT id, username, email, role, plan, avatar_url, created_at, last_login FROM users WHERE id = ?”,
[req.user.id]
);
if (!user) return res.status(404).json({ error: “User not found” });

```
// Fetch linked OAuth providers
const providers = await db.all("SELECT provider FROM oauth_accounts WHERE user_id = ?", [user.id]);
res.json({ ...user, providers: providers.map((p) => p.provider) });
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// — GET /api/user/projects —————————————————
router.get(”/projects”, requireAuth, async (req, res) => {
try {
const projects = await db.all(
`SELECT p.*, (SELECT COUNT(*) FROM licenses l WHERE l.project_id = p.id) as key_count, (SELECT COUNT(*) FROM auth_logs a WHERE a.project_id = p.id) as total_auths FROM projects p WHERE p.user_id = ? ORDER BY p.created_at DESC`,
[req.user.id]
);
res.json(projects);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

module.exports = router;
module.exports.requireAuth = requireAuth;
module.exports.issueToken = issueToken;
