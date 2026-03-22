const passport       = require(“passport”);
const GoogleStrategy = require(“passport-google-oauth20”).Strategy;
const GitHubStrategy = require(“passport-github2”).Strategy;
const { v4: uuidv4 } = require(“uuid”);
const db = require(”./database”);

const HOST = (process.env.PUBLIC_URL || “http://localhost:3000”).replace(//$/, “”);

// ─── Serialize / deserialize ──────────────────────────────────────────────────
// Only store user ID in session — never password or tokens
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
try {
const user = await db.get(
“SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE id = ?”,
[id]
);
done(null, user || false);
} catch (err) {
done(err);
}
});

// ─── Safe username deduplication ──────────────────────────────────────────────
async function safeUsername(base) {
const clean = (base || “user”).replace(/[^a-zA-Z0-9_]/g, “_”).slice(0, 28) || “user”;
let candidate = clean;
let suffix = 2;
while (true) {
const existing = await db.get(“SELECT id FROM users WHERE username = ?”, [candidate]);
if (!existing) return candidate;
candidate = `${clean}_${suffix++}`;
if (suffix > 999) return `user_${uuidv4().slice(0, 8)}`;
}
}

// ─── Find or create OAuth user ────────────────────────────────────────────────
// BUG FIX: this was crashing with “Internal server error” because:
//   1. The users table might not have all columns yet on first OAuth login
//   2. avatar_url from Google is sometimes an object, not a string
//   3. No null check on email before querying
async function findOrCreateOAuthUser(provider, profileId, profile) {
// 1. Already linked to this OAuth account?
const existing = await db.get(
`SELECT u.id, u.username, u.email, u.role, u.plan, u.avatar_url, u.verified FROM users u JOIN oauth_accounts o ON o.user_id = u.id WHERE o.provider = ? AND o.provider_id = ?`,
[provider, String(profileId)]
);
if (existing) {
await db.run(
“UPDATE users SET last_login = strftime(’%s’,‘now’) WHERE id = ?”,
[existing.id]
);
return existing;
}

// 2. Extract email safely — Google/GitHub both nest it differently
const rawEmail =
profile.emails?.[0]?.value ||
profile._json?.email ||
profile.email ||
null;
const email = rawEmail ? rawEmail.toLowerCase().trim() : null;

// 3. Extract avatar safely — can be object or string depending on provider
let avatar = null;
const rawAvatar = profile.photos?.[0]?.value || profile._json?.avatar_url || null;
if (rawAvatar && typeof rawAvatar === “string”) avatar = rawAvatar;

// 4. Same email already in DB? Link the new provider to that account.
let user = null;
if (email) {
user = await db.get(
“SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE email = ?”,
[email]
);
}

if (!user) {
// 5. Create brand-new user
const id = uuidv4();
const displayName =
profile.displayName ||
profile.username ||
profile._json?.login ||
(email ? email.split(”@”)[0] : “user”);
const username = await safeUsername(displayName);

```
await db.run(
  `INSERT INTO users (id, username, email, avatar_url, verified, role, plan)
   VALUES (?, ?, ?, ?, 1, 'user', 'free')`,
  [id, username, email || null, avatar]
);

user = await db.get(
  "SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE id = ?",
  [id]
);

if (!user) throw new Error("Failed to create user after OAuth insert");
```

}

// 6. Link the OAuth account
await db.run(
`INSERT OR IGNORE INTO oauth_accounts (id, user_id, provider, provider_id) VALUES (?, ?, ?, ?)`,
[uuidv4(), user.id, provider, String(profileId)]
);
await db.run(
“UPDATE users SET last_login = strftime(’%s’,‘now’), verified = 1 WHERE id = ?”,
[user.id]
);

return user;
}

// ─── Google strategy ──────────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
passport.use(
new GoogleStrategy(
{
clientID:     process.env.GOOGLE_CLIENT_ID,
clientSecret: process.env.GOOGLE_CLIENT_SECRET,
callbackURL:  `${HOST}/auth/google/callback`,
// Fetch the profile with email scope
scope: [“profile”, “email”],
},
async (_accessToken, _refreshToken, profile, done) => {
try {
const user = await findOrCreateOAuthUser(“google”, profile.id, profile);
done(null, user);
} catch (err) {
console.error(”[PASSPORT] Google error:”, err.message);
done(err);
}
}
)
);
console.log(”[SURFIX] Google OAuth ready”);
} else {
console.log(”[SURFIX] Google OAuth skipped — GOOGLE_CLIENT_ID/SECRET not set”);
}

// ─── GitHub strategy ──────────────────────────────────────────────────────────
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
passport.use(
new GitHubStrategy(
{
clientID:     process.env.GITHUB_CLIENT_ID,
clientSecret: process.env.GITHUB_CLIENT_SECRET,
callbackURL:  `${HOST}/auth/github/callback`,
scope:        [“user:email”],
},
async (_accessToken, _refreshToken, profile, done) => {
try {
const user = await findOrCreateOAuthUser(“github”, profile.id, profile);
done(null, user);
} catch (err) {
console.error(”[PASSPORT] GitHub error:”, err.message);
done(err);
}
}
)
);
console.log(”[SURFIX] GitHub OAuth ready”);
} else {
console.log(”[SURFIX] GitHub OAuth skipped — GITHUB_CLIENT_ID/SECRET not set”);
}

// Export the configured passport instance
module.exports = passport;
