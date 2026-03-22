const passport = require(“passport”);
const GoogleStrategy = require(“passport-google-oauth20”).Strategy;
const GitHubStrategy = require(“passport-github2”).Strategy;
const { v4: uuidv4 } = require(“uuid”);
const db = require(”./database”);

const HOST = (process.env.PUBLIC_URL || “http://localhost:3000”).replace(//$/, “”);

const GOOGLE_CALLBACK = HOST + “/auth/google/callback”;
const GITHUB_CALLBACK = HOST + “/auth/github/callback”;

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

async function safeUsername(base) {
const clean = (base || “user”).replace(/[^a-zA-Z0-9_]/g, “*”).slice(0, 28) || “user”;
let candidate = clean;
let suffix = 2;
while (true) {
const existing = await db.get(“SELECT id FROM users WHERE username = ?”, [candidate]);
if (!existing) return candidate;
candidate = clean + “*” + suffix++;
if (suffix > 999) return “user_” + uuidv4().slice(0, 8);
}
}

async function findOrCreateOAuthUser(provider, profileId, profile) {
const existing = await db.get(
“SELECT u.id, u.username, u.email, u.role, u.plan, u.avatar_url, u.verified “ +
“FROM users u JOIN oauth_accounts o ON o.user_id = u.id “ +
“WHERE o.provider = ? AND o.provider_id = ?”,
[provider, String(profileId)]
);
if (existing) {
await db.run(“UPDATE users SET last_login = strftime(’%s’,‘now’) WHERE id = ?”, [existing.id]);
return existing;
}

const rawEmail =
(profile.emails && profile.emails[0] && profile.emails[0].value) ||
(profile._json && profile._json.email) ||
null;
const email = rawEmail ? rawEmail.toLowerCase().trim() : null;

const rawAvatar =
(profile.photos && profile.photos[0] && profile.photos[0].value) ||
(profile._json && profile._json.avatar_url) ||
null;
const avatar = rawAvatar && typeof rawAvatar === “string” ? rawAvatar : null;

let user = null;
if (email) {
user = await db.get(
“SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE email = ?”,
[email]
);
}

if (!user) {
const id = uuidv4();
const displayName =
profile.displayName ||
profile.username ||
(profile._json && profile._json.login) ||
(email ? email.split(”@”)[0] : “user”);
const username = await safeUsername(displayName);

```
await db.run(
  "INSERT INTO users (id, username, email, avatar_url, verified, role, plan) VALUES (?, ?, ?, ?, 1, 'user', 'free')",
  [id, username, email || null, avatar]
);

user = await db.get(
  "SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE id = ?",
  [id]
);

if (!user) throw new Error("Failed to create user after OAuth insert");
```

}

await db.run(
“INSERT OR IGNORE INTO oauth_accounts (id, user_id, provider, provider_id) VALUES (?, ?, ?, ?)”,
[uuidv4(), user.id, provider, String(profileId)]
);
await db.run(
“UPDATE users SET last_login = strftime(’%s’,‘now’), verified = 1 WHERE id = ?”,
[user.id]
);

return user;
}

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
console.log(”[SURFIX] Google OAuth callback URL:”, GOOGLE_CALLBACK);
passport.use(new GoogleStrategy(
{
clientID: process.env.GOOGLE_CLIENT_ID,
clientSecret: process.env.GOOGLE_CLIENT_SECRET,
callbackURL: GOOGLE_CALLBACK,
scope: [“profile”, “email”],
},
async function(accessToken, refreshToken, profile, done) {
try {
const user = await findOrCreateOAuthUser(“google”, profile.id, profile);
done(null, user);
} catch (err) {
console.error(”[PASSPORT] Google error:”, err.message);
done(err);
}
}
));
console.log(”[SURFIX] Google OAuth ready”);
} else {
console.log(”[SURFIX] Google OAuth skipped - GOOGLE_CLIENT_ID/SECRET not set”);
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
console.log(”[SURFIX] GitHub OAuth callback URL:”, GITHUB_CALLBACK);
passport.use(new GitHubStrategy(
{
clientID: process.env.GITHUB_CLIENT_ID,
clientSecret: process.env.GITHUB_CLIENT_SECRET,
callbackURL: GITHUB_CALLBACK,
scope: [“user:email”],
},
async function(accessToken, refreshToken, profile, done) {
try {
const user = await findOrCreateOAuthUser(“github”, profile.id, profile);
done(null, user);
} catch (err) {
console.error(”[PASSPORT] GitHub error:”, err.message);
done(err);
}
}
));
console.log(”[SURFIX] GitHub OAuth ready”);
} else {
console.log(”[SURFIX] GitHub OAuth skipped - GITHUB_CLIENT_ID/SECRET not set”);
}

module.exports = passport;
