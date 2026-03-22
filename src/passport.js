const passport       = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const LocalStrategy  = require("passport-local").Strategy;
const bcrypt         = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const db = require("./database");

const HOST = (process.env.PUBLIC_URL || "http://localhost:3000").replace(/\/$/, "");

// ─── Serialize / deserialize ──────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get("SELECT * FROM users WHERE id = ?", [id]);
    done(null, user || false);
  } catch (err) {
    done(err);
  }
});

// ─── Local strategy (email + password) ───────────────────────────────────────
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const user = await db.get("SELECT * FROM users WHERE email = ?", [email.toLowerCase().trim()]);
      if (!user) return done(null, false, { message: "No account found with that email." });
      if (!user.password) return done(null, false, { message: "This account uses social login. Use Google or GitHub." });
      if (!user.verified) return done(null, false, { message: "Please verify your email first." });
      if (!bcrypt.compareSync(password, user.password)) return done(null, false, { message: "Incorrect password." });
      await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [user.id]);
      return done(null, user);
    } catch (err) {
      done(err);
    }
  })
);

// ─── OAuth helper — find or create user ──────────────────────────────────────
async function findOrCreateOAuthUser(provider, profileId, profile) {
  // 1. Check if this OAuth account already exists
  const existing = await db.get(
    "SELECT u.* FROM users u JOIN oauth_accounts o ON o.user_id = u.id WHERE o.provider = ? AND o.provider_id = ?",
    [provider, profileId]
  );
  if (existing) {
    await db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [existing.id]);
    return existing;
  }

  // 2. Check if a user exists with the same email — link the account
  const email = (profile.emails?.[0]?.value || "").toLowerCase().trim();
  let user = email ? await db.get("SELECT * FROM users WHERE email = ?", [email]) : null;

  if (!user) {
    // 3. Create a brand-new user
    const id = uuidv4();
    const username = (profile.displayName || profile.username || email.split("@")[0] || "user")
      .replace(/[^a-zA-Z0-9_]/g, "_")
      .slice(0, 32);
    const avatar = profile.photos?.[0]?.value || null;

    await db.run(
      `INSERT INTO users (id, username, email, avatar_url, verified, role)
       VALUES (?, ?, ?, ?, 1, 'user')`,
      [id, username, email || null, avatar]
    );
    user = await db.get("SELECT * FROM users WHERE id = ?", [id]);
  }

  // 4. Link the OAuth account to the user
  await db.run(
    `INSERT OR IGNORE INTO oauth_accounts (id, user_id, provider, provider_id)
     VALUES (?, ?, ?, ?)`,
    [uuidv4(), user.id, provider, profileId]
  );
  await db.run("UPDATE users SET last_login = strftime('%s','now'), verified = 1 WHERE id = ?", [user.id]);

  return user;
}

// ─── Google ───────────────────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${HOST}/auth/google/callback`,
        scope: ["profile", "email"],
      },
      async (_at, _rt, profile, done) => {
        try {
          const user = await findOrCreateOAuthUser("google", profile.id, profile);
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

// ─── GitHub ───────────────────────────────────────────────────────────────────
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: `${HOST}/auth/github/callback`,
        scope: ["user:email"],
      },
      async (_at, _rt, profile, done) => {
        try {
          const user = await findOrCreateOAuthUser("github", profile.id, profile);
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

module.exports = passport;
