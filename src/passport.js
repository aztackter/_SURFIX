var passport = require("passport");
var GoogleStrategy = require("passport-google-oauth20").Strategy;
var GitHubStrategy = require("passport-github2").Strategy;
var uuidv4 = require("uuid").v4;
var db = require("./database");

var HOST = (process.env.PUBLIC_URL || "http://localhost:3000").replace(/\/$/, "");

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.get("SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE id = ?", [id])
    .then(function(user) { done(null, user || false); })
    .catch(function(err) { done(err); });
});

function safeUsername(base) {
  var clean = (base || "user").replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 28) || "user";
  var candidate = clean;
  var suffix = 2;
  function loop() {
    return db.get("SELECT id FROM users WHERE username = ?", [candidate]).then(function(existing) {
      if (!existing) return candidate;
      candidate = clean + "_" + suffix++;
      if (suffix > 999) return "user_" + uuidv4().slice(0, 8);
      return loop();
    });
  }
  return loop();
}

function findOrCreateOAuthUser(provider, profileId, profile) {
  return db.get(
    "SELECT u.id, u.username, u.email, u.role, u.plan, u.avatar_url, u.verified FROM users u JOIN oauth_accounts o ON o.user_id = u.id WHERE o.provider = ? AND o.provider_id = ?",
    [provider, String(profileId)]
  ).then(function(existing) {
    if (existing) {
      return db.run("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", [existing.id])
        .then(function() { return existing; });
    }

    var rawEmail =
      (profile.emails && profile.emails[0] && profile.emails[0].value) ||
      (profile._json && profile._json.email) ||
      null;
    var email = rawEmail ? rawEmail.toLowerCase().trim() : null;

    var rawAvatar =
      (profile.photos && profile.photos[0] && profile.photos[0].value) ||
      (profile._json && profile._json.avatar_url) ||
      null;
    var avatar = (rawAvatar && typeof rawAvatar === "string") ? rawAvatar : null;

    var userPromise = email
      ? db.get("SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE email = ?", [email])
      : Promise.resolve(null);

    return userPromise.then(function(user) {
      if (user) return user;

      var id = uuidv4();
      var displayName =
        profile.displayName ||
        profile.username ||
        (profile._json && profile._json.login) ||
        (email ? email.split("@")[0] : "user");

      return safeUsername(displayName).then(function(username) {
        return db.run(
          "INSERT INTO users (id, username, email, avatar_url, verified, role, plan) VALUES (?, ?, ?, ?, 1, 'user', 'free')",
          [id, username, email || null, avatar]
        ).then(function() {
          return db.get("SELECT id, username, email, role, plan, avatar_url, verified FROM users WHERE id = ?", [id]);
        }).then(function(newUser) {
          if (!newUser) throw new Error("Failed to create user after OAuth insert");
          return newUser;
        });
      });
    });
  }).then(function(user) {
    return db.run(
      "INSERT OR IGNORE INTO oauth_accounts (id, user_id, provider, provider_id) VALUES (?, ?, ?, ?)",
      [uuidv4(), user.id, provider, String(profileId)]
    ).then(function() {
      return db.run("UPDATE users SET last_login = strftime('%s','now'), verified = 1 WHERE id = ?", [user.id]);
    }).then(function() {
      return user;
    });
  });
}

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  var googleCallback = HOST + "/auth/google/callback";
  console.log("[SURFIX] Google callback URL:", googleCallback);
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: googleCallback
  }, function(accessToken, refreshToken, profile, done) {
    findOrCreateOAuthUser("google", profile.id, profile)
      .then(function(user) { done(null, user); })
      .catch(function(err) {
        console.error("[PASSPORT] Google error:", err.message);
        done(err);
      });
  }));
  console.log("[SURFIX] Google OAuth ready");
} else {
  console.log("[SURFIX] Google OAuth skipped - GOOGLE_CLIENT_ID/SECRET not set");
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  var githubCallback = HOST + "/auth/github/callback";
  console.log("[SURFIX] GitHub callback URL:", githubCallback);
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: githubCallback,
    scope: ["user:email"]
  }, function(accessToken, refreshToken, profile, done) {
    findOrCreateOAuthUser("github", profile.id, profile)
      .then(function(user) { done(null, user); })
      .catch(function(err) {
        console.error("[PASSPORT] GitHub error:", err.message);
        done(err);
      });
  }));
  console.log("[SURFIX] GitHub OAuth ready");
} else {
  console.log("[SURFIX] GitHub OAuth skipped - GITHUB_CLIENT_ID/SECRET not set");
}

module.exports = passport;
