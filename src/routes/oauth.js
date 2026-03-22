const router   = require("express").Router();
// FIX: import from our configured passport.js, not the bare passport package
const passport = require("../passport");
const jwt      = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

// ─── Issue token via short-lived httpOnly cookie ───────────────────────────
// Never put the token in the URL — it ends up in server logs and browser history.
function issueAndRedirect(req, res, user) {
  if (!user) {
    return res.redirect("/?auth_error=login_failed");
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  // Store in a 2-minute httpOnly cookie — just long enough to complete the redirect
  res.cookie("sf_oauth_token", token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge:   2 * 60 * 1000,
    path:     "/auth/oauth-token",
  });

  res.redirect("/oauth-success");
}

// ─── Token exchange endpoint ───────────────────────────────────────────────
// oauth-success.html fetches this to get the token from the httpOnly cookie.
// Cookie is immediately cleared after one read.
router.get("/oauth-token", (req, res) => {
  const token = req.cookies?.sf_oauth_token;
  if (!token) {
    return res.status(400).json({ error: "No OAuth session found. Please try signing in again." });
  }
  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    res.clearCookie("sf_oauth_token", { path: "/auth/oauth-token" });
    return res.status(401).json({ error: "OAuth session expired. Please try again." });
  }
  res.clearCookie("sf_oauth_token", { path: "/auth/oauth-token" });
  res.json({ token });
});

// ─── Guard: return 503 if strategy is not configured ──────────────────────
function requireStrategy(name) {
  return (req, res, next) => {
    try {
      passport._strategy(name);
      next();
    } catch {
      res.status(503).json({
        error: `${name} login is not configured on this server. Use email/password instead.`,
      });
    }
  };
}

// ─── Google ───────────────────────────────────────────────────────────────────
router.get("/google",
  requireStrategy("google"),
  passport.authenticate("google", { scope: ["profile", "email"], session: false })
);
router.get("/google/callback",
  requireStrategy("google"),
  (req, res, next) => {
    passport.authenticate("google", { session: false }, (err, user) => {
      if (err) {
        console.error("[OAUTH] Google callback error:", err.message);
        return res.redirect("/?auth_error=google_failed");
      }
      if (!user) return res.redirect("/?auth_error=google_failed");
      issueAndRedirect(req, res, user);
    })(req, res, next);
  }
);

// ─── GitHub ───────────────────────────────────────────────────────────────────
router.get("/github",
  requireStrategy("github"),
  passport.authenticate("github", { scope: ["user:email"], session: false })
);
router.get("/github/callback",
  requireStrategy("github"),
  (req, res, next) => {
    passport.authenticate("github", { session: false }, (err, user) => {
      if (err) {
        console.error("[OAUTH] GitHub callback error:", err.message);
        return res.redirect("/?auth_error=github_failed");
      }
      if (!user) return res.redirect("/?auth_error=github_failed");
      issueAndRedirect(req, res, user);
    })(req, res, next);
  }
);

module.exports = router;
