const router   = require("express").Router();
const passport = require("passport");
const jwt      = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;
const HOST = (process.env.PUBLIC_URL || "http://localhost:3000").replace(/\/$/, "");

function issueAndRedirect(req, res, user) {
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
  // Pass token to the frontend via a short-lived query param — client stores it immediately
  res.redirect(`/oauth-success?token=${encodeURIComponent(token)}`);
}

// ─── Google ───────────────────────────────────────────────────────────────────
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/?auth_error=google_failed" }),
  (req, res) => issueAndRedirect(req, res, req.user)
);

// ─── GitHub ───────────────────────────────────────────────────────────────────
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get("/github/callback",
  passport.authenticate("github", { session: false, failureRedirect: "/?auth_error=github_failed" }),
  (req, res) => issueAndRedirect(req, res, req.user)
);

module.exports = router;
