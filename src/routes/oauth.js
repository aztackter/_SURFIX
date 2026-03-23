var router = require("express").Router();
var passport = require("../passport");
var jwt = require("jsonwebtoken");

var JWT_SECRET = process.env.JWT_SECRET;

function issueAndRedirect(req, res, user) {
  if (!user) return res.redirect("/?auth_error=login_failed");
  var token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
  res.cookie("sf_oauth_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 2 * 60 * 1000,
    path: "/auth/oauth-token"
  });
  res.redirect("/oauth-success");
}

router.get("/oauth-token", function(req, res) {
  var token = req.cookies && req.cookies.sf_oauth_token;
  if (!token) return res.status(400).json({ error: "No OAuth session found." });
  try {
    jwt.verify(token, JWT_SECRET);
  } catch (e) {
    res.clearCookie("sf_oauth_token", { path: "/auth/oauth-token" });
    return res.status(401).json({ error: "OAuth session expired." });
  }
  res.clearCookie("sf_oauth_token", { path: "/auth/oauth-token" });
  res.json({ token: token });
});

function requireStrategy(name) {
  return function(req, res, next) {
    try { passport._strategy(name); next(); }
    catch (e) { res.status(503).json({ error: name + " login is not configured." }); }
  };
}

router.get("/google",
  requireStrategy("google"),
  passport.authenticate("google", { scope: ["profile", "email"] })
);
router.get("/google/callback",
  requireStrategy("google"),
  function(req, res, next) {
    passport.authenticate("google", { session: false }, function(err, user) {
      if (err) {
        console.error("[OAUTH] Google error:", err.message);
        return res.redirect("/?auth_error=google_failed");
      }
      if (!user) return res.redirect("/?auth_error=google_failed");
      issueAndRedirect(req, res, user);
    })(req, res, next);
  }
);

router.get("/github",
  requireStrategy("github"),
  passport.authenticate("github", { scope: ["user:email"] })
);
router.get("/github/callback",
  requireStrategy("github"),
  function(req, res, next) {
    passport.authenticate("github", { session: false }, function(err, user) {
      if (err) {
        console.error("[OAUTH] GitHub error:", err.message);
        return res.redirect("/?auth_error=github_failed");
      }
      if (!user) return res.redirect("/?auth_error=github_failed");
      issueAndRedirect(req, res, user);
    })(req, res, next);
  }
);

module.exports = router;
