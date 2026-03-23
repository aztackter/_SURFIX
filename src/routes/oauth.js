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
  // Store token in localStorage via redirect
  res.redirect("/oauth-success?token=" + encodeURIComponent(token));
}

function requireStrategy(name) {
  return function(req, res, next) {
    try { 
      passport._strategy(name); 
      next(); 
    } catch (e) { 
      console.error("[OAUTH] Strategy not configured:", name);
      res.status(503).json({ error: name + " login is not configured." }); 
    }
  };
}

// Google OAuth
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

// GitHub OAuth
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

// Token exchange endpoint
router.get("/oauth-token", function(req, res) {
  var token = req.query.token;
  if (!token) return res.status(400).json({ error: "No token provided" });
  res.json({ token: token });
});

module.exports = router;
