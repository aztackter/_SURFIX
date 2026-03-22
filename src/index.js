require("dotenv").config();
var db = require("./database");
var onReady = db.onReady;

var express = require("express");
var helmet = require("helmet");
var cors = require("cors");
var compression = require("compression");
var morgan = require("morgan");
var rateLimit = require("express-rate-limit");
var session = require("express-session");
var SQLiteStore = require("connect-sqlite3")(session);
var cookieParser = require("cookie-parser");
var path = require("path");
var passport = require("./passport");

var app = express();
app.set("trust proxy", 1);

if (process.env.NODE_ENV === "production") {
  app.use(function(req, res, next) {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.status(403).json({ error: "HTTPS required" });
    }
    next();
  });
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

var ALLOWED_ORIGINS = [
  process.env.PUBLIC_URL,
  "http://localhost:3000",
  "http://localhost:3001"
].filter(Boolean);

app.use(cors({
  origin: function(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.some(function(o) { return origin.startsWith(o); })) return cb(null, true);
    cb(new Error("CORS: origin not allowed"));
  },
  credentials: true
}));

app.use(compression());
app.use(morgan(process.env.NODE_ENV === "production" ? "tiny" : "dev"));
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

var DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  process.env.DATA_DIR ||
  path.join(__dirname, "../data");

app.use(session({
  store: new SQLiteStore({ dir: DATA_DIR, db: "sessions.db" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  },
  name: "sf.sid"
}));

app.use(passport.initialize());
app.use(passport.session());

var rl = rateLimit;
app.locals.limiters = {
  authLimiter:      rl({ windowMs: 60000,    max: 30,  standardHeaders: true, legacyHeaders: false, message: { error: "Too many requests." } }),
  heartbeatLimiter: rl({ windowMs: 60000,    max: 120, standardHeaders: true, legacyHeaders: false }),
  adminLoginLimiter:rl({ windowMs: 60000,    max: 10,  standardHeaders: true, legacyHeaders: false, message: { error: "Too many login attempts." } }),
  publicObfLimiter: rl({ windowMs: 60000,    max: 10,  standardHeaders: true, legacyHeaders: false, message: { error: "Rate limit exceeded." } }),
  signupLimiter:    rl({ windowMs: 3600000,  max: 10,  standardHeaders: true, legacyHeaders: false, message: { error: "Too many signups." } }),
  forgotPwLimiter:  rl({ windowMs: 3600000,  max: 5,   standardHeaders: true, legacyHeaders: false, message: { error: "Too many reset requests." } })
};

app.use(express.static(path.join(__dirname, "../public")));

app.use("/api/public",  require("./routes/public"));
app.use("/api",         require("./routes/loader"));
app.use("/api/v1",      require("./routes/auth"));
app.use("/api/v1",      require("./routes/heartbeat"));
app.use("/api/admin",   require("./routes/admin"));
app.use("/api/user",    require("./routes/users"));
app.use("/auth",        require("./routes/oauth"));

app.get("/dashboard", function(req, res) {
  res.sendFile(path.join(__dirname, "../public/dashboard.html"));
});

app.get(["/", "/oauth-success", "/reset-password"], function(req, res) {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.use(function(req, res) {
  if (req.path.startsWith("/api/") || req.path.startsWith("/auth/")) {
    return res.status(404).json({ error: "Endpoint not found" });
  }
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.use(function(err, req, res, next) {
  if (err.message && err.message.startsWith("CORS")) {
    return res.status(403).json({ error: "Origin not allowed" });
  }
  console.error("[ERROR]", req.method, req.path, err.message);
  res.status(500).json({ error: "Internal server error" });
});

var PORT = process.env.PORT || 3000;
onReady(function() {
  app.listen(PORT, function() {
    console.log("[SURFIX] Listening on :" + PORT);
  });
});
