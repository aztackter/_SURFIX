require("dotenv").config();

// DB import triggers secret validation at startup — must be before anything else
const { onReady } = require("./database");

const express     = require("express");
const helmet      = require("helmet");
const cors        = require("cors");
const compression = require("compression");
const morgan      = require("morgan");
const rateLimit   = require("express-rate-limit");
const session     = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const passport    = require("passport");
const path        = require("path");
const fs          = require("fs");

require("./passport"); // loads strategy configs

const app = express();

// FIXED BUG-3: trust exactly one proxy hop (Railway's load balancer)
app.set("trust proxy", 1);

// ─── HTTPS enforcement ────────────────────────────────────────────────────────
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.status(403).json({ error: "HTTPS required" });
    }
    next();
  });
}

// ─── Security headers ─────────────────────────────────────────────────────────
// FIXED SEC-1: Enable helmet CSP properly
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// FIXED BUG-2: CORS restricted — only allow the public URL, not wildcard
const ALLOWED_ORIGINS = [
  process.env.PUBLIC_URL,
  "http://localhost:3000",
  "http://localhost:3001",
].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow requests with no origin (curl, Roblox HttpGet, mobile)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.some((o) => origin.startsWith(o))) return cb(null, true);
      cb(new Error("CORS: origin not allowed"));
    },
    credentials: true,
  })
);

app.use(compression());
app.use(morgan(process.env.NODE_ENV === "production" ? "tiny" : "dev"));
app.use(express.json({ limit: "2mb" })); // FIXED SEC-17: tightened from 10mb

// ─── Session (for OAuth flows) ────────────────────────────────────────────────
const DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  process.env.DATA_DIR ||
  path.join(__dirname, "../data");

app.use(
  session({
    store: new SQLiteStore({ dir: DATA_DIR, db: "sessions.db" }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
    name: "sf.sid",
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ─── Rate limiters — defined once, applied per-route ─────────────────────────
// FIXED BUG-1: Limiters are applied directly to routers, not globally before mounting
const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down." },
});
const heartbeatLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
const adminLoginLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts." },
});
// FIXED SEC-16: Public obfuscate now has its own strict limiter
const publicObfLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Obfuscation rate limit exceeded." },
});

// Expose limiters for routes to use
app.locals.limiters = { authLimiter, heartbeatLimiter, adminLoginLimiter, publicObfLimiter };

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "../public")));

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use("/api/public",    require("./routes/public"));
app.use("/api",           require("./routes/loader"));
app.use("/api/v1",        require("./routes/auth"));
app.use("/api/v1",        require("./routes/heartbeat"));
app.use("/api/admin",     require("./routes/admin"));
app.use("/api/user",      require("./routes/users"));     // new user auth routes
app.use("/auth",          require("./routes/oauth"));     // new OAuth routes

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/dashboard.html"));
});
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.message && err.message.startsWith("CORS")) {
    return res.status(403).json({ error: err.message });
  }
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ─── Start only after DB is ready ────────────────────────────────────────────
// FIXED BUG-5: Don't accept connections until schema is fully applied
const PORT = process.env.PORT || 3000;
onReady(() => {
  app.listen(PORT, () => console.log(`[SURFIX] Listening on :${PORT}`));
});
