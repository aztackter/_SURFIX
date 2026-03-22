require("dotenv").config();
const express     = require("express");
const helmet      = require("helmet");
const cors        = require("cors");
const compression = require("compression");
const morgan      = require("morgan");
const rateLimit   = require("express-rate-limit");
const path        = require("path");

// ── Fail fast on missing secrets ─────────────────────────────────────────────
const REQUIRED_ENV = ["JWT_SECRET", "LOADER_SECRET", "PUBLIC_URL"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[SURFIX] FATAL: ${key} environment variable is not set.`);
    process.exit(1);
  }
}
if ((process.env.JWT_SECRET || "").length < 32) {
  console.error("[SURFIX] FATAL: JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1);

// ── HTTPS enforcement ─────────────────────────────────────────────────────────
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.status(403).json({ error: "HTTPS required" });
    }
    next();
  });
}

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// ── CORS — restrict to your own domain only ───────────────────────────────────
// The wildcard origin ("*") was a critical misconfiguration: any website could
// call /api/v1/auth and steal script payloads. Now we only accept requests from
// the PUBLIC_URL origin (or localhost in dev).
const ALLOWED_ORIGINS = [
  process.env.PUBLIC_URL?.replace(/\/$/, ""),
  ...(process.env.NODE_ENV !== "production"
    ? ["http://localhost:3000", "http://127.0.0.1:3000"]
    : []),
].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow requests with no origin (curl, Roblox HttpGet, server-to-server)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      cb(new Error(`CORS: origin '${origin}' not allowed`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(compression());
app.use(morgan("tiny"));
app.use(express.json({ limit: "2mb" })); // was 10mb — scripts shouldn't be huge
app.use(express.static(path.join(__dirname, "../public")));

// ── Rate limiters ─────────────────────────────────────────────────────────────
// FIX: every meaningful endpoint now has its own limiter.

// Public obfuscation — CPU-heavy, was completely unprotected
const obfuscateLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,                  // 10 obfuscations per minute per IP
  standardHeaders: true,
  message: { error: "Rate limit exceeded. Try again later." },
});

// License auth
const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  message: { error: "Too many auth requests." },
});

// Heartbeat — legitimate clients ping every ~30s, so 120/min is generous
const heartbeatLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
});

// Admin login — strict
const adminLoginLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  message: { error: "Too many login attempts." },
});

// General admin API — authenticated but still needs a ceiling
const adminApiLimiter = rateLimit({
  windowMs: 60_000,
  max: 200,
  standardHeaders: true,
  message: { error: "Admin rate limit exceeded." },
});

// Apply limiters before routes
app.use("/api/public/obfuscate", obfuscateLimiter);
app.use("/api/v1/auth",          authLimiter);
app.use("/api/v1/heartbeat",     heartbeatLimiter);
app.use("/api/admin/login",      adminLoginLimiter);
app.use("/api/admin",            adminApiLimiter);

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api/public",  require("./routes/public"));
app.use("/api",         require("./routes/loader"));
app.use("/api/v1",      require("./routes/auth"));
app.use("/api/v1",      require("./routes/heartbeat"));
app.use("/api/admin",   require("./routes/admin"));

// ── Frontend fallback ─────────────────────────────────────────────────────────
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/dashboard.html"));
});
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[SURFIX] Listening on :${PORT}`));
