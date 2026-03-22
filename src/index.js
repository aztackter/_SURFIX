require(“dotenv”).config();

// DB import triggers secret validation - must be first
const { onReady } = require(”./database”);

const express      = require(“express”);
const helmet       = require(“helmet”);
const cors         = require(“cors”);
const compression  = require(“compression”);
const morgan       = require(“morgan”);
const rateLimit    = require(“express-rate-limit”);
const session      = require(“express-session”);
const SQLiteStore  = require(“connect-sqlite3”)(session);
const cookieParser = require(“cookie-parser”);
const path         = require(“path”);

// FIX: require passport AFTER it is configured by passport.js
// passport.js exports the configured passport instance directly
const passport = require(”./passport”);

const app = express();
app.set(“trust proxy”, 1);

// – HTTPS enforcement ———————————————————
if (process.env.NODE_ENV === “production”) {
app.use((req, res, next) => {
if (req.headers[“x-forwarded-proto”] !== “https”) {
return res.status(403).json({ error: “HTTPS required” });
}
next();
});
}

// – Security headers –––––––––––––––––––––––––––––
app.use(helmet({
contentSecurityPolicy: {
directives: {
defaultSrc:  [”‘self’”],
scriptSrc:   [”‘self’”, “‘unsafe-inline’”],
styleSrc:    [”‘self’”, “‘unsafe-inline’”, “https://fonts.googleapis.com”],
fontSrc:     [“https://fonts.gstatic.com”],
imgSrc:      [”‘self’”, “data:”, “https:”],
connectSrc:  [”‘self’”],
frameSrc:    [”‘none’”],
objectSrc:   [”‘none’”],
},
},
crossOriginEmbedderPolicy: false,
}));

// – CORS –––––––––––––––––––––––––––––––––––
const ALLOWED_ORIGINS = [
process.env.PUBLIC_URL,
“http://localhost:3000”,
“http://localhost:3001”,
].filter(Boolean);

app.use(cors({
origin: (origin, cb) => {
if (!origin) return cb(null, true); // curl, Roblox HttpGet, mobile
if (ALLOWED_ORIGINS.some((o) => origin.startsWith(o))) return cb(null, true);
cb(new Error(“CORS: origin not allowed”));
},
credentials: true,
}));

app.use(compression());
app.use(morgan(process.env.NODE_ENV === “production” ? “tiny” : “dev”));
app.use(express.json({ limit: “2mb” }));
app.use(cookieParser());

// – Session —————————————————————––
const DATA_DIR =
process.env.RAILWAY_VOLUME_MOUNT_PATH ||
process.env.DATA_DIR ||
path.join(__dirname, “../data”);

app.use(session({
store:  new SQLiteStore({ dir: DATA_DIR, db: “sessions.db” }),
secret: process.env.SESSION_SECRET,
resave: false,
saveUninitialized: false,
cookie: {
secure:   process.env.NODE_ENV === “production”,
httpOnly: true,
sameSite: “lax”,
maxAge:   7 * 24 * 60 * 60 * 1000,
},
name: “sf.sid”,
}));

// FIX: use the same passport instance that was configured in passport.js
app.use(passport.initialize());
app.use(passport.session());

// – Rate limiters ———————————————————––
const authLimiter = rateLimit({
windowMs: 60_000, max: 30,
standardHeaders: true, legacyHeaders: false,
message: { error: “Too many requests, slow down.” },
});
const heartbeatLimiter = rateLimit({
windowMs: 60_000, max: 120,
standardHeaders: true, legacyHeaders: false,
});
const adminLoginLimiter = rateLimit({
windowMs: 60_000, max: 10,
standardHeaders: true, legacyHeaders: false,
message: { error: “Too many login attempts.” },
});
const publicObfLimiter = rateLimit({
windowMs: 60_000, max: 10,
standardHeaders: true, legacyHeaders: false,
message: { error: “Obfuscation rate limit exceeded.” },
});
const signupLimiter = rateLimit({
windowMs: 60 * 60_000, max: 10,
standardHeaders: true, legacyHeaders: false,
message: { error: “Too many signup attempts. Try again later.” },
});
const forgotPwLimiter = rateLimit({
windowMs: 60 * 60_000, max: 5,
standardHeaders: true, legacyHeaders: false,
message: { error: “Too many reset requests. Try again later.” },
});

app.locals.limiters = {
authLimiter, heartbeatLimiter, adminLoginLimiter,
publicObfLimiter, signupLimiter, forgotPwLimiter,
};

// – Static files –––––––––––––––––––––––––––––––
app.use(express.static(path.join(__dirname, “../public”)));

// – Routes ––––––––––––––––––––––––––––––––––
app.use(”/api/public”,  require(”./routes/public”));
app.use(”/api”,         require(”./routes/loader”));
app.use(”/api/v1”,      require(”./routes/auth”));
app.use(”/api/v1”,      require(”./routes/heartbeat”));
app.use(”/api/admin”,   require(”./routes/admin”));
app.use(”/api/user”,    require(”./routes/users”));
app.use(”/auth”,        require(”./routes/oauth”));

// – SPA pages —————————————————————–
app.get(”/dashboard”, (req, res) => {
res.sendFile(path.join(__dirname, “../public/dashboard.html”));
});

// Explicit page routes only - prevents /api 404s from returning HTML
const PAGE_ROUTES = [”/”, “/oauth-success”, “/reset-password”];
app.get(PAGE_ROUTES, (req, res) => {
res.sendFile(path.join(__dirname, “../public/index.html”));
});

// 404 handler - JSON for /api, HTML for pages
app.use((req, res) => {
if (req.path.startsWith(”/api/”) || req.path.startsWith(”/auth/”)) {
return res.status(404).json({ error: “Endpoint not found” });
}
res.sendFile(path.join(__dirname, “../public/index.html”));
});

// – Global error handler - never leak internal details ———————–
app.use((err, req, res, _next) => {
if (err.message && err.message.startsWith(“CORS”)) {
return res.status(403).json({ error: “Request origin not allowed” });
}
console.error(”[ERROR]”, req.method, req.path, err.message);
res.status(500).json({ error: “Internal server error” });
});

// – Start after DB is ready —————————————————
const PORT = process.env.PORT || 3000;
onReady(() => {
app.listen(PORT, () => console.log(`[SURFIX] Listening on :${PORT}`));
});
