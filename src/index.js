require("dotenv").config();
const express    = require("express");
const helmet     = require("helmet");
const cors       = require("cors");
const compression = require("compression");
const morgan     = require("morgan");
const rateLimit  = require("express-rate-limit");
const path       = require("path");

const app = express();
app.set("trust proxy", 1);

if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.status(403).json({ error: "HTTPS required" });
    }
    next();
  });
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(compression());
app.use(morgan("tiny"));
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "../public")));

app.use("/api/v1/auth",      rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true }));
app.use("/api/v1/heartbeat", rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true }));
app.use("/api/admin/login",  rateLimit({ windowMs: 60_000, max: 10,  standardHeaders: true }));

app.use("/api/public",   require("./routes/public"));
app.use("/api",          require("./routes/loader"));   // ← mounts loader at /api/loader/...
app.use("/api/v1",       require("./routes/auth"));
app.use("/api/v1",       require("./routes/heartbeat"));
app.use("/api/admin",    require("./routes/admin"));

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/dashboard.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SURFIX listening on :${PORT}`));
