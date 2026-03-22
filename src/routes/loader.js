const router = require(“express”).Router();
const db = require(”../database”);
const SurfixObfuscator = require(”../obfuscator”);
const rateLimit = require(“express-rate-limit”);
const path = require(“path”);
const fs = require(“fs”);
const crypto = require(“crypto”);

if (!process.env.LOADER_SECRET) {
throw new Error(“LOADER_SECRET must be set in environment”);
}
const LOADER_SECRET = process.env.LOADER_SECRET;

if (!process.env.PUBLIC_URL) {
throw new Error(“PUBLIC_URL must be set in environment”);
}
const HOST = process.env.PUBLIC_URL.replace(//$/, “”);

const MAX_CACHE_SIZE = 500;
const loaderCache = new Map();

function loadTemplate() {
const candidates = [
path.join(__dirname, “../templates/loader.html”),
path.join(process.cwd(), “src/templates/loader.html”),
path.join(process.cwd(), “templates/loader.html”),
];
for (const p of candidates) {
if (fs.existsSync(p)) return fs.readFileSync(p, “utf8”);
}
throw new Error(“loader.html not found. Tried:\n” + candidates.join(”\n”));
}

let HTML_TEMPLATE;
try {
HTML_TEMPLATE = loadTemplate();
} catch (err) {
console.error(”[SURFIX] FATAL:”, err.message);
process.exit(1);
}

function escapeLua(str) {
if (!str) return “”;
return str.replace(/\/g, “\\”).replace(/”/g, ‘\”’);
}

function escapeHtml(str) {
if (!str) return “”;
return str
.replace(/&/g, “&”)
.replace(/</g, “<”)
.replace(/>/g, “>”)
.replace(/”/g, “"”)
.replace(/’/g, “'”);
}

function isValidProjectId(id) {
return /^[a-zA-Z0-9_-]+$/.test(id);
}

function cacheGet(key) {
const val = loaderCache.get(key);
if (!val) return null;
loaderCache.delete(key);
loaderCache.set(key, val);
return val;
}

function cacheSet(key, value) {
if (loaderCache.size >= MAX_CACHE_SIZE) {
const firstKey = loaderCache.keys().next().value;
loaderCache.delete(firstKey);
}
loaderCache.set(key, value);
}

function getRawToken() {
const day = Math.floor(Date.now() / (1000 * 60 * 60 * 24)).toString();
return crypto
.createHmac(“sha256”, LOADER_SECRET)
.update(“raw:” + day)
.digest(“hex”)
.slice(0, 24);
}

function getPrevToken() {
const day = (Math.floor(Date.now() / (1000 * 60 * 60 * 24)) - 1).toString();
return crypto
.createHmac(“sha256”, LOADER_SECRET)
.update(“raw:” + day)
.digest(“hex”)
.slice(0, 24);
}

function isValidRawToken(token) {
if (!token || token.length !== 24) return false;
try {
return (
crypto.timingSafeEqual(Buffer.from(token), Buffer.from(getRawToken())) ||
crypto.timingSafeEqual(Buffer.from(token), Buffer.from(getPrevToken()))
);
} catch {
return false;
}
}

const EXECUTOR_UA_RE =
/Roblox|Delta|Synapse|Krnl|Fluxus|ScriptWare|Arceus|Coco|Sirius|Vega|Evon|Celery|JJSploit|Oxygen|Hydrogen|Cryptic|Script-Executor|Executor|LuaExecutor|Xeno|Solara|Aurora|Swift|Nova|RequestAsync|HttpService/i;

const BROWSER_UA_RE = /Mozilla|Chrome|Safari|Firefox|Edg/i;

function shouldServeLua(req) {
const rawParam = req.query.raw || “”;

// Token-authenticated executor request - always Lua
if (rawParam.length === 24 && isValidRawToken(rawParam)) return true;

// Legacy flag
if (rawParam === “1”) return true;

const ua = req.headers[“user-agent”] || “”;
const accept = req.headers[“accept”] || “”;

// Explicit executor UA -> Lua
if (EXECUTOR_UA_RE.test(ua)) return true;

// Confident real browser -> HTML
if (accept.includes(“text/html”) && BROWSER_UA_RE.test(ua)) return false;

// Unknown/empty UA -> Lua (safe default)
return true;
}

function buildRawLoader(project, ffa) {
const token = getRawToken();
const loaderUrl = `${HOST}/api/loader/${project.id}.lua?raw=${token}`;

return `– ${escapeLua(project.name)} v${escapeLua(project.version)} | Protected by SURFIX
local _KEY = “${ffa ? “FFA” : “”}”
local _PROJECT = “${escapeLua(project.id)}”
local _HOST = “${HOST}”

local function _HWID()
if game and game.GetService then
local ok, id = pcall(function()
return tostring(game:GetService(“RbxAnalyticsService”):GetClientId())
end)
if ok and id then return id end
end
if GetConvar then
return tostring(GetConvar(“sv_licenseKey”, “FIVEM-” .. tostring(math.random(1e9))))
end
return tostring(os.time()) .. tostring(math.random(1e15))
end

local function _POST(url, body)
if game and game.GetService then
local hs = game:GetService(“HttpService”)
local ok, res = pcall(function()
return hs:RequestAsync({
Url    = url,
Method = “POST”,
Headers = { [“Content-Type”] = “application/json” },
Body   = hs:JSONEncode(body)
})
end)
if not ok or not res then return nil end
local ok2, parsed = pcall(function() return hs:JSONDecode(res.Body) end)
return ok2 and parsed or nil
end
return nil
end

${ffa ? “” : `if _KEY == "" then error("[SURFIX] Set your license key before running this script.") return end`}

local _data = _POST(_HOST .. “/api/v1/auth”, {
key      = _KEY,
project  = _PROJECT,
hwid     = _HWID(),
platform = “roblox”
})

if not _data then
error(”[SURFIX] Failed to reach license server.”)
return
end
if _data.error then
error(”[SURFIX] “ .. tostring(_data.error))
return
end
if not _data.script or _data.script == “” then
error(”[SURFIX] Empty response from server.”)
return
end

local _fn, _err = (loadstring or load)(_data.script)
if not _fn then
error(”[SURFIX] Load error: “ .. tostring(_err))
return
end
_fn()`;
}

const loaderLimiter = rateLimit({
windowMs: 60 * 1000,
max: 60,
message: “– Rate limit exceeded. Try again later.”,
standardHeaders: true,
legacyHeaders: false,
});

router.use(loaderLimiter);

router.get(”/loader/:projectId.lua”, async (req, res) => {
try {
const { projectId } = req.params;

```
if (!isValidProjectId(projectId)) {
  return res.status(400).type("text/plain").send("-- Invalid project ID");
}

const project = await db.get(
  "SELECT id, name, version, ffa FROM projects WHERE id = ?",
  [projectId]
);
if (!project) {
  return res.status(404).type("text/plain").send("-- Project not found");
}

res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
res.setHeader("Pragma", "no-cache");
res.setHeader("Expires", "0");

const ffa = project.ffa === 1;

if (shouldServeLua(req)) {
  const token = getRawToken();
  const cacheKey = `${project.id}:${project.version}:${token}`;
  const cached = cacheGet(cacheKey);

  if (cached) {
    res.set("Content-Type", "text/plain; charset=utf-8");
    return res.send(cached);
  }

  const rawLoader = buildRawLoader(project, ffa);
  const obfuscator = new SurfixObfuscator({ level: "light", lightning: false, silent: false });
  const { code } = obfuscator.obfuscate(rawLoader);

  cacheSet(cacheKey, code);
  res.set("Content-Type", "text/plain; charset=utf-8");
  return res.send(code);
}

// Browser: serve styled HTML with token-bearing URL embedded
const executorUrl = `${HOST}/api/loader/${project.id}.lua?raw=${getRawToken()}`;
const urlParts = [];
for (let i = 0; i < executorUrl.length; i++) {
  urlParts.push(executorUrl.charCodeAt(i).toString(16));
}

const html = HTML_TEMPLATE
  .replace(/__PROJECT_NAME__/g, escapeHtml(project.name))
  .replace(/__FFA_NOTE__/g, ffa ? "FFA Mode - No license key required" : 'script_key = "YOUR_KEY"; -- A key is required')
  .replace(/__PARTS__/g, JSON.stringify(urlParts));

res.set({
  "Content-Type": "text/html; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'",
});

return res.send(html);
```

} catch (err) {
console.error(”[SURFIX] Loader error:”, err);
res.status(500).type(“text/plain”).send(”– Internal error: “ + err.message);
}
});

async function warmCache() {
try {
const projects = await db.all(“SELECT id, name, version, ffa FROM projects”);
const token = getRawToken();
for (const proj of projects) {
const cacheKey = `${proj.id}:${proj.version}:${token}`;
if (!loaderCache.has(cacheKey)) {
const rawLoader = buildRawLoader(proj, proj.ffa === 1);
const obfuscator = new SurfixObfuscator({ level: “light”, lightning: false, silent: false });
const { code } = obfuscator.obfuscate(rawLoader);
cacheSet(cacheKey, code);
}
}
console.log(`[SURFIX] Cache warmed (${projects.length} projects)`);
} catch (err) {
console.error(”[SURFIX] Cache warm failed:”, err);
}
}

setImmediate(() => warmCache());

module.exports = router;
