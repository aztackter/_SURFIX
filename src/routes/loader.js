const router = require("express").Router();
const db = require("../database");
const SurfixObfuscator = require("../obfuscator");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

if (!process.env.LOADER_SECRET) {
  throw new Error("LOADER_SECRET must be set in environment");
}
const LOADER_SECRET = process.env.LOADER_SECRET;

if (!process.env.PUBLIC_URL) {
  throw new Error("PUBLIC_URL must be set in environment");
}
const HOST = process.env.PUBLIC_URL;

const MAX_CACHE_SIZE = 500;
const loaderCache = new Map();

function escapeLua(str) {
  if (!str) return "";
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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

const HTML_TEMPLATE = fs.readFileSync(
  path.join(__dirname, "../templates/loader.html"),
  "utf8"
);

const loaderLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: "-- Rate limit exceeded. Please try again later.",
  standardHeaders: true,
  legacyHeaders: false
});

router.use("/loader", loaderLimiter);

function buildRawLoader(project, ffa) {
  return `-- ${escapeLua(project.name)} v${escapeLua(project.version)} | Protected by SURFIX
-- ${ffa ? "FFA Mode: No key required" : "Set your license key below before running"}
local _KEY = "${ffa ? "FFA" : ""}" -- << PASTE YOUR KEY HERE (if not FFA)
local _PROJECT = "${escapeLua(project.id)}"
local _HOST = "${HOST}"

local function _HWID()
  if game and game.GetService then
    local ok, id = pcall(function()
      return tostring(game:GetService("RbxAnalyticsService"):GetClientId())
    end)
    if ok and id then return id end
  end
  if GetConvar then return tostring(GetConvar("sv_licenseKey", "FIVEM-"..tostring(math.random(1e9)))) end
  return tostring(os.time()) .. tostring(math.random(1e15))
end

local function _POST(url, body)
  if game and game.GetService then
    local hs = game:GetService("HttpService")
    local ok, res = pcall(function()
      return hs:RequestAsync({ Url=url, Method="POST",
        Headers={["Content-Type"]="application/json"},
        Body=hs:JSONEncode(body) })
    end)
    if not ok or not res then return nil end
    local ok2, parsed = pcall(function() return hs:JSONDecode(res.Body) end)
    return ok2 and parsed or nil
  end
  return nil
end

${ffa ? "" : `if _KEY == "" then
  error("[SURFIX] You must set your license key. Contact the script author.")
  return
end`}

local _data = _POST(_HOST .. "/api/v1/auth", {
  key     = _KEY,
  project = _PROJECT,
  hwid    = _HWID(),
  platform = "auto"
})

if not _data then
  error("[SURFIX] Failed to connect to license server. Check your internet.")
  return
end

if _data.error then
  error("[SURFIX] " .. tostring(_data.error))
  return
end

if not _data.script then
  error("[SURFIX] Empty response from server")
  return
end

local _loader = loadstring or load
local _fn, _err = _loader(_data.script)
if not _fn then
  error("[SURFIX] Script load error: " .. tostring(_err))
  return
end
_fn()`;
}

router.get("/loader/:projectId.lua", async (req, res) => {
  try {
    const { projectId } = req.params;
    if (!isValidProjectId(projectId)) {
      return res.status(400).type("text/plain").send("-- Invalid project ID");
    }

    const project = await db.get("SELECT id, name, version, ffa FROM projects WHERE id = ?", [projectId]);
    if (!project) return res.status(404).type("text/plain").send("-- Project not found");

    const ffa = project.ffa === 1;
    const accept = req.headers.accept || "";
    const userAgent = req.headers["user-agent"] || "";
    const isBrowser = accept.includes("text/html") && !accept.includes("application/json") && /Gecko|Chrome|Safari|Firefox|Edg/.test(userAgent);

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    if (isBrowser) {
      const loaderUrl = `${HOST}/api/loader/${project.id}.lua`;
      const urlParts = [];
      for (let i = 0; i < loaderUrl.length; i++) {
        urlParts.push(loaderUrl.charCodeAt(i).toString(16));
      }
      const partsJson = JSON.stringify(urlParts);
      const html = HTML_TEMPLATE
        .replace("__PROJECT_NAME__", escapeHtml(project.name))
        .replace("__FFA_NOTE__", ffa ? "FFA Mode — No license key required" : 'script_key = "YOUR_KEY"; -- A key is required')
        .replace("__PARTS__", partsJson);
      res.set({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
      });
      res.type("html").send(html);
      return;
    }

    const cacheKey = `${project.id}:${project.version}:${HOST}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      res.type("text/plain").send(cached);
      return;
    }

    const rawLoader = buildRawLoader(project, ffa);
    const obfuscator = new SurfixObfuscator({ level: "light", lightning: false, silent: false });
    const { code: obfuscatedLoader } = obfuscator.obfuscate(rawLoader);
    cacheSet(cacheKey, obfuscatedLoader);
    res.type("text/plain").send(obfuscatedLoader);
  } catch (err) {
    console.error("Loader error:", err);
    res.status(500).type("text/plain").send("-- Error: " + err.message);
  }
});

async function warmCache() {
  try {
    const projects = await db.all("SELECT id, name, version, ffa FROM projects");
    for (const proj of projects) {
      const cacheKey = `${proj.id}:${proj.version}:${HOST}`;
      if (!loaderCache.has(cacheKey)) {
        const rawLoader = buildRawLoader(proj, proj.ffa === 1);
        const obfuscator = new SurfixObfuscator({ level: "light", lightning: false, silent: false });
        const { code } = obfuscator.obfuscate(rawLoader);
        cacheSet(cacheKey, code);
      }
    }
  } catch (err) {
    console.error("Failed to warm loader cache:", err);
  }
}

setImmediate(() => warmCache());

module.exports = router;
