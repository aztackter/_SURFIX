var router = require("express").Router();
var db = require("../database");
var SurfixObfuscator = require("../obfuscator");
var rateLimit = require("express-rate-limit");
var path = require("path");
var fs = require("fs");

var MAX_CACHE_SIZE = 500;
var loaderCache = new Map();

function getHost() {
  if (!process.env.PUBLIC_URL) {
    console.error("[LOADER] PUBLIC_URL is not set");
    return "";
  }
  return process.env.PUBLIC_URL.replace(/\/$/, "");
}

function loadTemplate() {
  var candidates = [
    path.join(__dirname, "../templates/loader.html"),
    path.join(process.cwd(), "src/templates/loader.html"),
    path.join(process.cwd(), "templates/loader.html")
  ];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(candidates[i])) return fs.readFileSync(candidates[i], "utf8");
  }
  throw new Error("loader.html not found. Tried: " + candidates.join(", "));
}

var HTML_TEMPLATE;
try {
  HTML_TEMPLATE = loadTemplate();
} catch (err) {
  console.error("[SURFIX] FATAL:", err.message);
  process.exit(1);
}

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
  var val = loaderCache.get(key);
  if (!val) return null;
  loaderCache.delete(key);
  loaderCache.set(key, val);
  return val;
}

function cacheSet(key, value) {
  if (loaderCache.size >= MAX_CACHE_SIZE) {
    loaderCache.delete(loaderCache.keys().next().value);
  }
  loaderCache.set(key, value);
}

var EXECUTOR_UA = /Roblox|Delta|Synapse|Krnl|Fluxus|ScriptWare|Arceus|Coco|Electron|Sirius|Vega|Evon|Celery|JJSploit|Oxygen|Hydrogen|Cryptic|Executor|LuaExecutor|Xeno|Solara|Aurora|Swift|Nova|RequestAsync|HttpService/i;
var BROWSER_UA = /Mozilla|Chrome|Safari|Firefox|Edg/i;

function isFromBrowser(req) {
  var ua = req.headers["user-agent"] || "";
  var accept = req.headers["accept"] || "";
  if (EXECUTOR_UA.test(ua)) return false;
  return accept.includes("text/html") && BROWSER_UA.test(ua);
}

function buildRawLoader(project, ffa, HOST) {
  return '-- ' + escapeLua(project.name) + ' v' + escapeLua(project.version) + ' | Protected by SURFIX\n' +
    'local _KEY = "' + (ffa ? "" : "") + '"\n' +
    'local _PROJECT = "' + escapeLua(project.id) + '"\n' +
    'local _HOST = "' + HOST + '"\n' +
    '\n' +
    'local function _HWID()\n' +
    '  if game and game.GetService then\n' +
    '    local ok, id = pcall(function()\n' +
    '      return tostring(game:GetService("RbxAnalyticsService"):GetClientId())\n' +
    '    end)\n' +
    '    if ok and id then return id end\n' +
    '  end\n' +
    '  return tostring(os.time()) .. tostring(math.random(1e15))\n' +
    'end\n' +
    '\n' +
    'local function _POST(url, body)\n' +
    '  if game and game.GetService then\n' +
    '    local hs = game:GetService("HttpService")\n' +
    '    local ok, res = pcall(function()\n' +
    '      return hs:RequestAsync({ Url=url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=hs:JSONEncode(body) })\n' +
    '    end)\n' +
    '    if not ok or not res then return nil end\n' +
    '    local ok2, parsed = pcall(function() return hs:JSONDecode(res.Body) end)\n' +
    '    return ok2 and parsed or nil\n' +
    '  end\n' +
    '  return nil\n' +
    'end\n' +
    '\n' +
    (ffa ? '' : 'if _KEY == "" then error("[SURFIX] Set your license key.") return end\n') +
    '\n' +
    'local _data = _POST(_HOST .. "/api/v1/auth", { key=_KEY, project=_PROJECT, hwid=_HWID(), platform="roblox" })\n' +
    'if not _data then error("[SURFIX] Failed to connect to license server.") return end\n' +
    'if _data.error then error("[SURFIX] " .. tostring(_data.error)) return end\n' +
    'if not _data.script or _data.script == "" then error("[SURFIX] Empty script received.") return end\n' +
    'local _fn, _err = (loadstring or load)(_data.script)\n' +
    'if not _fn then error("[SURFIX] Script load error: " .. tostring(_err)) return end\n' +
    '_fn()\n';
}

var loaderLimiter = rateLimit({ windowMs: 60000, max: 60, standardHeaders: true, legacyHeaders: false });
router.use(loaderLimiter);

router.get("/loader/:projectId.lua", function(req, res) {
  var HOST = getHost();
  var projectId = req.params.projectId;

  if (!isValidProjectId(projectId)) {
    return res.status(400).type("text/plain").send("-- Invalid project ID");
  }

  db.get("SELECT id, name, version, ffa FROM projects WHERE id = ?", [projectId])
    .then(function(project) {
      if (!project) return res.status(404).type("text/plain").send("-- Project not found");

      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");

      var ffa = project.ffa === 1;

      if (isFromBrowser(req)) {
        var loaderUrl = HOST + "/api/loader/" + project.id + ".lua";
        var urlParts = [];
        for (var i = 0; i < loaderUrl.length; i++) {
          urlParts.push(loaderUrl.charCodeAt(i).toString(16));
        }
        var html = HTML_TEMPLATE
          .replace(/__PROJECT_NAME__/g, escapeHtml(project.name))
          .replace(/__FFA_NOTE__/g, ffa ? "FFA Mode - No license key required" : 'script_key = "YOUR_KEY";')
          .replace(/__PARTS__/g, JSON.stringify(urlParts));
        res.type("html").send(html);
        return;
      }

      var cacheKey = project.id + ":" + project.version + ":" + HOST;
      var cached = cacheGet(cacheKey);
      if (cached) {
        return res.type("text/plain").send(cached);
      }

      var rawLoader = buildRawLoader(project, ffa, HOST);
      var obfuscator = new SurfixObfuscator({ level: "light", lightning: false, silent: false });
      var result = obfuscator.obfuscate(rawLoader);
      cacheSet(cacheKey, result.code);
      res.type("text/plain").send(result.code);
    })
    .catch(function(err) {
      console.error("[LOADER]", err.message);
      res.status(500).type("text/plain").send("-- Internal error");
    });
});

var onReady = require("../database").onReady;
onReady(function() {
  db.all("SELECT id, name, version, ffa FROM projects")
    .then(function(projects) {
      var HOST = getHost();
      projects.forEach(function(proj) {
        var cacheKey = proj.id + ":" + proj.version + ":" + HOST;
        if (!loaderCache.has(cacheKey)) {
          var rawLoader = buildRawLoader(proj, proj.ffa === 1, HOST);
          var obfuscator = new SurfixObfuscator({ level: "light", lightning: false, silent: false });
          var result = obfuscator.obfuscate(rawLoader);
          cacheSet(cacheKey, result.code);
        }
      });
      console.log("[SURFIX] Cache warmed (" + projects.length + " projects)");
    })
    .catch(function(err) {
      console.error("[LOADER] warmCache error:", err.message);
    });
});

module.exports = router;
