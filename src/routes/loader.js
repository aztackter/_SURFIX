const router = require("express").Router();
const db = require("../database");

router.get("/loader/:projectId.lua", async (req, res) => {
  try {
    const project = await db.get("SELECT id, name, version, ffa FROM projects WHERE id = ?", [req.params.projectId]);
    if (!project) return res.status(404).send("-- Project not found");

    const host = `${req.protocol}://${req.get("host")}`;
    const ffa = project.ffa === 1;
    const userAgent = req.headers["user-agent"] || "";
    const isBrowser = userAgent.includes("Mozilla") || userAgent.includes("Chrome") || userAgent.includes("Safari");

    if (isBrowser) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Referrer-Policy", "no-referrer");
      
      return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
  <title>${project.name} — SURFIX Protected Script</title>
  <style>
    * {
      user-select: none;
      -webkit-user-select: none;
      -moz-user-select: none;
      -ms-user-select: none;
    }
    body {
      background: #0a0a0a;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      font-family: system-ui, -apple-system, 'Segoe UI', monospace;
      margin: 0;
      padding: 20px;
      cursor: default;
    }
    .card {
      background: #111;
      border: 1px solid #2a2a2a;
      border-radius: 16px;
      padding: 32px;
      max-width: 500px;
      text-align: center;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      position: relative;
    }
    .icon {
      font-size: 48px;
      margin-bottom: 16px;
    }
    h1 {
      color: #fff;
      font-size: 24px;
      margin-bottom: 12px;
    }
    p {
      color: #888;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    code {
      background: #1a1a1a;
      padding: 12px;
      border-radius: 8px;
      display: block;
      font-family: monospace;
      font-size: 12px;
      color: #4ade80;
      word-break: break-all;
      margin: 16px 0;
      pointer-events: none;
    }
    .note {
      font-size: 12px;
      color: #666;
      margin-top: 16px;
    }
    a {
      color: #8b5cf6;
      text-decoration: none;
      pointer-events: none;
    }
    .warning {
      font-size: 11px;
      color: #ff4444;
      margin-top: 20px;
      padding-top: 16px;
      border-top: 1px solid #222;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>${escapeHtml(project.name)}</h1>
    <p>This is a protected Lua script. It cannot be viewed in a browser.</p>
    <code>loadstring(game:HttpGet("${host}/api/loader/${project.id}.lua"))()</code>
    <div class="note">
      <span>📜 Loadstring</span><br>
      ${ffa ? 'FFA Mode — No license key required' : 'script_key = "YOUR_KEY"; -- A key is required'}
    </div>
    <div class="note">
      Contents can not be displayed on browser • <a href="#">SURFIX</a>
    </div>
    <div class="warning">
      ⚠️ Protected content — unauthorized access detected
    </div>
  </div>

  <script>
    (function() {
      // Disable right-click
      document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
      });
      
      // Disable keyboard shortcuts
      document.addEventListener('keydown', function(e) {
        // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U, Ctrl+S, Ctrl+P
        if (e.key === 'F12' || 
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
            (e.ctrlKey && e.key === 'u') ||
            (e.ctrlKey && e.key === 's') ||
            (e.ctrlKey && e.key === 'p') ||
            (e.ctrlKey && e.key === 'U') ||
            (e.key === 'PrintScreen')) {
          e.preventDefault();
          return false;
        }
      });
      
      // Anti-debug: detect DevTools opening
      let devToolsOpen = false;
      const threshold = 160;
      const checkDevTools = function() {
        const widthDiff = window.outerWidth - window.innerWidth;
        const heightDiff = window.outerHeight - window.innerHeight;
        if (widthDiff > threshold || heightDiff > threshold) {
          if (!devToolsOpen) {
            devToolsOpen = true;
            document.body.innerHTML = '<div style="background:#000; color:#ff4444; display:flex; align-items:center; justify-content:center; height:100vh; text-align:center; padding:20px;"><div><h1>⚠️ Developer Tools Detected</h1><p>Debugging tools are not allowed on this page.</p><p>Close DevTools to continue.</p></div></div>';
          }
        } else {
          devToolsOpen = false;
        }
      };
      setInterval(checkDevTools, 500);
      
      // Disable copy/paste
      document.addEventListener('copy', function(e) {
        e.preventDefault();
        return false;
      });
      document.addEventListener('cut', function(e) {
        e.preventDefault();
        return false;
      });
      document.addEventListener('paste', function(e) {
        e.preventDefault();
        return false;
      });
      
      // Disable drag and drop
      document.addEventListener('dragstart', function(e) {
        e.preventDefault();
        return false;
      });
      
      // Disable text selection (additional)
      document.addEventListener('selectstart', function(e) {
        e.preventDefault();
        return false;
      });
      
      // Disable image dragging
      document.querySelectorAll('img, code').forEach(el => {
        el.addEventListener('dragstart', (e) => {
          e.preventDefault();
          return false;
        });
      });
      
      // Console warning
      console.log('%c⚠️ Protected Content', 'color: #ff4444; font-size: 14px; font-weight: bold;');
      console.log('%cThis page is protected. Viewing source is not allowed.', 'color: #888;');
    })();
  </script>
</body>
</html>`);
    }

    // API clients get Lua loader (unchanged)
    const loader = `-- ${project.name} v${project.version} | Protected by SURFIX
-- ${ffa ? "FFA Mode: No key required" : "Set your license key below before running"}
local _KEY = "${ffa ? "FFA" : ""}" -- << PASTE YOUR KEY HERE (if not FFA)
local _PROJECT = "${project.id}"
local _HOST = "${host}"

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

local _fn, _err = loadstring(_data.script)
if not _fn then
  error("[SURFIX] Script load error: " .. tostring(_err))
  return
end
_fn()`;

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(loader);
  } catch (err) {
    res.status(500).send("-- Error: " + err.message);
  }
});

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = router;
