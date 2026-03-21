const router = require("express").Router();
const db = require("../database");

router.get("/loader/:projectId.lua", async (req, res) => {
  try {
    const project = await db.get("SELECT id, name, version, ffa FROM projects WHERE id = ?", [req.params.projectId]);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    if (!project) return res.status(404).send("-- Project not found");

    const host = `${req.protocol}://${req.get("host")}`;
    const ffa = project.ffa === 1;

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

${project.ffa !== 1 ? `if _data.session_id then
  local _SID = _data.session_id
  local _HB_running = true
  local function _HB_LOOP()
    while _HB_running do
      if wait then wait(30) else os.execute("sleep 30") end
      local r = _POST(_HOST .. "/api/v1/heartbeat", {
        key=_KEY, project=_PROJECT, session_id=_SID
      })
      if r and r.action == "kill" then
        _HB_running = false
        error("[SURFIX] " .. (r.message or "Session terminated"))
      end
    end
  end
  if game and game.GetService then
    spawn(_HB_LOOP)
    game:GetService("Players").LocalPlayer.AncestryChanged:Connect(function()
      _POST(_HOST .. "/api/v1/heartbeat/end", {
        key=_KEY, project=_PROJECT, session_id=_SID
      })
      _HB_running = false
    end)
  else
    _HB_LOOP()
  end
end` : "-- FFA mode: no heartbeat needed"}

local _fn, _err = loadstring(_data.script)
if not _fn then
  error("[SURFIX] Script load error: " .. tostring(_err))
  return
end
_fn()`;

    res.send(loader);
  } catch (err) {
    res.status(500).send("-- Error: " + err.message);
  }
});

module.exports = router;
