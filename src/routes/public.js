var router = require("express").Router();
var SurfixObfuscator = require("../obfuscator");

var MAX_SCRIPT_BYTES = 256 * 1024;

router.post("/obfuscate",
  function(req, res, next) { req.app.locals.limiters.publicObfLimiter(req, res, next); },
  async function(req, res) {
    var body = req.body || {};
    var script = body.script;
    if (!script) return res.status(400).json({ error: "No script provided" });

    if (Buffer.byteLength(script, "utf8") > MAX_SCRIPT_BYTES) {
      return res.status(413).json({ error: "Script too large. Maximum size is " + (MAX_SCRIPT_BYTES / 1024) + " KB." });
    }

    var level = ["light", "medium", "max"].includes(body.protection_level) ? body.protection_level : "max";

    try {
      var obfuscator = new SurfixObfuscator({ level: level, lightning: !!body.lightning, silent: !!body.silent });
      var result = obfuscator.obfuscate(script);
      res.json({ success: true, script: result.code, techniques: result.techniques, size: result.size });
    } catch (err) {
      console.error("[OBFUSCATE]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
