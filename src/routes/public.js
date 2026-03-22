const router = require("express").Router();
const SurfixObfuscator = require("../obfuscator");

const MAX_SCRIPT_BYTES = 256 * 1024; // 256 KB — FIXED SEC-17

router.post(
  "/obfuscate",
  // FIXED SEC-16: Apply the strict public obfuscation rate limiter
  (req, res, next) => req.app.locals.limiters.publicObfLimiter(req, res, next),
  async (req, res) => {
    const { script, protection_level, lightning, silent } = req.body || {};

    if (!script) return res.status(400).json({ error: "No script provided" });

    // FIXED SEC-17: reject oversized scripts before any CPU work
    if (Buffer.byteLength(script, "utf8") > MAX_SCRIPT_BYTES) {
      return res.status(413).json({
        error: `Script too large. Maximum size is ${MAX_SCRIPT_BYTES / 1024} KB.`,
      });
    }

    // Validate protection level
    const level = ["light", "medium", "max"].includes(protection_level)
      ? protection_level
      : "max";

    try {
      const obfuscator = new SurfixObfuscator({
        level,
        lightning: !!lightning,
        silent: !!silent,
      });
      const { code, techniques, size } = obfuscator.obfuscate(script);
      res.json({ success: true, script: code, techniques, size });
    } catch (err) {
      console.error("[OBFUSCATE]", err);
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
