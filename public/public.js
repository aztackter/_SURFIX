const router = require("express").Router();
const SurfixObfuscator = require("../obfuscator");

router.post("/obfuscate", async (req, res) => {
  const { script, protection_level, lightning, silent } = req.body || {};
  
  if (!script) {
    return res.status(400).json({ error: "No script provided" });
  }

  try {
    const obfuscator = new SurfixObfuscator({
      level: protection_level || "max",
      lightning: lightning || false,
      silent: silent || false
    });
    
    const { code, techniques, size } = obfuscator.obfuscate(script);
    
    res.json({
      success: true,
      script: code,
      techniques: techniques,
      size: size
    });
  } catch (err) {
    console.error("Obfuscation error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
