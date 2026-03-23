var SurfixObfuscator = require("./obfuscator");

var POOL_SIZE = 8;
var TTL_MS = 30 * 60 * 1000;
var MAX_ENTRIES = 200;

var cache = new Map();

function cacheKey(projectId, scriptVersion, lightning, silent) {
  return projectId + ":" + scriptVersion + ":" + (lightning ? 1 : 0) + ":" + (silent ? 1 : 0);
}

function evict() {
  var now = Date.now();
  for (var entry of cache) {
    if (now - entry[1].ts > TTL_MS) cache.delete(entry[0]);
  }
  if (cache.size > MAX_ENTRIES) {
    var entries = Array.from(cache.entries()).sort(function(a, b) { return a[1].ts - b[1].ts; });
    if (entries[0]) cache.delete(entries[0][0]);
  }
}

function getObfuscated(projectId, scriptVersion, script, config) {
  evict();
  var key = cacheKey(projectId, scriptVersion, config.lightning, config.silent);

  if (!cache.has(key)) {
    var obf0 = new SurfixObfuscator(config);
    var first = obf0.obfuscate(script).code;
    var variants = [first];
    cache.set(key, { variants: variants, idx: 1, ts: Date.now() });

    setImmediate(function() {
      var entry = cache.get(key);
      if (!entry) return;
      for (var i = 1; i < POOL_SIZE; i++) {
        var obf = new SurfixObfuscator(config);
        entry.variants.push(obf.obfuscate(script).code);
      }
    });
  }

  var entry = cache.get(key);
  var code = entry.variants[entry.idx % entry.variants.length];
  entry.idx++;
  return code;
}

function invalidate(projectId) {
  for (var key of cache.keys()) {
    if (key.startsWith(projectId + ":")) {
      cache.delete(key);
    }
  }
}

setInterval(function() { evict(); }, 60000);

module.exports = { getObfuscated: getObfuscated, invalidate: invalidate };
