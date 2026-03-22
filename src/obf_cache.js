const SurfixObfuscator = require("./obfuscator");

const POOL_SIZE  = 8;
const TTL_MS     = 30 * 60 * 1000;
const MAX_ENTRIES = 200;

const cache = new Map();

function cacheKey(projectId, scriptVersion, lightning, silent) {
  return `${projectId}:${scriptVersion}:${lightning ? 1 : 0}:${silent ? 1 : 0}`;
}

function evict() {
  const now = Date.now();
  for (const [k, v] of cache) {
    if (now - v.ts > TTL_MS) cache.delete(k);
  }
  if (cache.size > MAX_ENTRIES) {
    const oldest = [...cache.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
    if (oldest) cache.delete(oldest[0]);
  }
}

function getObfuscated(projectId, scriptVersion, script, config) {
  evict();
  const key = cacheKey(projectId, scriptVersion, config.lightning, config.silent);

  if (!cache.has(key)) {
    // FIXED BUG-18: Generate variants asynchronously to avoid blocking the event loop
    // on first request. We synchronously generate ONE variant and return it immediately,
    // then warm the rest in the background.
    const obf0 = new SurfixObfuscator(config);
    const first = obf0.obfuscate(script).code;
    const variants = [first];
    cache.set(key, { variants, idx: 1, ts: Date.now() });

    // Warm the remaining pool in the background without blocking
    setImmediate(() => {
      const entry = cache.get(key);
      if (!entry) return;
      for (let i = 1; i < POOL_SIZE; i++) {
        const obf = new SurfixObfuscator(config);
        entry.variants.push(obf.obfuscate(script).code);
      }
    });
  }

  const entry = cache.get(key);
  const code = entry.variants[entry.idx % entry.variants.length];
  entry.idx++;
  return code;
}

// FIXED BUG-17: Invalidate ALL cached versions for a project, not just the new one.
// When a script changes we want to evict every old version's cached variants.
function invalidate(projectId) {
  for (const key of cache.keys()) {
    if (key.startsWith(`${projectId}:`)) {
      cache.delete(key);
    }
  }
}

setInterval(() => evict(), 60_000);

module.exports = { getObfuscated, invalidate };
