const SurfixObfuscator = require("./obfuscator");

const POOL_SIZE = 8;
const TTL_MS = 30 * 60 * 1000;
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
    const variants = [];
    for (let i = 0; i < POOL_SIZE; i++) {
      const obf = new SurfixObfuscator(config);
      const { code } = obf.obfuscate(script);
      variants.push(code);
    }
    cache.set(key, { variants, idx: 0, ts: Date.now() });
  }

  const entry = cache.get(key);
  const code = entry.variants[entry.idx % POOL_SIZE];
  entry.idx++;
  return code;
}

function invalidate(projectId, scriptVersion) {
  for (const [key, value] of cache) {
    if (key.startsWith(`${projectId}:${scriptVersion}:`)) {
      cache.delete(key);
    }
  }
}

setInterval(() => evict(), 60000);

module.exports = { getObfuscated, invalidate };
