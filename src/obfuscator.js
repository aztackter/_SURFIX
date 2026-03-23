const crypto = require("crypto");

function randHex(n) { return crypto.randomBytes(n).toString("hex"); }
function randId()  { return "_" + randHex(4).toUpperCase(); }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function fnv32(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

function xorB64(str, keyHex) {
  const src = Buffer.from(str, "utf8");
  const key = Buffer.from(keyHex, "hex");
  const out = Buffer.alloc(src.length);
  for (let i = 0; i < src.length; i++) out[i] = src[i] ^ key[i % key.length];
  return out.toString("base64");
}

const LUA_B64_DEC = `local function _SFB64(s)
  local A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local t={} for i=1,#A do t[A:sub(i,i)]=i-1 end
  local o,n,p="",0,0
  for i=1,#s do local c=t[s:sub(i,i)] if c then n=n*64+c p=p+6
    if p>=8 then p=p-8 o=o..string.char(math.floor(n/2^p)%256) end end end
  return o
end`;

const LUA_XOR_DEC = `local function _SFXD(d,k)
  local o={} local l=#k
  for i=1,#d do o[i]=string.char(d:byte(i)~k:byte((i-1)%l+1)) end
  return table.concat(o)
end`;

const LUA_FNV = `local function _SFFNV(s)
  local h=2166136261
  for i=1,#s do h=(h~s:byte(i))*16777619 h=h%4294967296 end
  return string.format("%08x",h)
end`;

function encryptStrings(source) {
  const strings = new Map();
  const pattern = /"([^"\\]{3,})"|'([^'\\]{3,})'/g;
  let m;
  while ((m = pattern.exec(source)) !== null) {
    const raw = m[0];
    const content = m[1] || m[2];
    if (!strings.has(raw) && !/^[\s]+$/.test(content)) {
      strings.set(raw, { content, id: randId() });
    }
  }
  if (strings.size === 0) return { code: source, tableCode: "" };

  const tableId = randId();
  const keyHex = randHex(16);
  const keyB64 = Buffer.from(keyHex, "hex").toString("base64");

  let tableCode = `${LUA_B64_DEC}\n${LUA_XOR_DEC}\nlocal ${tableId}={}\n`;
  tableCode += `local _STK=_SFXD(_SFB64("${keyB64}"),string.rep(string.char(0x42),16))\n`;

  for (const [, { content, id }] of strings) {
    const encB64 = xorB64(content, keyHex);
    tableCode += `${tableId}["${id}"]=_SFXD(_SFB64("${encB64}"),_STK)\n`;
  }

  let out = source;
  for (const [raw, { id }] of strings) {
    const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(escaped, "g"), `${tableId}["${id}"]`);
  }
  return { code: out, tableCode };
}

function flattenControlFlow(source) {
  const normalized = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length < 4) return normalized;

  const chunks = [];
  let i = 0;
  while (i < lines.length) {
    const size = randInt(3, 6);
    chunks.push(lines.slice(i, i + size).join("\n"));
    i += size;
  }

  const stateIds = chunks.map(() => randInt(1000, 9999));
  const dispatchVar = randId();
  const stateVar = randId();

  let out = `local ${stateVar}=${stateIds[0]}\nlocal ${dispatchVar}=true\nwhile ${dispatchVar} do\n`;
  for (let j = 0; j < chunks.length; j++) {
    const cur = stateIds[j];
    const next = stateIds[j + 1];
    out += `if ${stateVar}==${cur} then\n${chunks[j]}\n`;
    if (next !== undefined) out += `${stateVar}=${next}\n`;
    else out += `${dispatchVar}=false\n`;
    out += `end\n`;
  }
  return out + "end";
}

function injectOpaquePredicates(source) {
  const preds = [
    `(${randInt(2,9)}*${randInt(2,9)}>${randInt(1,3)})`,
    `(math.abs(-${randInt(5,50)})==${randInt(5,50)})`,
    `(type("")=="string")`,
    `(#"surfix">0)`,
    `(${randInt(1,5)}>${randInt(100,999)})`,
    `(type(nil)~="string")`,
  ];
  const junkTemplates = [
    () => `do local ${randId()}=${randInt(1,999)} end`,
    () => `if ${preds[randInt(0,3)]} then local ${randId()}=${randInt(1,99)} end`,
    () => `do local ${randId()}=string.rep("x",${randInt(1,4)}) end`,
    () => `if ${preds[randInt(4,5)]} then else end`,
  ];
  const lines = source.split("\n");
  const out = [];
  for (const line of lines) {
    out.push(line);
    if (Math.random() < 0.1) {
      out.push(junkTemplates[randInt(0, junkTemplates.length - 1)]());
    }
  }
  return out.join("\n");
}

function xorEncryptSource(source) {
  const keyHex = randHex(16);
  const encB64 = xorB64(source, keyHex);
  const keyB64 = Buffer.from(keyHex, "hex").toString("base64");
  return { encB64, keyB64 };
}

function buildVMWrapper(encB64, keyB64, checksum) {
  const OP_LOADK = randInt(10, 60);
  const OP_EXEC  = randInt(61, 120);
  const OP_CHK   = randInt(121, 180);
  const OP_END   = randInt(181, 240);
  const vmId     = randId();

  const vm = `
local function ${vmId}(bc,kp)
  local _ip=1
  local function _rb() local b=bc:byte(_ip) _ip=_ip+1 return b end
  local _acc=nil
  while _ip<=#bc do
    local op=_rb()
    if op==${OP_LOADK} then
      local idx=_rb()
      _acc=kp[idx]
    elseif op==${OP_CHK} then
      if _SFFNV(_acc):sub(1,8)~="${checksum.slice(0,8)}" then
        error("[SURFIX] Integrity violation")
      end
    elseif op==${OP_EXEC} then
      local fn,e=loadstring(_acc)
      if not fn then error("[SURFIX] "..tostring(e)) end
      fn()
    elseif op==${OP_END} then
      break
    end
  end
end`;

  const bytecode = [OP_LOADK, 1, OP_CHK, OP_EXEC, OP_END];
  const bcB64 = Buffer.from(bytecode).toString("base64");
  return { vm, bcB64, vmId };
}

function buildAntiTamper(lightning) {
  if (lightning) return "";
  return `
local function _SFADB()
  local ok=pcall(function()
    if debug and debug.sethook then
      local _t=0
      debug.sethook(function() _t=_t+1 end,"l")
      local _a=0
      for i=1,10 do _a=_a+i end
      debug.sethook()
      if _t>0 then error("D") end
    end
  end)
  if not ok then return end
  if debug and debug.getinfo then
    local i=debug.getinfo(1)
    if i and i.what=="C" then error("[SURFIX] Debugger detected") end
  end
end
pcall(_SFADB)`;
}

function buildJunkCode() {
  const blocks = [];
  for (let i = 0; i < randInt(3, 6); i++) {
    const id = randId();
    const n  = randInt(5, 40);
    const ch = i % 3;
    if (ch === 0)
      blocks.push(`local function ${id}() local _x=0 for _i=1,${n} do _x=_x+_i end return _x end`);
    else if (ch === 1)
      blocks.push(`local ${id}=setmetatable({},{__index=function(_,_k) return ${randInt(1,999)} end})`);
    else
      blocks.push(`local ${id}=string.rep("${randHex(2)}",${randInt(1,3)})`);
  }
  return blocks.join("\n");
}

class SurfixObfuscator {
  constructor(config = {}) {
    this.level    = config.level    || "max";
    this.lightning = !!config.lightning;
    this.silent    = !!config.silent;
  }

  obfuscate(source) {
    source = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

    const techniques = [];
    let payload = source;

    if (this.level === "light") {
      const { encB64, keyB64 } = xorEncryptSource(payload);
      const cs = fnv32(payload).toString(16).padStart(8, "0");
      const code = this._lightWrap(encB64, keyB64, cs);
      return { code, techniques: ["xor_encrypt", "integrity_check"], size: code.length };
    }

    const { code: strCode, tableCode } = encryptStrings(payload);
    payload = strCode;
    if (tableCode) techniques.push("string_table_encryption");

    if (this.level === "max" && !this.lightning) {
      payload = flattenControlFlow(payload);
      techniques.push("control_flow_flattening");
    }

    if (this.level === "max" && !this.lightning) {
      payload = injectOpaquePredicates(payload);
      techniques.push("opaque_predicates");
    }

    const { encB64, keyB64 } = xorEncryptSource(payload);
    techniques.push("xor_encrypt");

    const checksum = fnv32(payload).toString(16).padStart(8, "0");
    const { vm, bcB64, vmId } = buildVMWrapper(encB64, keyB64, checksum);
    techniques.push("vm_bytecode");

    const antiTamper = buildAntiTamper(this.lightning);
    if (!this.lightning) techniques.push("anti_debug");

    let junk = "";
    if (this.level === "max" && !this.lightning) {
      junk = buildJunkCode();
      techniques.push("junk_injection");
    }

    const silentPre  = this.silent ? `local _SFP=print print=function() end` : "";
    const silentPost = this.silent ? `print=_SFP` : "";
    if (this.silent) techniques.push("silent_mode");

    const code = [
      `-- Protected by SURFIX`,
      LUA_B64_DEC,
      LUA_XOR_DEC,
      LUA_FNV,
      antiTamper,
      junk,
      tableCode,
      silentPre,
      vm,
      `local _sfbc=_SFB64("${bcB64}")`,
      `local _sfkp={[1]=_SFXD(_SFB64("${encB64}"),_SFXD(_SFB64("${keyB64}"),string.rep(string.char(0x58),16)))}`,
      `${vmId}(_sfbc,_sfkp)`,
      silentPost,
    ].filter(Boolean).join("\n");

    return { code, techniques, size: code.length };
  }

  _lightWrap(encB64, keyB64, checksum) {
    return [
      `-- Protected by SURFIX (Light)`,
      LUA_B64_DEC,
      LUA_XOR_DEC,
      LUA_FNV,
      `local _k=_SFB64("${keyB64}")`,
      `local _p=_SFXD(_SFB64("${encB64}"),_k)`,
      `if _SFFNV(_p):sub(1,8)~="${checksum.slice(0,8)}" then error("[SURFIX] Integrity check failed") return end`,
      `local _fn,_e=loadstring(_p) if not _fn then error("[SURFIX] ".._e) end _fn()`,
    ].join("\n");
  }
}

module.exports = SurfixObfuscator;
