/*
 * Obfustring analyzer — v1
 *
 * Runs inside a Web Worker (or in Node for tests). It never touches the DOM
 * and never executes or emulates the sample: everything here is static
 * byte-level analysis of an untrusted file.
 *
 * Pipeline: parse PE -> entropy -> strings -> IOCs -> decoders -> findings.
 */
'use strict';

const LIMITS = {
  maxStrings: 50000,      // cap on extracted strings kept in the result
  minStringLen: 4,
  maxDecodeDepth: 3,      // layers of base64/hex we will peel
  maxXorHitsPerKey: 64,
  maxDecoded: 2000,
  chartPoints: 512,
};

// ---------------------------------------------------------------- helpers

const enc = new TextEncoder();
const isPrintable = (c) => (c >= 0x20 && c < 0x7f) || c === 0x09;

function entropy(b, start = 0, end = b.length) {
  const n = end - start;
  if (n <= 0) return 0;
  const f = new Uint32Array(256);
  for (let i = start; i < end; i++) f[b[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (f[i]) { const p = f[i] / n; h -= p * Math.log2(p); }
  }
  return h;
}

function entropyChart(b) {
  const block = Math.max(256, Math.ceil(b.length / LIMITS.chartPoints));
  const pts = [];
  for (let off = 0; off < b.length; off += block) {
    pts.push({ offset: off, entropy: +entropy(b, off, Math.min(b.length, off + block)).toFixed(3) });
  }
  return { blockSize: block, points: pts };
}

function bytesToLatin1(b) {
  let s = '';
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode.apply(null, b.subarray(i, i + 8192));
  return s;
}

function printableRatio(b) {
  if (!b.length) return 0;
  let p = 0;
  for (let i = 0; i < b.length; i++) if (isPrintable(b[i]) || b[i] === 0x0a || b[i] === 0x0d) p++;
  return p / b.length;
}

const hex8 = (n) => '0x' + (n >>> 0).toString(16).padStart(8, '0');
const hex2 = (n) => '0x' + n.toString(16).padStart(2, '0');

// ---------------------------------------------------------------- PE parsing

const MACHINES = { 0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA64' };
const SCN = { CODE: 0x20, EXEC: 0x20000000, READ: 0x40000000, WRITE: 0x80000000 };

function parsePE(b) {
  const r = { isPE: false, errors: [] };
  if (b.length < 64 || b[0] !== 0x4d || b[1] !== 0x5a) { r.errors.push('No MZ header — not a PE file'); return r; }
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const peOff = dv.getUint32(0x3c, true);
  if (peOff + 24 > b.length || dv.getUint32(peOff, true) !== 0x00004550) {
    r.errors.push('MZ header present but PE signature missing/invalid'); return r;
  }
  try {
    const coff = peOff + 4;
    r.machine = MACHINES[dv.getUint16(coff, true)] || hex8(dv.getUint16(coff, true));
    const nSec = dv.getUint16(coff + 2, true);
    r.timestamp = dv.getUint32(coff + 4, true);
    const optSize = dv.getUint16(coff + 16, true);
    r.characteristics = dv.getUint16(coff + 18, true);
    r.isDLL = !!(r.characteristics & 0x2000);
    const opt = coff + 20;
    const magic = dv.getUint16(opt, true);
    if (magic !== 0x10b && magic !== 0x20b) { r.errors.push('Unknown optional header magic ' + hex8(magic)); return r; }
    r.is64 = magic === 0x20b;
    r.entryPoint = dv.getUint32(opt + 16, true);
    r.imageBase = r.is64 ? Number(dv.getBigUint64(opt + 24, true)) : dv.getUint32(opt + 28, true);
    r.sizeOfHeaders = dv.getUint32(opt + 60, true);
    r.subsystem = dv.getUint16(opt + 68, true);
    const nDD = dv.getUint32(opt + (r.is64 ? 108 : 92), true);
    const ddOff = opt + (r.is64 ? 112 : 96);
    r.dataDirs = [];
    for (let i = 0; i < Math.min(nDD, 16); i++) {
      const o = ddOff + i * 8;
      if (o + 8 > opt + optSize) break;
      r.dataDirs.push({ rva: dv.getUint32(o, true), size: dv.getUint32(o + 4, true) });
    }

    r.sections = [];
    const secTbl = opt + optSize;
    for (let i = 0; i < Math.min(nSec, 96); i++) {
      const o = secTbl + i * 40;
      if (o + 40 > b.length) { r.errors.push('Section table truncated'); break; }
      let name = '';
      for (let j = 0; j < 8 && b[o + j]; j++) name += String.fromCharCode(b[o + j]);
      const s = {
        name,
        virtualSize: dv.getUint32(o + 8, true),
        virtualAddress: dv.getUint32(o + 12, true),
        rawSize: dv.getUint32(o + 16, true),
        rawPtr: dv.getUint32(o + 20, true),
        flags: dv.getUint32(o + 36, true),
      };
      const end = Math.min(b.length, s.rawPtr + s.rawSize);
      s.entropy = s.rawPtr < b.length && s.rawSize ? +entropy(b, s.rawPtr, end).toFixed(3) : 0;
      s.exec = !!(s.flags & SCN.EXEC) || !!(s.flags & SCN.CODE);
      s.write = !!(s.flags & SCN.WRITE);
      s.read = !!(s.flags & SCN.READ);
      r.sections.push(s);
    }
    r.isPE = true;

    const rvaToOff = (rva) => {
      for (const s of r.sections) {
        const span = Math.max(s.virtualSize, s.rawSize);
        if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
          const d = rva - s.virtualAddress;
          return d < s.rawSize ? s.rawPtr + d : -1;
        }
      }
      return rva < r.sizeOfHeaders ? rva : -1;
    };
    const cstr = (off, max = 256) => {
      if (off < 0 || off >= b.length) return null;
      let s = '';
      for (let i = off; i < b.length && i < off + max && b[i]; i++) s += String.fromCharCode(b[i]);
      return s;
    };

    r.entrySection = null;
    for (const s of r.sections) {
      if (r.entryPoint >= s.virtualAddress && r.entryPoint < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
        r.entrySection = s.name; break;
      }
    }

    // Imports (data directory 1)
    r.imports = [];
    const imp = r.dataDirs[1];
    if (imp && imp.rva && imp.size) {
      let d = rvaToOff(imp.rva);
      for (let n = 0; d >= 0 && d + 20 <= b.length && n < 512; n++, d += 20) {
        const oft = dv.getUint32(d, true), nameRva = dv.getUint32(d + 12, true), ft = dv.getUint32(d + 16, true);
        if (!oft && !nameRva && !ft) break;
        const dll = cstr(rvaToOff(nameRva)) || '?';
        const funcs = [];
        let t = rvaToOff(oft || ft);
        const step = r.is64 ? 8 : 4;
        for (let k = 0; t >= 0 && t + step <= b.length && k < 4096; k++, t += step) {
          let ordinal = false, val;
          if (r.is64) {
            const v = dv.getBigUint64(t, true);
            if (v === 0n) break;
            ordinal = (v >> 63n) === 1n;
            val = Number(v & 0x7fffffffn);
          } else {
            const v = dv.getUint32(t, true);
            if (v === 0) break;
            ordinal = (v >>> 31) === 1;
            val = v & 0x7fffffff;
          }
          funcs.push(ordinal ? '#' + (val & 0xffff) : (cstr(rvaToOff(val) + 2) || '?'));
        }
        r.imports.push({ dll, functions: funcs });
      }
    }
    r.importCount = r.imports.reduce((a, d) => a + d.functions.length, 0);
    r.isDotNet = !!(r.dataDirs[14] && r.dataDirs[14].size);

    // Overlay: bytes after the last section's raw data
    let lastRaw = r.sizeOfHeaders;
    for (const s of r.sections) if (s.rawSize) lastRaw = Math.max(lastRaw, s.rawPtr + s.rawSize);
    if (lastRaw < b.length) {
      r.overlay = { offset: lastRaw, size: b.length - lastRaw, entropy: +entropy(b, lastRaw, b.length).toFixed(3) };
    }
  } catch (e) {
    r.errors.push('PE parse error: ' + e.message);
  }
  return r;
}

// ---------------------------------------------------------------- strings

function extractStrings(b, minLen = LIMITS.minStringLen) {
  const out = [];
  let truncated = false;
  // ASCII
  let start = -1;
  for (let i = 0; i <= b.length; i++) {
    if (i < b.length && isPrintable(b[i])) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= minLen) {
      if (out.length >= LIMITS.maxStrings) { truncated = true; break; }
      out.push({ offset: start, enc: 'ascii', value: bytesToLatin1(b.subarray(start, i)) });
    }
    start = -1;
  }
  // UTF-16LE (two alignments)
  for (let align = 0; align < 2 && !truncated; align++) {
    start = -1;
    let s = '';
    for (let i = align; i + 1 <= b.length; i += 2) {
      const ok = i + 1 < b.length && isPrintable(b[i]) && b[i + 1] === 0;
      if (ok) { if (start < 0) { start = i; s = ''; } s += String.fromCharCode(b[i]); continue; }
      if (start >= 0 && s.length >= minLen) {
        if (out.length >= LIMITS.maxStrings) { truncated = true; break; }
        out.push({ offset: start, enc: 'utf16le', value: s });
      }
      start = -1;
    }
  }
  out.sort((a, b2) => a.offset - b2.offset);
  return { list: out, truncated };
}

// ---------------------------------------------------------------- IOCs

const TLDS = 'com|net|org|info|biz|io|ru|cn|su|xyz|top|club|online|site|tk|ml|ga|cf|gq|pw|cc|ws|me|co|us|uk|de|fr|nl|in|br|ir|kp|onion|app|dev|live|shop|store|icu|cyou|buzz|link|click|space|website|fun|host|cloud|ly|to|gg|tv|vip|work|win|bid|loan|date|party|review|stream|download|gdn|kim|men|lol';

const IOC_PATTERNS = [
  { type: 'url', re: /\b(?:https?|ftp|wss?):\/\/[^\s"'<>\\^`{|}]{3,}/gi },
  { type: 'ipv4', re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b/g },
  { type: 'email', re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[a-z]{2,24}\b/g },
  // TLD is matched lowercase-only on purpose: avoids .NET noise like "System.IO"
  { type: 'domain', re: new RegExp('\\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+(?:' + TLDS + ')\\b(?![.\\w-]*\\()', 'g') },
  { type: 'registry', re: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR)\\[^\s"'<>|]{2,}/gi },
  { type: 'registry', re: /\b(?:SOFTWARE|SYSTEM)\\(?:[A-Za-z0-9_ .-]+\\)+[A-Za-z0-9_ .-]*/g },
  { type: 'path', re: /\b[A-Za-z]:\\[^\s"'<>|*?\x00-\x1f]{2,}/g },
  { type: 'path', re: /%(?:APPDATA|TEMP|TMP|USERPROFILE|LOCALAPPDATA|PROGRAMDATA|SYSTEMROOT|WINDIR|PUBLIC|ALLUSERSPROFILE)%[^\s"'<>|]*/gi },
  { type: 'crypto-wallet', re: /\bbc1[ac-hj-np-z02-9]{25,59}\b/g },
  { type: 'crypto-wallet', re: /\b0x[a-fA-F0-9]{40}\b/g },
  { type: 'user-agent', re: /Mozilla\/\d\.\d \([^)]{4,200}\)[^"\x00]{0,120}/g },
  { type: 'command', re: /\b(?:powershell(?:\.exe)?\s+[^\n]{0,200}-(?:e|en|enc|encodedcommand|w\s+hidden|nop|ep\s+bypass)\b[^\n]{0,200}|cmd(?:\.exe)?\s+\/[ck]\s+[^\n]{2,200}|vssadmin(?:\.exe)?\s+delete\s+shadows[^\n]{0,100}|bcdedit[^\n]{0,20}(?:recoveryenabled|bootstatuspolicy)[^\n]{0,80}|wmic[^\n]{0,20}shadowcopy\s+delete[^\n]{0,60}|schtasks(?:\.exe)?\s+\/create[^\n]{0,200}|certutil(?:\.exe)?\s+[^\n]{0,30}-(?:urlcache|decode)[^\n]{0,150}|bitsadmin[^\n]{0,20}\/transfer[^\n]{0,150}|mshta(?:\.exe)?\s+[^\n]{3,200}|regsvr32[^\n]{0,30}\/i:[^\n]{0,150}|rundll32(?:\.exe)?\s+[^\n]{3,200})/gi },
];

// Domains that show up in benign binaries (certs, manifests, runtimes)
const BENIGN_DOMAINS = /(?:^|\.)(?:microsoft\.com|windows\.com|windowsupdate\.com|digicert\.com|verisign\.com|symantec\.com|symcb\.com|symcd\.com|thawte\.com|globalsign\.(?:com|net)|sectigo\.com|usertrust\.com|comodoca\.com|letsencrypt\.org|godaddy\.com|entrust\.net|w3\.org|xmlsoap\.org|openssl\.org|python\.org|apple\.com|google\.com|mozilla\.org|gnu\.org|sourceforge\.net|github\.com|oracle\.com|java\.com|adobe\.com|intel\.com|nvidia\.com)$/i;

function classifyIp(ip) {
  const o = ip.split(':')[0].split('.').map(Number);
  if (o[0] === 0 || o.slice(1).every((x) => x === 0)) return 'version-like';
  if (o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168) || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 169 && o[1] === 254)) return 'private';
  if (o[0] >= 224) return 'reserved';
  return 'public';
}

function findIocs(text) {
  const hits = [];
  for (const { type, re } of IOC_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      let v = m[0].replace(/[.,;:)\]]+$/, '');
      const ioc = { type, value: v };
      if (type === 'ipv4') {
        ioc.class = classifyIp(v);
        if (ioc.class === 'version-like') continue;
      }
      if (type === 'domain' || type === 'url' || type === 'email') {
        const host = type === 'url' ? (v.split('/')[2] || '').split(':')[0].split('@').pop()
          : type === 'email' ? v.split('@')[1] : v;
        if (BENIGN_DOMAINS.test(host)) ioc.benign = true;
      }
      if (type === 'ipv4' && ioc.class !== 'public') ioc.benign = true;
      hits.push(ioc);
    }
  }
  return hits;
}

function defang(ioc) {
  const v = ioc.value;
  switch (ioc.type) {
    case 'url': return v.replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp').replace(/\./g, '[.]');
    case 'ipv4':
    case 'domain': return v.replace(/\./g, '[.]');
    case 'email': return v.replace('@', '[@]').replace(/\./g, '[.]');
    default: return v;
  }
}

// ---------------------------------------------------------------- suspicious APIs

const API_GROUPS = {
  'Process injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC', 'NtQueueApcThread', 'SetThreadContext', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'NtMapViewOfSection', 'ResumeThread'],
  'Memory / shellcode': ['VirtualAlloc', 'VirtualProtect', 'VirtualProtectEx', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'HeapCreate'],
  'Dynamic API resolution': ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress'],
  'Anti-debug / anti-VM': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'GetTickCount', 'QueryPerformanceCounter', 'NtSetInformationThread', 'GetSystemFirmwareTable'],
  'Network': ['InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetConnectA', 'InternetConnectW', 'HttpSendRequestA', 'HttpSendRequestW', 'HttpOpenRequestA', 'URLDownloadToFileA', 'URLDownloadToFileW', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest', 'WSAStartup', 'socket', 'connect', 'send', 'recv', 'gethostbyname', 'getaddrinfo'],
  'Persistence': ['RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW', 'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW'],
  'Execution': ['WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW', 'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW'],
  'Crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptGenKey', 'CryptImportKey', 'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey'],
  'Keylogging / spying': ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'GetForegroundWindow', 'BitBlt', 'GetClipboardData'],
  'Privilege / tokens': ['AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'ImpersonateLoggedOnUser', 'DuplicateTokenEx'],
};
const API_TO_GROUP = new Map();
for (const [g, list] of Object.entries(API_GROUPS)) for (const a of list) API_TO_GROUP.set(a, g);

// ---------------------------------------------------------------- decoders

const COMMON_TOKENS = ['http', 'www', '.com', '.net', '.org', '.exe', '.dll', '.bat', '.ps1', '.vbs', 'software', 'microsoft', 'windows', 'system32', 'cmd', 'powershell', 'user', 'agent', 'mozilla', 'kernel32', 'ntdll', 'admin', 'password', 'login', 'config', 'temp', 'appdata', 'run', 'error', 'file', 'the ', ' and ', 'this ', 'version', 'server', 'client', 'key', 'data', 'path', 'process'];

function textScore(s) {
  if (!s || s.length < 4) return { score: 0, iocs: [] };
  let letters = 0, vowels = 0, digits = 0, other = 0;
  for (const ch of s) {
    if (/[A-Za-z]/.test(ch)) { letters++; if (/[aeiouAEIOU]/.test(ch)) vowels++; }
    else if (/[0-9]/.test(ch)) digits++;
    else if (ch !== ' ') other++;
  }
  const iocs = findIocs(s).filter((i) => !i.benign);
  const lower = s.toLowerCase();
  let words = 0;
  for (const t of COMMON_TOKENS) if (lower.includes(t)) words++;
  let score = iocs.length * 40 + words * 10;
  const lr = letters / s.length;
  if (lr > 0.5) score += 10;
  if (letters && vowels / letters > 0.2 && vowels / letters < 0.6) score += 10;
  if (other / s.length > 0.3) score -= 20;
  if (s.length > 6 && new Set(s).size / s.length < 0.35 && !iocs.length) score -= 30; // "wwwwswww"-style junk
  return { score, iocs };
}

const B64_RE = /[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{20,}={0,2}/g;
const HEX_RE = /\b(?:[0-9a-fA-F]{2}){8,}\b/g;
const ESC_HEX_RE = /(?:\\x[0-9a-fA-F]{2}){4,}/g;

function b64decode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (s.length % 4 === 1) return null;
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const out = new Uint8Array(Math.floor(s.length * 3 / 4));
  let bits = 0, acc = 0, j = 0;
  for (let i = 0; i < s.length; i++) {
    const v = A.indexOf(s[i]);
    if (v < 0) return null;
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[j++] = (acc >> bits) & 0xff; }
  }
  return out.subarray(0, j);
}
function hexdecode(s) {
  s = s.replace(/\\x/g, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

// Turn decoded bytes into text if they look like text (ASCII or UTF-16LE).
function bytesAsText(bytes) {
  if (bytes.length >= 4 && bytes.length % 2 === 0) {
    let zeros = 0;
    for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    if (zeros / (bytes.length / 2) > 0.9) {
      const narrow = new Uint8Array(bytes.length / 2);
      for (let i = 0; i < narrow.length; i++) narrow[i] = bytes[i * 2];
      if (printableRatio(narrow) > 0.9) return { text: bytesToLatin1(narrow), note: 'utf16le' };
    }
  }
  if (printableRatio(bytes) > 0.9) return { text: bytesToLatin1(bytes).replace(/[\r\n]+/g, ' ').trim(), note: null };
  return null;
}

function magicOf(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return 'PE/MZ executable';
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip data';
  if (bytes.length >= 2 && bytes[0] === 0x78 && (bytes[1] === 0x9c || bytes[1] === 0xda || bytes[1] === 0x01)) return 'zlib data';
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4) return 'ZIP archive';
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return 'ELF executable';
  if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'PDF document';
  return null;
}

// Recursively peel base64 / hex / \x-escaped layers from a string.
function peel(str, chain, depth, sink, origin) {
  if (depth >= LIMITS.maxDecodeDepth) return;
  const tryLayer = (re, name, decodeFn) => {
    // matchAll clones the regex, so recursion below can't clobber lastIndex
    for (const m of str.matchAll(re)) {
      const cand = m[0];
      if (name === 'base64' && !(/[0-9+/]/.test(cand) && /[a-z]/.test(cand) && /[A-Z]/.test(cand))) continue;
      if (name === 'hex' && cand.length % 2) continue;
      const bytes = decodeFn(cand);
      if (!bytes || bytes.length < 4) continue;
      const c = chain.concat(name);
      const magic = magicOf(bytes);
      if (magic) { sink.push({ origin, method: c.join(' → '), value: `[${magic}, ${bytes.length} bytes]`, magic, score: 60, iocs: [] }); continue; }
      const t = bytesAsText(bytes);
      if (!t) continue;
      const cc = t.note ? c.concat(t.note) : c;
      const sc = textScore(t.text);
      if (sc.score >= 20) sink.push({ origin, method: cc.join(' → '), value: t.text, score: sc.score, iocs: sc.iocs });
      peel(t.text, cc, depth + 1, sink, origin);
    }
  };
  tryLayer(B64_RE, 'base64', b64decode);
  tryLayer(HEX_RE, 'hex', hexdecode);
  tryLayer(ESC_HEX_RE, '\\x-hex', hexdecode);
}

function rot13(s) {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const b = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
  });
}

// Known-plaintext single-byte XOR: for each needle, find positions where
// b[i]^k == needle[0] and the rest of the needle matches under the same key.
const XOR_NEEDLES = ['http://', 'https://', 'This program cannot', '.exe\0', '.dll\0', 'kernel32', 'Kernel32', 'KERNEL32', '\\Software\\', 'SOFTWARE\\', 'Mozilla/', 'cmd.exe', 'powershell', 'HKEY_', 'CurrentVersion\\Run', 'ws2_32', 'wininet', 'GetProcAddress', 'VirtualAlloc', 'LoadLibrary'].map((s) => enc.encode(s));

function xorScan(b) {
  const keyHits = new Map(); // key -> [{pos, needle}]
  for (const nd of XOR_NEEDLES) {
    const L = nd.length, n0 = nd[0];
    for (let i = 0; i + L <= b.length; i++) {
      const k = b[i] ^ n0;
      if (k === 0) continue;
      let j = 1;
      while (j < L && (b[i + j] ^ k) === nd[j]) j++;
      if (j === L) {
        let arr = keyHits.get(k);
        if (!arr) keyHits.set(k, (arr = []));
        if (arr.length < LIMITS.maxXorHitsPerKey) arr.push({ pos: i, needle: bytesToLatin1(nd).replace('\0', '') });
      }
    }
  }
  const results = [];
  for (const [k, hits] of keyHits) {
    const seen = new Set();
    for (const h of hits) {
      // Grow the decoded string left and right while it stays printable.
      // Stop at raw 0x00 (unencoded padding) and at encoded nulls (byte == key),
      // otherwise XOR'd zero-padding turns into runs of the key character.
      const ok = (i) => b[i] !== 0 && b[i] !== k && isPrintable(b[i] ^ k);
      let s = h.pos, e = h.pos;
      while (s > 0 && ok(s - 1) && h.pos - s < 4096) s--;
      while (e < b.length && ok(e) && e - h.pos < 4096) e++;
      if (seen.has(s)) continue;
      seen.add(s);
      const dec = new Uint8Array(e - s);
      for (let i = s; i < e; i++) dec[i - s] = b[i] ^ k;
      const text = bytesToLatin1(dec);
      const sc = textScore(text);
      const isStub = h.needle === 'This program cannot';
      results.push({
        origin: s, method: `xor ${hex2(k)}`, key: k, value: text,
        score: sc.score + (isStub ? 50 : 0), iocs: sc.iocs,
        magic: isStub ? 'XOR-encoded PE (DOS stub found)' : undefined,
      });
    }
  }
  return results;
}

function findEmbeddedPEs(b) {
  const found = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 1; i + 64 < b.length; i++) {
    if (b[i] !== 0x4d || b[i + 1] !== 0x5a) continue;
    const lfa = dv.getUint32(i + 0x3c, true);
    if (lfa < 0x40 || lfa > 0x1000 || i + lfa + 4 > b.length) continue;
    if (dv.getUint32(i + lfa, true) === 0x00004550) found.push({ offset: i });
    if (found.length >= 32) break;
  }
  return found;
}

// ---------------------------------------------------------------- findings

const PACKER_SECTIONS = {
  UPX0: 'UPX', UPX1: 'UPX', UPX2: 'UPX', 'UPX!': 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack', ASPack: 'ASPack',
  '.MPRESS1': 'MPRESS', '.MPRESS2': 'MPRESS', '.petite': 'Petite', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack',
  '.themida': 'Themida', '.winlice': 'WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
  '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector', pec1: 'PECompact', pec2: 'PECompact', PEC2: 'PECompact',
  PEC2TO: 'PECompact', '.perplex': 'Perplex', '.yP': 'Y0da Crypter', '.y0da': 'Y0da Crypter', '.spack': 'Simple Pack',
  '.packed': 'Generic packer', '.RLPack': 'RLPack', '.ccg': 'CCG Packer', '.boom': 'The Boomer', '.taz': 'PESpin',
  '.MaskPE': 'MaskPE', '.sforce3': 'StarForce', '.svkp': 'SVKP', '.Upack': 'Upack', '.ByDwing': 'Upack', 'kkrunchy': 'kkrunchy',
  '.mackt': 'ImpRec', '.shrink1': 'Shrinker', '.WWPACK': 'WWPack', 'BitArts': 'Crunch', '.neolite': 'Neolite',
};
const STANDARD_SECTIONS = new Set(['.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata', '.edata', '.pdata', '.tls', '.bss', '.CRT', '.didat', '.gfids', '.00cfg', '.xdata', 'CODE', 'DATA', 'BSS', '.textbss', '.sxdata', '.debug', '_RDATA', '.voltbl', '.retplne', '.fptable', '.giats', '.buildid', '.eh_fram', '.ndata', 'INIT', 'PAGE', '.orpc', '.text$mn', '.wixburn', '.gehcont', '.sdata', '.rodata', '/4', '/14', '/29', '/41', '/55', '/67', '/80', '/91']);

function buildFindings(b, pe, strs, decoded, embedded, xorPEs, apiInfo, fileEntropy) {
  const F = [];
  const add = (severity, points, title, detail) => F.push({ severity, points, title, detail });

  if (pe.isPE) {
    const packers = new Set();
    for (const s of pe.sections) if (PACKER_SECTIONS[s.name]) packers.add(PACKER_SECTIONS[s.name]);
    const hdr = bytesToLatin1(b.subarray(0, Math.min(b.length, 4096)));
    if (hdr.includes('UPX!')) packers.add('UPX');
    if (packers.size) add('high', 30, `Packer signature: ${[...packers].join(', ')}`, 'Section names or header markers match known packers/protectors. The real code is compressed or encrypted on disk.' + (packers.has('UPX') ? ' UPX can usually be reversed with `upx -d` in a sandbox.' : ''));

    const hiExec = pe.sections.filter((s) => s.exec && s.entropy > 7.2);
    const hiOther = pe.sections.filter((s) => !s.exec && s.entropy > 7.2 && s.name !== '.rsrc');
    if (hiExec.length) add('high', 25, 'High-entropy executable section', hiExec.map((s) => `${s.name || '(unnamed)'}: ${s.entropy}`).join(', ') + ' — compiled code is typically 5.5–6.8; above 7.2 suggests compression or encryption.');
    if (hiOther.length) add('medium', 10, 'High-entropy data section', hiOther.map((s) => `${s.name || '(unnamed)'}: ${s.entropy}`).join(', ') + ' — may hold an encrypted payload or config.');
    const rsrc = pe.sections.find((s) => s.name === '.rsrc' && s.entropy > 7.4);
    if (rsrc) add('low', 5, 'High-entropy resource section', `.rsrc entropy ${rsrc.entropy}. Often just compressed icons/images, but also a common place to stash payloads.`);

    const virt = pe.sections.filter((s) => s.rawSize === 0 && s.virtualSize > 0x1000 && s.exec);
    if (virt.length) add('high', 20, 'Empty-on-disk executable section', virt.map((s) => `${s.name}: vsize ${hex8(s.virtualSize)}, raw 0`).join(', ') + ' — space reserved for code that gets unpacked at runtime.');

    const wx = pe.sections.filter((s) => s.exec && s.write);
    if (wx.length) add('medium', 15, 'Writable + executable section', wx.map((s) => s.name || '(unnamed)').join(', ') + ' — self-modifying code / unpacking stubs need W+X; normal compilers rarely emit it.');

    if (!pe.entrySection) add('medium', 15, 'Entry point outside all sections', `EP ${hex8(pe.entryPoint)} does not fall inside any section.`);
    else {
      const idx = pe.sections.findIndex((s) => s.name === pe.entrySection);
      const first = pe.sections.findIndex((s) => s.exec);
      if (idx !== first && pe.sections.length > 1) add('medium', 15, 'Entry point in unexpected section', `EP is in "${pe.entrySection}" (section #${idx + 1}), not the first code section. Typical of packer stubs appended to the binary.`);
    }

    const odd = pe.sections.filter((s) => !STANDARD_SECTIONS.has(s.name) && !PACKER_SECTIONS[s.name]);
    if (odd.length) add('low', 5, 'Non-standard section names', odd.map((s) => JSON.stringify(s.name)).join(', '));

    if (!pe.isDotNet) {
      const funcs = pe.imports.flatMap((d) => d.functions);
      if (pe.importCount === 0) add('high', 20, 'No import table', 'The binary imports nothing — it must resolve every API at runtime, which is a strong packing/obfuscation sign.');
      else if (pe.importCount < 10) {
        const onlyLoader = funcs.some((f) => /^(LoadLibrary|GetProcAddress)/.test(f));
        add(onlyLoader ? 'high' : 'medium', onlyLoader ? 20 : 10, `Tiny import table (${pe.importCount} functions)`, (onlyLoader ? 'Includes LoadLibrary/GetProcAddress — classic packer stub that rebuilds imports at runtime. ' : '') + funcs.slice(0, 15).join(', '));
      }
    } else {
      add('info', 0, '.NET assembly', 'Managed code. Obfuscators like ConfuserEx encrypt the #US string heap; v1 does not parse .NET metadata yet, so use dnSpy/de4dot for deeper analysis.');
    }

    if (pe.overlay && pe.overlay.size > 1024) {
      const hi = pe.overlay.entropy > 7.2;
      add(hi ? 'medium' : 'low', hi ? 15 : 5, 'Overlay data', `${pe.overlay.size.toLocaleString()} bytes after the last section at ${hex8(pe.overlay.offset)}, entropy ${pe.overlay.entropy}. Installers and signed files have overlays too; high entropy can mean an appended payload.`);
    }

    const now = Date.now() / 1000;
    if (pe.timestamp === 0) add('low', 3, 'Zeroed compile timestamp', 'Timestamp stripped — common with reproducible builds, but also with tampered binaries.');
    else if (pe.timestamp > now + 86400) add('low', 5, 'Compile timestamp in the future', new Date(pe.timestamp * 1000).toISOString());
  }

  // String density: legit binaries are full of readable text
  const strBytes = strs.list.reduce((a, s) => a + s.value.length, 0);
  const density = b.length ? strBytes / b.length : 0;
  if (b.length > 8192 && density < 0.02) add('medium', 15, 'Very low string density', `Only ${(density * 100).toFixed(2)}% of the file is readable strings. Normal binaries are usually 5–25%.`);

  if (fileEntropy > 7.5 && !pe.isPE) add('medium', 10, 'Whole-file entropy very high', `Entropy ${fileEntropy.toFixed(3)} — file is compressed or encrypted.`);

  if (apiInfo.stringOnly.length >= 3) add('medium', 15, `${apiInfo.stringOnly.length} suspicious API names stored as strings`, 'These APIs appear as plain strings but are not in the import table, which suggests they are resolved dynamically via GetProcAddress to hide intent: ' + apiInfo.stringOnly.slice(0, 20).join(', '));

  const textDecoded = decoded.filter((d) => !d.magic);
  if (textDecoded.length) {
    const methods = [...new Set(textDecoded.map((d) => d.method.split(' → ')[0].split(' ')[0]))];
    add('high', 20, `${textDecoded.length} encoded string(s) recovered`, `Recovered via ${methods.join(', ')}. Hiding strings is deliberate — legitimate software rarely does this.`);
  }
  if (xorPEs.length) add('high', 30, 'XOR-encoded executable inside file', xorPEs.map((x) => `${x.method} near ${hex8(x.origin)}`).join('; ') + ' — likely a dropper carrying an encrypted second stage.');
  if (embedded.length) add('medium', 15, `Embedded PE file(s) (${embedded.length})`, embedded.map((e) => hex8(e.offset)).join(', ') + ' — another executable is stored inside this one.');
  const b64PE = decoded.filter((d) => d.magic && !d.magic.startsWith('XOR'));
  if (b64PE.length) add('high', 20, 'Encoded binary payload', b64PE.map((d) => `${d.magic} via ${d.method}`).join('; '));

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  F.sort((a, c) => order[a.severity] - order[c.severity] || c.points - a.points);
  const score = Math.min(100, F.reduce((a, f) => a + f.points, 0));
  const verdict = score >= 50 ? 'Likely obfuscated / packed' : score >= 20 ? 'Some obfuscation indicators' : 'No strong obfuscation indicators';
  return { findings: F, score, verdict };
}

// ---------------------------------------------------------------- main

function analyze(b, progress = () => {}) {
  const t0 = Date.now();
  progress({ stage: 'Parsing headers' });
  const pe = parsePE(b);
  const fileEntropy = entropy(b);
  const chart = entropyChart(b);

  progress({ stage: 'Extracting strings' });
  const strs = extractStrings(b);
  const plainSet = new Set(strs.list.map((s) => s.value));

  progress({ stage: 'Extracting IOCs' });
  const iocMap = new Map();
  const addIoc = (ioc, source, offset, method) => {
    const key = ioc.type + '|' + ioc.value;
    if (iocMap.has(key)) return;
    iocMap.set(key, { ...ioc, defanged: defang(ioc), source, offset, method });
  };
  for (const s of strs.list) for (const i of findIocs(s.value)) addIoc(i, 'plain', s.offset);

  progress({ stage: 'Checking API usage' });
  const imported = new Set(pe.isPE ? pe.imports.flatMap((d) => d.functions) : []);
  const apiInfo = { imported: [], stringOnly: [] };
  for (const f of imported) if (API_TO_GROUP.has(f)) apiInfo.imported.push({ name: f, group: API_TO_GROUP.get(f) });
  const seenApi = new Set();
  for (const s of strs.list) {
    if (s.value.length > 40) continue;
    const v = s.value.trim();
    if (API_TO_GROUP.has(v) && !imported.has(v) && !seenApi.has(v)) {
      seenApi.add(v);
      apiInfo.stringOnly.push(v);
    }
  }

  progress({ stage: 'Decoding base64 / hex layers' });
  let decoded = [];
  for (const s of strs.list) {
    if (s.value.length < 16) continue;
    peel(s.value, [], 0, decoded, s.offset);
  }
  progress({ stage: 'Trying ROT13 / reversed strings' });
  for (const s of strs.list) {
    if (s.value.length < 8) continue;
    const base = textScore(s.value).iocs.length;
    for (const [name, fn] of [['rot13', rot13], ['reverse', (x) => [...x].reverse().join('')]]) {
      const t = fn(s.value);
      const sc = textScore(t);
      // These transforms are cheap and noisy on random bytes, so demand a strong score.
      if (sc.score >= 60 && sc.iocs.length > base && !plainSet.has(t)) decoded.push({ origin: s.offset, method: name, value: t, score: sc.score, iocs: sc.iocs });
    }
  }

  progress({ stage: 'Brute-forcing single-byte XOR' });
  const xr = xorScan(b);
  const xorPEs = xr.filter((x) => x.magic);
  decoded = decoded.concat(xr.filter((x) => x.magic || x.score >= 20));

  progress({ stage: 'Looking for embedded executables' });
  const embedded = findEmbeddedPEs(b);

  // Dedupe decoded by value, drop anything that already exists in plaintext.
  const seen = new Set();
  decoded = decoded.filter((d) => {
    if ((!d.magic && plainSet.has(d.value)) || seen.has(d.method + d.value)) return false;
    seen.add(d.method + d.value);
    return true;
  }).sort((a, c) => c.score - a.score).slice(0, LIMITS.maxDecoded);
  for (const d of decoded) for (const i of d.iocs) addIoc(i, 'decoded', d.origin, d.method);

  progress({ stage: 'Scoring' });
  const verdict = buildFindings(b, pe, strs, decoded, embedded, xorPEs, apiInfo, fileEntropy);

  const iocs = [...iocMap.values()].sort((a, c) => (a.benign ? 1 : 0) - (c.benign ? 1 : 0) || (a.source === 'decoded' ? -1 : 1) - (c.source === 'decoded' ? -1 : 1));

  return {
    version: '1.0.0',
    size: b.length,
    entropy: +fileEntropy.toFixed(3),
    chart,
    pe,
    ...verdict,
    strings: strs.list,
    stringsTruncated: strs.truncated,
    iocs,
    decoded,
    embedded,
    apis: apiInfo,
    elapsedMs: Date.now() - t0,
  };
}

// ---------------------------------------------------------------- wiring

if (typeof self !== 'undefined' && typeof window === 'undefined' && typeof self.postMessage === 'function') {
  self.onmessage = (e) => {
    try {
      const res = analyze(new Uint8Array(e.data.buffer), (p) => self.postMessage({ type: 'progress', ...p }));
      self.postMessage({ type: 'result', result: res });
    } catch (err) {
      self.postMessage({ type: 'error', message: String((err && err.message) || err) });
    }
  };
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyze, parsePE, entropy, extractStrings, findIocs, defang, b64decode, xorScan, textScore };
}
