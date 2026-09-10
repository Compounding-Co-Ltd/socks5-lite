// socks5.js — a very lightweight, zero-dependency SOCKS5 + HTTP CONNECT proxy.
//
// One listener serves BOTH protocols (auto-detected by the first byte: SOCKS5 = 0x05,
// HTTP = an ASCII method like CONNECT/GET). Traffic egresses via this host's network.
//
// Access control (same for both protocols), in order:
//   1) ban check     — fail2ban: IPs with too many auth failures are blocked for a while
//   2) trusted CIDRs — sources in the trusted ranges (+localhost) are allowed with no auth
//   3) whitelist     — (optional, toggleable) only listed IPs/CIDR/wildcards may proceed
//   4) auth (token)  — (optional) other sources authenticate:
//        · SOCKS5 → username/password (RFC 1929)
//        · HTTP   → Proxy-Authorization: Basic (Playwright handles this automatically)
//
// With no config.json present: trusted-CIDR-only, no auth, fail2ban on.
// Config is read from config.json next to this file (or $PROXY_CONFIG) and hot-reloaded.
'use strict';
const net = require('net');
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = process.env.PROXY_CONFIG || path.join(__dirname, 'config.json');
const DEFAULT_TRUSTED = ['100.64.0.0/10']; // CGNAT/private overlay range; override via config

function loadConfig() {
  let c = {};
  try { c = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch { c = {}; }
  const auth = c.auth || {}, wl = c.whitelist || {}, f2b = c.fail2ban || {}, tr = c.trusted || {};
  return {
    host: process.env.PROXY_HOST || c.host || '0.0.0.0',
    port: parseInt(process.env.PROXY_PORT || c.port || 1080, 10),
    trusted: {
      allow: tr.allow !== false,
      cidrs: Array.isArray(tr.cidrs) && tr.cidrs.length ? tr.cidrs : DEFAULT_TRUSTED,
    },
    auth: {
      enabled: !!auth.enabled,
      username: auth.username || process.env.PROXY_USER || 'user',
      password: process.env.PROXY_TOKEN || auth.password || '',
    },
    whitelist: { enabled: !!wl.enabled, entries: Array.isArray(wl.entries) ? wl.entries : [] },
    fail2ban: {
      enabled: f2b.enabled !== false,
      maxFails: f2b.maxFails || 5,
      windowSec: f2b.windowSec || 600,
      banSec: f2b.banSec || 3600,
    },
  };
}

let CFG = loadConfig();
try {
  fs.watchFile(CONFIG_PATH, { interval: 3000 }, () => {
    CFG = loadConfig();
    log(`config reloaded (auth=${CFG.auth.enabled} whitelist=${CFG.whitelist.enabled}/${CFG.whitelist.entries.length} f2b=${CFG.fail2ban.enabled})`);
  });
} catch { /* config 없어도 기본값으로 동작 */ }

function log(...a) { console.log(new Date().toISOString(), ...a); }

// ─── IP helpers ───────────────────────────────────────────────────────────────
function normalizeIp(ip) { if (!ip) return ''; return ip.startsWith('::ffff:') ? ip.slice(7) : ip; }
function ipToLong(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return null;
  return (((+m[1]) * 256 + (+m[2])) * 256 + (+m[3])) * 256 + (+m[4]);
}
function matchEntry(ip, entry) {
  entry = String(entry).trim();
  if (!entry) return false;
  if (entry.includes('/')) {
    const [base, bitsStr] = entry.split('/');
    const bits = parseInt(bitsStr, 10);
    const bl = ipToLong(base), il = ipToLong(ip);
    if (bl == null || il == null || !(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return ((bl & mask) >>> 0) === ((il & mask) >>> 0);
  }
  if (entry.includes('*')) {
    const re = new RegExp('^' + entry.split('.').map((o) => (o === '*' ? '\\d{1,3}' : o.replace(/[^\d]/g, ''))).join('\\.') + '$');
    return re.test(ip);
  }
  return entry === ip;
}
function inTrusted(ip) { return CFG.trusted.cidrs.some((c) => matchEntry(ip, c)); }
function inWhitelist(ip) { return CFG.whitelist.entries.some((e) => matchEntry(ip, e)); }

// ─── fail2ban ───────────────────────────────────────────────────────────────
const fails = new Map();
function isBanned(ip) { const r = fails.get(ip); return !!(r && r.bannedUntil > Date.now()); }
function recordFail(ip) {
  if (!CFG.fail2ban.enabled) return;
  const now = Date.now();
  const r = fails.get(ip) || { times: [], bannedUntil: 0 };
  r.times = r.times.filter((t) => now - t < CFG.fail2ban.windowSec * 1000);
  r.times.push(now);
  if (r.times.length >= CFG.fail2ban.maxFails) { r.bannedUntil = now + CFG.fail2ban.banSec * 1000; r.times = []; log(`fail2ban: BAN ${ip} for ${CFG.fail2ban.banSec}s`); }
  fails.set(ip, r);
}
function recordSuccess(ip) { fails.delete(ip); }
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of fails) {
    const lastFail = r.times.length ? r.times[r.times.length - 1] : 0;
    if (r.bannedUntil < now && now - lastFail > CFG.fail2ban.windowSec * 1000) fails.delete(ip);
  }
}, 60000).unref();

// ─── access decision ──────────────────────────────────────────────────────────
function gate(ip) {
  if (isBanned(ip)) return 'reject';
  const trusted = CFG.trusted.allow && (inTrusted(ip) || ip === '127.0.0.1' || ip === '::1');
  if (trusted) return 'noauth';
  if (CFG.whitelist.enabled && !inWhitelist(ip)) return 'reject';
  if (CFG.auth.enabled) return 'auth';
  return 'noauth';
}

function pipeConnect(client, host, port, pre, onOk, onFail) {
  const remote = net.connect(port, host, () => {
    onOk(remote);
    if (pre && pre.length) remote.write(pre);
    remote.pipe(client); client.pipe(remote);
  });
  remote.setNoDelay(true);
  remote.on('error', () => { try { onFail(); } catch {} });
  client.on('error', () => remote.destroy());
  client.on('close', () => remote.destroy());
}

// ─── SOCKS5 ─────────────────────────────────────────────────────────────────
function handleSocks(client, first, mode, rip) {
  let stage = 0, buf = first;
  const onData = (chunk) => {
    if (stage === 3) return;
    if (chunk.length) buf = Buffer.concat([buf, chunk]);

    if (stage === 0) {
      if (buf.length < 2) return;
      if (buf[0] !== 0x05) { client.end(); return; }
      const n = buf[1];
      if (buf.length < 2 + n) return;
      const methods = buf.slice(2, 2 + n);
      buf = buf.slice(2 + n);
      if (mode === 'auth') {
        if (methods.includes(0x02)) { client.write(Buffer.from([0x05, 0x02])); stage = 1; }
        else { client.write(Buffer.from([0x05, 0xFF])); client.end(); return; }
      } else { client.write(Buffer.from([0x05, 0x00])); stage = 2; }
    }
    if (stage === 1) {
      if (buf.length < 2 || buf[0] !== 0x01) { if (buf.length >= 1 && buf[0] !== 0x01) client.end(); return; }
      const ulen = buf[1];
      if (buf.length < 2 + ulen + 1) return;
      const uname = buf.slice(2, 2 + ulen).toString('utf8');
      const plen = buf[2 + ulen];
      if (buf.length < 2 + ulen + 1 + plen) return;
      const passwd = buf.slice(3 + ulen, 3 + ulen + plen).toString('utf8');
      buf = buf.slice(3 + ulen + plen);
      const ok = uname === CFG.auth.username && passwd === CFG.auth.password && CFG.auth.password.length > 0;
      if (!ok) { client.write(Buffer.from([0x01, 0x01])); recordFail(rip); client.end(); return; }
      client.write(Buffer.from([0x01, 0x00])); recordSuccess(rip); stage = 2;
    }
    if (stage === 2) {
      if (buf.length < 4) return;
      if (buf[0] !== 0x05) { client.end(); return; }
      const cmd = buf[1], atyp = buf[3];
      let host, offset;
      if (atyp === 0x01) { if (buf.length < 10) return; host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`; offset = 8; }
      else if (atyp === 0x03) { const len = buf[4]; if (buf.length < 5 + len + 2) return; host = buf.slice(5, 5 + len).toString('utf8'); offset = 5 + len; }
      else if (atyp === 0x04) { if (buf.length < 22) return; const p = []; for (let i = 0; i < 16; i += 2) p.push(buf.readUInt16BE(4 + i).toString(16)); host = p.join(':'); offset = 20; }
      else { client.end(); return; }
      const port = buf.readUInt16BE(offset);
      buf = Buffer.alloc(0);
      if (cmd !== 0x01) { client.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); client.end(); return; }
      stage = 3;
      pipeConnect(client, host, port, null,
        () => client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])),
        () => { try { client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch {} client.end(); });
    }
  };
  client.on('data', onData);
  onData(Buffer.alloc(0));
}

// ─── HTTP proxy (CONNECT + absolute-form) ─────────────────────────────────────
function handleHttp(client, first, mode, rip) {
  let buf = first, done = false;
  const onData = (chunk) => {
    if (done) return;
    if (chunk.length) buf = Buffer.concat([buf, chunk]);
    const headEnd = buf.indexOf('\r\n\r\n');
    if (headEnd === -1) { if (buf.length > 65536) client.destroy(); return; }
    done = true;
    client.removeListener('data', onData);

    const lines = buf.slice(0, headEnd).toString('utf8').split('\r\n');
    const rest = buf.slice(headEnd + 4);
    const [method, target, version] = (lines[0] || '').split(' ');
    const headers = {};
    for (let i = 1; i < lines.length; i++) { const idx = lines[i].indexOf(':'); if (idx > 0) headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim(); }

    // auth (challenge-response)
    if (mode === 'auth') {
      const m = /^Basic\s+(.+)$/i.exec(headers['proxy-authorization'] || '');
      let ok = false;
      if (m) {
        const dec = Buffer.from(m[1], 'base64').toString('utf8');
        const i = dec.indexOf(':');
        ok = dec.slice(0, i) === CFG.auth.username && dec.slice(i + 1) === CFG.auth.password && CFG.auth.password.length > 0;
        if (!ok) recordFail(rip);   // 자격증명은 왔는데 틀림 → 실패로 카운트
      }
      if (!ok) {
        // 자격증명 없음(정상 첫 요청) 또는 틀림 → 407 챌린지. 클라가 창(자격증명) 붙여 재시도.
        client.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        client.end();
        return;
      }
      recordSuccess(rip);
    }

    if ((method || '').toUpperCase() === 'CONNECT') {          // HTTPS/WSS 터널
      const [host, portStr] = target.split(':');
      const port = parseInt(portStr, 10) || 443;
      let established = false;
      pipeConnect(client, host, port, rest,
        () => { established = true; client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); },
        () => { if (!established) { try { client.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'); } catch {} } client.end(); });
    } else {                                                    // 평문 HTTP absolute-form
      let u; try { u = new URL(target); } catch { client.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return; }
      const host = u.hostname, port = parseInt(u.port, 10) || 80;
      const reqLine = `${method} ${u.pathname}${u.search} ${version || 'HTTP/1.1'}`;
      const keep = lines.slice(1).filter((l) => { const k = l.split(':')[0].trim().toLowerCase(); return k !== 'proxy-authorization' && k !== 'proxy-connection'; });
      const outHead = Buffer.from([reqLine, ...keep, '', ''].join('\r\n'));
      pipeConnect(client, host, port, Buffer.concat([outHead, rest]),
        () => {},
        () => { try { client.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'); } catch {} client.end(); });
    }
  };
  client.on('data', onData);
  onData(Buffer.alloc(0));
}

// ─── listener (protocol auto-detect) ──────────────────────────────────────────
const server = net.createServer((client) => {
  const rip = normalizeIp(client.remoteAddress);
  const mode = gate(rip);
  if (mode === 'reject') { client.destroy(); return; }
  client.on('error', () => {});
  client.once('data', (first) => {
    if (!first || !first.length) { client.end(); return; }
    if (first[0] === 0x05) handleSocks(client, first, mode, rip);   // SOCKS5
    else handleHttp(client, first, mode, rip);                       // HTTP
  });
});

server.on('error', (e) => { log('SERVER ERROR', e.message); process.exit(1); });
server.listen(CFG.port, CFG.host, () => log(
  `SOCKS5+HTTP on ${CFG.host}:${CFG.port} | trusted=${CFG.trusted.allow}(${CFG.trusted.cidrs.length}) ` +
  `auth=${CFG.auth.enabled} whitelist=${CFG.whitelist.enabled}(${CFG.whitelist.entries.length}) fail2ban=${CFG.fail2ban.enabled}`,
));
