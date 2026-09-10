// office-socks.js — zero-dependency SOCKS5 (CONNECT) proxy for the office Windows box.
// Egress goes out this machine's network (office IP). Access is restricted to the
// Tailscale CGNAT range (100.64.0.0/10) plus localhost, as defense-in-depth on top
// of the Windows Firewall rule. No authentication (tailnet is private).
'use strict';
const net = require('net');

const HOST = process.env.PROXY_HOST || '0.0.0.0';
const PORT = parseInt(process.env.PROXY_PORT || '1080', 10);

function normalizeIp(ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}
function allowed(ip) {
  ip = normalizeIp(ip);
  if (ip === '127.0.0.1' || ip === '::1') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  return a === 100 && b >= 64 && b <= 127; // 100.64.0.0/10 (Tailscale)
}

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

const server = net.createServer((client) => {
  const rip = normalizeIp(client.remoteAddress);
  if (!allowed(rip)) { client.destroy(); return; }
  client.on('error', () => {});

  let stage = 0;           // 0 = greeting, 1 = request, 2 = piping
  let buf = Buffer.alloc(0);

  client.on('data', (chunk) => {
    if (stage === 2) return;
    buf = Buffer.concat([buf, chunk]);

    if (stage === 0) {
      if (buf.length < 2) return;
      if (buf[0] !== 0x05) { client.end(); return; }
      const n = buf[1];
      if (buf.length < 2 + n) return;
      buf = buf.slice(2 + n);
      client.write(Buffer.from([0x05, 0x00])); // no-auth
      stage = 1;
    }

    if (stage === 1) {
      if (buf.length < 4) return;
      if (buf[0] !== 0x05) { client.end(); return; }
      const cmd = buf[1], atyp = buf[3];
      let host, offset;
      if (atyp === 0x01) {                    // IPv4
        if (buf.length < 10) return;
        host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
        offset = 8;
      } else if (atyp === 0x03) {             // domain
        const len = buf[4];
        if (buf.length < 5 + len + 2) return;
        host = buf.slice(5, 5 + len).toString('utf8');
        offset = 5 + len;
      } else if (atyp === 0x04) {             // IPv6
        if (buf.length < 22) return;
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(4 + i).toString(16));
        host = parts.join(':');
        offset = 20;
      } else { client.end(); return; }

      const port = buf.readUInt16BE(offset);
      buf = Buffer.alloc(0);

      if (cmd !== 0x01) { // only CONNECT
        client.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        client.end();
        return;
      }

      const remote = net.connect(port, host, () => {
        client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        stage = 2;
        remote.pipe(client);
        client.pipe(remote);
      });
      remote.setNoDelay(true);
      remote.on('error', () => {
        try { client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch (e) {}
        client.end();
      });
      client.on('error', () => remote.destroy());
      client.on('close', () => remote.destroy());
    }
  });
});

server.on('error', (e) => { log('SERVER ERROR', e.message); process.exit(1); });
server.listen(PORT, HOST, () => log(`SOCKS5 listening on ${HOST}:${PORT} (tailnet-only)`));
