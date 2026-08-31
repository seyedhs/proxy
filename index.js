// ============================================================================
// index.js - نسخه مستقل برای اجرا در GitHub Actions (بدون Cloudflare)
// با پشتیبانی از ساب‌لینک‌های URL و کش جغرافیایی
// ============================================================================

const fs = require('fs').promises;
const path = require('path');

// ---------- ابزارهای عمومی ----------
function b64EncodeUnicode(str) {
  return Buffer.from(str, 'utf-8').toString('base64');
}

function b64DecodeUnicode(b64) {
  return Buffer.from(b64, 'base64').toString('utf-8');
}

function looksLikeBase64Blob(text) {
  const t = text.trim();
  if (t.length < 40) return false;
  if (/[<>]/.test(t)) return false;
  return /^[A-Za-z0-9+/_=\s\-]+$/.test(t.slice(0, 200));
}

const FA_DIGITS = ["۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹"];
function toPersianNumber(n) {
  return String(n).split('').map(d => /\d/.test(d) ? FA_DIGITS[+d] : d).join('');
}

function formatNumber(n, style) {
  return style === 'en' ? String(n) : toPersianNumber(n);
}

const FLAG_BASE = 0x1f1e6;
function countryCodeToFlag(cc) {
  if (!cc || cc.length !== 2 || cc === 'XX') return '';
  cc = cc.toUpperCase();
  const codePoints = [...cc].map(c => FLAG_BASE + (c.charCodeAt(0) - 65));
  return String.fromCodePoint(...codePoints);
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const current = idx++;
      try {
        results[current] = await fn(items[current], current);
      } catch (e) {
        results[current] = { __error: e.message };
      }
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

// ---------- پارسرها ----------
function safeDecodeURIComponent(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}

function parseConfigLink(rawLine) {
  const raw = rawLine.trim();
  if (!raw) return null;
  try {
    if (raw.startsWith('vmess://')) return parseVmess(raw);
    if (raw.startsWith('vless://')) return parseGenericUri(raw, 'vless');
    if (raw.startsWith('trojan://')) return parseGenericUri(raw, 'trojan');
    if (raw.startsWith('hysteria2://')) return parseGenericUri(raw, 'hysteria2');
    if (raw.startsWith('hy2://')) return parseGenericUri(raw.replace('hy2://', 'hysteria2://'), 'hysteria2');
    if (raw.startsWith('ss://')) return parseShadowsocks(raw);
  } catch (e) { return null; }
  return null;
}

function parseGenericUri(raw, protocol) {
  const hashIdx = raw.indexOf('#');
  const remark = hashIdx >= 0 ? safeDecodeURIComponent(raw.slice(hashIdx + 1)) : '';
  const withoutHash = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  const u = new URL(withoutHash);
  const server = u.hostname.replace(/^\[|\]$/g, '');
  const port = u.port || (protocol === 'trojan' || protocol === 'hysteria2' ? '443' : '443');
  const userinfo = safeDecodeURIComponent(u.username || '');
  const params = {};
  for (const [k, v] of u.searchParams.entries()) params[k] = v;
  return { protocol, userinfo, server, port, params, remark, raw };
}

function parseVmess(raw) {
  const b64 = raw.slice('vmess://'.length).trim();
  let json;
  try {
    json = JSON.parse(b64DecodeUnicode(b64));
  } catch (e) {
    return parseGenericUri(raw, 'vmess');
  }
  return { protocol: 'vmess', vmessJson: json, remark: json.ps || '', raw };
}

function parseShadowsocks(raw) {
  const hashIdx = raw.indexOf('#');
  const remark = hashIdx >= 0 ? safeDecodeURIComponent(raw.slice(hashIdx + 1)) : '';
  const body = raw.slice('ss://'.length, hashIdx >= 0 ? hashIdx : undefined);
  let server, port, method, password;
  let params = {};
  const atIdx = body.lastIndexOf('@');
  if (atIdx >= 0) {
    const userinfoRaw = decodeURIComponent(body.slice(0, atIdx));
    let userinfo;
    try { userinfo = b64DecodeUnicode(userinfoRaw); } catch (e) { userinfo = userinfoRaw; }
    const colonIdx = userinfo.indexOf(':');
    method = userinfo.slice(0, colonIdx);
    password = userinfo.slice(colonIdx + 1);
    let rest = body.slice(atIdx + 1);
    const qIdx = rest.indexOf('?');
    const hostport = qIdx >= 0 ? rest.slice(0, qIdx) : rest;
    if (qIdx >= 0) params = Object.fromEntries(new URLSearchParams(rest.slice(qIdx + 1)));
    const lastColon = hostport.lastIndexOf(':');
    server = hostport.slice(0, lastColon);
    port = hostport.slice(lastColon + 1);
  } else {
    const decoded = b64DecodeUnicode(body);
    const m = decoded.match(/^(.*?):(.*)@(.*):(\d+)$/);
    if (m) { method = m[1]; password = m[2]; server = m[3]; port = m[4]; }
  }
  return { protocol: 'ss', method, password, server, port, params, remark, raw };
}

function rebuildLink(cfg, newRemark) {
  if (cfg.protocol === 'vmess') {
    const json = { ...cfg.vmessJson, ps: newRemark };
    return 'vmess://' + b64EncodeUnicode(JSON.stringify(json));
  }
  if (cfg.protocol === 'ss') {
    const userinfo = b64EncodeUnicode(`${cfg.method}:${cfg.password}`);
    const qs = new URLSearchParams(cfg.params || {}).toString();
    return `ss://${encodeURIComponent(userinfo)}@${cfg.server}:${cfg.port}${qs ? '?' + qs : ''}#${encodeURIComponent(newRemark)}`;
  }
  const qs = new URLSearchParams(cfg.params || {}).toString();
  return `${cfg.protocol}://${encodeURIComponent(cfg.userinfo)}@${cfg.server}:${cfg.port}${qs ? '?' + qs : ''}#${encodeURIComponent(newRemark)}`;
}

function getHostForGeo(cfg) {
  if (cfg.protocol === 'vmess') return cfg.vmessJson.add;
  return cfg.server;
}

function isCloudflareWorkerConfig(cfg) {
  if (!['vless', 'trojan'].includes(cfg.protocol)) return false;
  const p = cfg.params || {};
  const net = p.type || p.net || 'tcp';
  const isWs = net === 'ws';
  const isTls = (p.security || '') === 'tls';
  const sni = (p.sni || p.host || '').toLowerCase();
  return isWs && isTls && sni.endsWith('workers.dev');
}

function cloneWithServer(cfg, newServer, newPort) {
  return { ...cfg, server: newServer, port: newPort || cfg.port, params: { ...cfg.params } };
}

function parsePlainProxyLine(rawLine, kind) {
  const raw = rawLine.trim();
  if (!raw) return null;
  let remark = '';
  let body = raw;
  const hashIdx = raw.indexOf('#');
  if (hashIdx >= 0) { remark = safeDecodeURIComponent(raw.slice(hashIdx + 1)); body = raw.slice(0, hashIdx); }
  if (body.includes('://')) {
    try {
      const u = new URL(body);
      return { protocol: kind, server: u.hostname, port: u.port, username: safeDecodeURIComponent(u.username || ''), password: safeDecodeURIComponent(u.password || ''), remark, raw };
    } catch (e) {}
  }
  if (body.includes('@')) {
    const [cred, hostport] = body.split('@');
    const [username, password] = cred.split(':');
    const [server, port] = hostport.split(':');
    return { protocol: kind, server, port, username, password, remark, raw };
  }
  const parts = body.split(':');
  if (parts.length === 2) {
    return { protocol: kind, server: parts[0], port: parts[1], username: '', password: '', remark, raw };
  }
  if (parts.length === 4) {
    return { protocol: kind, server: parts[0], port: parts[1], username: parts[2], password: parts[3], remark, raw };
  }
  return null;
}

function rebuildPlainProxyLine(cfg, newRemark) {
  const scheme = cfg.protocol === 'socks5' ? 'socks5' : 'http';
  const auth = cfg.username ? `${encodeURIComponent(cfg.username)}:${encodeURIComponent(cfg.password)}@` : '';
  return `${scheme}://${auth}${cfg.server}:${cfg.port}#${encodeURIComponent(newRemark)}`;
}

// ---------- Geo (با کش پایدار در .state/ که بین اجراهای Actions کامیت می‌شه) ----------
const STATE_DIR = '.state';
const GEO_CACHE_FILE = `${STATE_DIR}/geo-cache.json`;
let geoCache = {};

const IPINFO_TOKEN = process.env.IPINFO_TOKEN || '';
const GEO_CONCURRENCY = Number(process.env.GEO_CONCURRENCY) || 8;
const GEO_TIMEOUT_MS = Number(process.env.GEO_TIMEOUT_MS) || 8000;
// سقف پیش‌فرض تعداد کانفیگ هر خروجی وقتی output.maxCount توی config.json مشخص نشده باشه.
// هر خروجی می‌تونه با گذاشتن "maxCount" مخصوص خودش این پیش‌فرض رو override کنه (۰ یا منفی = بدون سقف).
const DEFAULT_MAX_COUNT = Number(process.env.DEFAULT_MAX_COUNT) || 100;

async function loadGeoCache() {
  try {
    const data = await fs.readFile(GEO_CACHE_FILE, 'utf-8');
    geoCache = JSON.parse(data);
  } catch (e) { geoCache = {}; }
  console.log(`🗂️  کش جغرافیایی بارگذاری شد: ${Object.keys(geoCache).length} آیتم`);
}

async function saveGeoCache() {
  await fs.mkdir(STATE_DIR, { recursive: true });
  await fs.writeFile(GEO_CACHE_FILE, JSON.stringify(geoCache));
}

// ---------- History خروجی‌ها (برای اولویت‌دهی به کانفیگ‌های جدید در maxCount) ----------
const HISTORY_FILE = `${STATE_DIR}/output-history.json`;
let outputHistory = {};

async function loadOutputHistory() {
  try {
    const data = await fs.readFile(HISTORY_FILE, 'utf-8');
    outputHistory = JSON.parse(data);
  } catch (e) { outputHistory = {}; }
}

async function saveOutputHistory() {
  await fs.mkdir(STATE_DIR, { recursive: true });
  await fs.writeFile(HISTORY_FILE, JSON.stringify(outputHistory));
}

// fetch با تایم‌اوت، تا یک درخواست گیرکرده کل پایپ‌لاین رو برای همیشه معلق نکنه
async function fetchWithTimeout(url, options = {}, timeoutMs = GEO_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function extractFlagFromRemark(remark) {
  if (!remark) return null;
  const flagEmojiMatch = remark.match(/[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/);
  if (flagEmojiMatch) {
    const flag = flagEmojiMatch[0];
    const codePoints = [...flag].map(c => c.codePointAt(0) || 0);
    if (codePoints.length === 2) {
      const cc = String.fromCharCode((codePoints[0] - FLAG_BASE) + 65, (codePoints[1] - FLAG_BASE) + 65);
      return { countryCode: cc, flag };
    }
  }
  const bracketMatch = remark.match(/[\[\(]([A-Za-z]{2})[\]\)]/);
  if (bracketMatch) {
    const cc = bracketMatch[1].toUpperCase();
    return { countryCode: cc, flag: countryCodeToFlag(cc) };
  }
  return null;
}

async function resolveHostToIp(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) return host;
  try {
    const res = await fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { accept: 'application/dns-json' }
    });
    if (!res.ok) return host;
    const data = await res.json();
    const ans = (data.Answer || []).find(a => a.type === 1);
    return ans ? ans.data : host;
  } catch (e) {
    console.warn(`   ⚠️ DNS resolve ناموفق برای ${host}: ${e.message}`);
    return host;
  }
}

// اگر IPINFO_TOKEN در سیکرت‌ها ست شده باشه اول از ipinfo.io استفاده می‌کنه (محدودیت بسیار بالاتر)
// و فقط اگر توکن نبود یا شکست خورد، می‌ره سراغ ip-api.com به‌عنوان fallback

// ip-api.com رایگان سقف ~۴۵ درخواست/دقیقه داره؛ روی رانرهای گیت‌هاب با IP مشترک این سقف
// خیلی زود پر می‌شه و باعث "fetch failed" / قطع اتصال می‌شه. این صف، صرفاً درخواست‌های
// ip-api رو با فاصله‌ی ثابت جهانی (بین همه‌ی workerهای همزمان) پخش می‌کنه تا زیر سقف بمونیم.
const IP_API_MIN_INTERVAL_MS = Number(process.env.IP_API_MIN_INTERVAL_MS) || 1400; // ~43 در دقیقه
let ipApiQueueTail = Promise.resolve();
let lastIpApiCallAt = 0;
function scheduleIpApiSlot() {
  const slot = ipApiQueueTail.then(async () => {
    const wait = Math.max(0, lastIpApiCallAt + IP_API_MIN_INTERVAL_MS - Date.now());
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    lastIpApiCallAt = Date.now();
  });
  ipApiQueueTail = slot;
  return slot;
}

async function lookupCountryCode(ip) {
  if (IPINFO_TOKEN) {
    try {
      const res = await fetchWithTimeout(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`);
      if (res.status === 429) {
        console.warn(`   ⚠️ ipinfo.io rate-limit شد، fallback به ip-api.com برای ${ip}`);
      } else if (res.status === 401 || res.status === 403) {
        console.warn(`   ⚠️ ipinfo.io توکن را رد کرد (status ${res.status}) — IPINFO_TOKEN را در سیکرت‌های ریپو و در env استپ اجرای اسکریپت در workflow چک کن. fallback به ip-api.com برای ${ip}`);
      } else if (res.ok) {
        const data = await res.json();
        if (data.country) return data.country;
        console.warn(`   ⚠️ پاسخ ipinfo.io برای ${ip} فیلد country نداشت، fallback به ip-api.com`);
      } else {
        console.warn(`   ⚠️ ipinfo.io پاسخ غیرمنتظره برای ${ip}: status ${res.status}، fallback به ip-api.com`);
      }
    } catch (e) {
      console.warn(`   ⚠️ ipinfo.io خطا برای ${ip}: ${e.message}`);
    }
  } else {
    console.warn(`   ⚠️ IPINFO_TOKEN در محیط اجرا خالی است — مستقیم به ip-api.com می‌رود. اگر توکن را در GitHub Secrets ست کرده‌ای، مطمئن شو که در workflow زیر "env:" همون استپی که node index.js رو اجرا می‌کنه هم پاس داده شده: IPINFO_TOKEN: \${{ secrets.IPINFO_TOKEN }}`);
  }
  try {
    await scheduleIpApiSlot();
    const res = await fetchWithTimeout(`http://ip-api.com/json/${ip}?fields=countryCode,status`);
    if (!res.ok) return 'XX';
    const data = await res.json();
    if (data.status === 'success' && data.countryCode) return data.countryCode;
  } catch (e) {
    console.warn(`   ⚠️ ip-api.com خطا برای ${ip}: ${e.message}`);
  }
  return 'XX';
}

async function getCountryAndFlag(cfg, identityKey) {
  const extracted = extractFlagFromRemark(cfg.remark);
  if (extracted) {
    geoCache[identityKey] = extracted.countryCode;
    return extracted;
  }
  if (geoCache[identityKey]) {
    const cc = geoCache[identityKey];
    return { countryCode: cc, flag: countryCodeToFlag(cc) };
  }
  const host = getHostForGeo(cfg);
  const ip = await resolveHostToIp(host);
  const cc = await lookupCountryCode(ip);
  if (cc !== 'XX') {
    geoCache[identityKey] = cc;
  }
  return { countryCode: cc, flag: countryCodeToFlag(cc) };
}

// ---------- توابع دریافت از ساب‌لینک‌ها ----------
async function fetchText(url) {
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': 'Mozilla/5.0 (cf-proxy-worker)' }
    });
    if (!res.ok) return '';
    return await res.text();
  } catch (e) {
    return '';
  }
}

function normalizeBody(text) {
  const trimmed = text.trim();
  if (!trimmed) return '';
  const firstLine = trimmed.split('\n')[0];
  const knownPrefixes = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://', 'ss://'];
  const startsKnown = knownPrefixes.some(p => firstLine.startsWith(p));
  if (!startsKnown && looksLikeBase64Blob(trimmed)) {
    try {
      const decoded = b64DecodeUnicode(trimmed.replace(/\s+/g, ''));
      if (knownPrefixes.some(p => decoded.includes(p))) return decoded;
    } catch (e) {}
  }
  return trimmed;
}

async function fetchAndParseVpnGroup(urls) {
  const results = [];
  for (const url of urls) {
    const raw = await fetchText(url);
    const body = normalizeBody(raw);
    if (!body) continue;
    for (const line of body.split('\n')) {
      const cfg = parseConfigLink(line);
      if (cfg) results.push(cfg);
    }
  }
  return results;
}

async function fetchAndParsePlainGroup(urls, kind) {
  const results = [];
  for (const url of urls) {
    const raw = await fetchText(url);
    if (!raw) continue;
    for (const line of raw.split('\n')) {
      const cfg = parsePlainProxyLine(line, kind);
      if (cfg) results.push(cfg);
    }
  }
  return results;
}

// ---------- فرمت‌های خروجی ----------
function buildTxt(numberedConfigs) {
  return numberedConfigs.map(c => rebuildLink(c.cfg, c.remark)).join('\n') + '\n';
}

function buildPlainProxyList(numberedConfigs) {
  return numberedConfigs.map(c => rebuildPlainProxyLine(c.cfg, c.remark)).join('\n') + '\n';
}

function buildStreamSettings(cfg) {
  const p = cfg.params || {};
  const network = p.type || 'tcp';
  const security = p.security || (cfg.protocol === 'trojan' ? 'tls' : 'none');
  const stream = { network, security };

  if (security === 'tls' || security === 'reality') {
    stream.tlsSettings = {
      serverName: p.sni || p.host || cfg.server,
      allowInsecure: p.allowInsecure === '1' || p.insecure === '1',
    };
    if (p.fp) stream.tlsSettings.fingerprint = p.fp;
    if (p.alpn) stream.tlsSettings.alpn = p.alpn.split(',');
  }

  if (network === 'ws') {
    stream.wsSettings = { path: p.path || '/', headers: p.host ? { Host: p.host } : {} };
  } else if (network === 'grpc') {
    stream.grpcSettings = { serviceName: p.serviceName || p.path || '' };
  } else if (network === 'tcp' && p.headerType === 'http') {
    stream.tcpSettings = {
      header: {
        type: 'http',
        request: { path: [p.path || '/'], headers: { Host: [p.host || cfg.server] } },
      },
    };
  }
  return stream;
}

function buildXrayStreamSettingsForLb(cfg) {
  const p = cfg.params || {};
  const network = p.type || p.net || 'tcp';

  // shadowsocks در نمونه‌ی هدف فیلد security نداره، فقط network
  if (cfg.protocol === 'ss') {
    return { network };
  }

  const security = p.security || (cfg.protocol === 'trojan' ? 'tls' : 'none');
  const stream = { network, security };

  if (security === 'reality') {
    stream.realitySettings = {
      serverName: p.sni || p.host || cfg.server,
      publicKey: p.pbk || '',
      shortId: p.sid || '',
      fingerprint: p.fp || 'chrome',
    };
  } else if (security === 'tls') {
    stream.tlsSettings = {
      serverName: p.sni || p.host || cfg.server,
    };
    if (p.fp) stream.tlsSettings.fingerprint = p.fp;
    if (p.alpn) stream.tlsSettings.alpn = p.alpn.split(',');
  }

  if (network === 'ws') {
    stream.wsSettings = { path: p.path || '/', headers: p.host ? { Host: p.host } : {} };
  } else if (network === 'grpc') {
    stream.grpcSettings = { serviceName: p.serviceName || p.path || '' };
  }
  return stream;
}

function buildXrayOutbound(cfg, tag) {
  const p = cfg.params || {};
  const streamSettings = buildXrayStreamSettingsForLb(cfg);

  if (cfg.protocol === 'vless') {
    return {
      protocol: 'vless',
      settings: {
        vnext: [{
          address: cfg.server,
          port: +cfg.port,
          users: [{ id: cfg.userinfo, flow: p.flow || undefined, encryption: p.encryption || 'none', level: 8 }],
        }],
      },
      streamSettings,
      tag,
    };
  }
  if (cfg.protocol === 'trojan') {
    return {
      protocol: 'trojan',
      settings: { servers: [{ address: cfg.server, port: +cfg.port, password: cfg.userinfo, level: 8 }] },
      streamSettings,
      tag,
    };
  }
  if (cfg.protocol === 'vmess') {
    const j = cfg.vmessJson;
    return {
      protocol: 'vmess',
      settings: {
        vnext: [{
          address: j.add,
          port: +j.port,
          users: [{ id: j.id, alterId: +(j.aid || 0), security: j.scy || null, level: 8 }],
        }],
      },
      streamSettings,
      tag,
    };
  }
  if (cfg.protocol === 'ss') {
    return {
      protocol: 'shadowsocks',
      settings: { servers: [{ address: cfg.server, port: +cfg.port, method: cfg.method, password: cfg.password, level: 8 }] },
      streamSettings,
      tag,
    };
  }
  return null;
}

function buildXrayLoadBalanced(numberedConfigs, remarkBase) {
  const outbounds = [];

  numberedConfigs.forEach(({ cfg }, i) => {
    if (cfg.protocol === 'hysteria2') return;
    const tag = `proxy-${i + 1}`;
    const ob = buildXrayOutbound(cfg, tag);
    if (ob) outbounds.push(ob);
  });

  outbounds.push({ protocol: 'freedom', settings: {}, tag: 'direct' });
  outbounds.push({ protocol: 'blackhole', settings: { response: { type: 'http' } }, tag: 'block' });
  outbounds.push({ protocol: 'dns', tag: 'dns-out' });

  return JSON.stringify({
    log: { loglevel: 'warning' },
    remarks: remarkBase,
    dns: {
      servers: [
        'https://dns.google/dns-query',
        'https://cloudflare-dns.com/dns-query',
        { address: '1.1.1.2', domains: ['domain:ir', 'geosite:category-ir'], skipFallback: true, tag: 'domestic-dns' },
      ],
    },
    fakedns: [{ ipPool: '198.18.0.0/15', poolSize: 10000 }],
    inbounds: [{
      port: 10808,
      protocol: 'socks',
      settings: { auth: 'noauth', udp: true, userLevel: 8 },
      sniffing: { destOverride: ['http', 'tls', 'fakedns'], enabled: true, routeOnly: false },
      tag: 'socks',
    }],
    observatory: {
      enableConcurrency: true,
      probeInterval: '3m',
      probeUrl: 'https://www.gstatic.com/generate_204',
      subjectSelector: ['proxy-'],
    },
    outbounds,
    policy: {
      levels: { 8: { connIdle: 300, downlinkOnly: 1, handshake: 4, uplinkOnly: 1 } },
      system: { statsOutboundUplink: true, statsOutboundDownlink: true },
    },
    routing: {
      balancers: [{ selector: ['proxy-'], strategy: { type: 'leastPing' }, tag: 'proxy-round' }],
      domainStrategy: 'AsIs',
      rules: [
        { inboundTag: ['socks'], outboundTag: 'dns-out', port: '53', type: 'field' },
        { ip: ['geoip:private'], outboundTag: 'direct', type: 'field' },
        { domain: ['geosite:private'], outboundTag: 'direct', type: 'field' },
        { domain: ['domain:ir', 'geosite:category-ir'], outboundTag: 'direct', type: 'field' },
        { ip: ['geoip:ir'], outboundTag: 'direct', type: 'field' },
        { inboundTag: ['domestic-dns'], outboundTag: 'direct', type: 'field' },
        { domain: ['geosite:category-ads-all'], outboundTag: 'block', type: 'field' },
        { balancerTag: 'proxy-round', network: 'tcp,udp', type: 'field' },
      ],
    },
  }, null, 2);
}

function singboxTlsBlock(p, fallbackSni, forceEnabled) {
  const security = p.security || '';
  if (security !== 'tls' && security !== 'reality' && !forceEnabled) {
    return { enabled: false };
  }
  const tls = {
    enabled: true,
    server_name: p.sni || p.host || fallbackSni,
  };
  if (security === 'reality') {
    tls.reality = {
      enabled: true,
      public_key: p.pbk || '',
      short_id: p.sid || '',
    };
    tls.utls = { enabled: true, fingerprint: p.fp || 'chrome' };
  } else {
    tls.insecure = p.allowInsecure === '1' || p.insecure === '1';
    if (p.alpn) tls.alpn = p.alpn.split(',');
    if (p.fp) tls.utls = { enabled: true, fingerprint: p.fp };
  }
  return tls;
}

function singboxTransportBlock(p) {
  const net = p.type || p.net || 'tcp';
  if (net === 'ws') {
    return { type: 'ws', path: p.path || '/', headers: p.host ? { Host: p.host } : {} };
  }
  if (net === 'grpc') {
    return { type: 'grpc', service_name: p.serviceName || p.path || '' };
  }
  return {};
}

function buildSingboxOutbound(cfg, tag) {
  const p = cfg.params || {};
  if (cfg.protocol === 'vless') {
    return {
      type: 'vless',
      tag,
      server: cfg.server,
      server_port: +cfg.port,
      uuid: cfg.userinfo,
      flow: p.flow || undefined,
      tls: singboxTlsBlock(p, cfg.server),
      transport: singboxTransportBlock(p),
    };
  }
  if (cfg.protocol === 'trojan') {
    return {
      type: 'trojan',
      tag,
      server: cfg.server,
      server_port: +cfg.port,
      password: cfg.userinfo,
      tls: singboxTlsBlock(p, cfg.server, true),
      transport: singboxTransportBlock(p),
    };
  }
  if (cfg.protocol === 'vmess') {
    const j = cfg.vmessJson;
    return {
      type: 'vmess',
      tag,
      server: j.add,
      server_port: +j.port,
      uuid: j.id,
      security: j.scy || null,
      alter_id: +(j.aid || 0),
      transport: j.net === 'ws' ? { type: 'ws', path: j.path || '/', headers: j.host ? { Host: j.host } : {} } :
                j.net === 'grpc' ? { type: 'grpc', service_name: j.path || '' } : {},
      tls: j.tls === 'tls' ? { enabled: true, server_name: j.sni || j.host || j.add } : { enabled: false },
    };
  }
  if (cfg.protocol === 'hysteria2') {
    return {
      type: 'hysteria2',
      tag,
      server: cfg.server,
      server_port: +cfg.port,
      password: cfg.userinfo,
      tls: { enabled: true, server_name: p.sni || cfg.server, insecure: p.insecure === '1' },
    };
  }
  if (cfg.protocol === 'ss') {
    return {
      type: 'shadowsocks',
      tag,
      server: cfg.server,
      server_port: +cfg.port,
      method: cfg.method,
      password: cfg.password,
    };
  }
  return null;
}

function buildSingbox(numberedConfigs, options = {}, remarkBase) {
  const testInterval = options.testInterval || '10m';
  const urltestName = options.urltestName || 'بهترین پینگ';
  const selectorTag = remarkBase;

  const outbounds = [];
  const tags = [];
  numberedConfigs.forEach(({ cfg, remark }, i) => {
    const tag = remark || `node-${i}`;
    const ob = buildSingboxOutbound(cfg, tag);
    if (ob) {
      outbounds.push(ob);
      tags.push(tag);
    }
  });

  const selectorOutbound = { type: 'selector', tag: selectorTag, outbounds: [...tags, 'direct'] };
  const directOutbound = { type: 'direct', tag: 'direct' };
  const urltestOutbound = {
    type: 'urltest',
    tag: urltestName,
    outbounds: tags,
    url: 'https://www.gstatic.com/generate_204',
    interrupt_exist_connections: false,
    interval: testInterval,
  };

  const ruleSetNames = ['geosite-malware', 'geoip-malware', 'geosite-phishing', 'geoip-phishing', 'geosite-cryptominers', 'geosite-category-ads-all', 'geosite-ir', 'geoip-ir'];
  const ruleSet = ruleSetNames.map(tag => ({
    type: 'remote',
    tag,
    format: 'binary',
    url: `https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/${tag}.srs`,
    download_detour: 'direct',
  }));

  const config = {
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: [
        { type: 'https', server: '8.8.8.8', detour: selectorTag, tag: 'dns-remote' },
        { type: 'udp', server: '8.8.8.8', server_port: 53, tag: 'dns-direct' },
        { type: 'fakeip', tag: 'dns-fake', inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' },
      ],
      rules: [
        { domain: ['raw.githubusercontent.com'], server: 'dns-direct' },
        { clash_mode: 'Direct', server: 'dns-direct' },
        { clash_mode: 'Global', server: 'dns-remote' },
        { type: 'logical', mode: 'and', rules: [{ rule_set: 'geosite-ir' }, { rule_set: 'geoip-ir' }], action: 'route', server: 'dns-direct' },
        { rule_set: ['geosite-malware', 'geosite-phishing', 'geosite-cryptominers', 'geosite-category-ads-all'], action: 'reject' },
        { disable_cache: true, inbound: 'tun-in', query_type: ['A', 'AAAA'], server: 'dns-fake' },
      ],
      strategy: 'ipv4_only',
      independent_cache: true,
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        address: ['172.18.0.1/30', 'fdfe:dcba:9876::1/126'],
        mtu: 9000,
        auto_route: true,
        strict_route: true,
        endpoint_independent_nat: true,
        stack: 'mixed',
      },
      { type: 'mixed', tag: 'mixed-in', listen: '0.0.0.0', listen_port: 2080 },
    ],
    outbounds: [selectorOutbound, directOutbound, urltestOutbound, ...outbounds],
    route: {
      rules: [
        { ip_cidr: '172.18.0.2', action: 'hijack-dns' },
        { clash_mode: 'Direct', outbound: 'direct' },
        { clash_mode: 'Global', outbound: selectorTag },
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        { network: 'udp', action: 'reject' },
        { rule_set: ['geosite-malware', 'geosite-phishing', 'geosite-cryptominers', 'geosite-category-ads-all'], action: 'reject' },
        { rule_set: ['geoip-malware', 'geoip-phishing'], action: 'reject' },
        { rule_set: ['geosite-ir'], action: 'route', outbound: 'direct' },
        { rule_set: ['geoip-ir'], action: 'route', outbound: 'direct' },
      ],
      rule_set: ruleSet,
      auto_detect_interface: true,
      default_domain_resolver: { server: 'dns-direct', strategy: 'prefer_ipv4', rewrite_ttl: 60 },
      final: selectorTag,
    },
    ntp: {
      enabled: true,
      server: 'time.cloudflare.com',
      server_port: 123,
      domain_resolver: 'dns-direct',
      interval: '30m',
      write_to_system: false,
    },
    experimental: {
      cache_file: { enabled: true, store_fakeip: true },
      clash_api: {
        external_controller: '127.0.0.1:9090',
        external_ui: 'ui',
        external_ui_download_url: 'https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip',
        external_ui_download_detour: 'direct',
        default_mode: 'Rule',
      },
    },
  };

  return JSON.stringify(config, null, 4);
}

function yamlNeedsQuote(s) {
  if (s === '') return true;
  if (/^\s|\s$/.test(s)) return true;
  if (/^[-?:,\[\]{}#&*!|>'"%@`]/.test(s)) return true;
  if (/:(\s|$)/.test(s)) return true;
  if (/\s#/.test(s)) return true;
  if (/^(true|false|null|yes|no|on|off|~)$/i.test(s)) return true;
  if (/^-?\d+(\.\d+)?$/.test(s)) return true;
  return false;
}

function yamlStr(v) {
  if (v === undefined || v === null) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  if (!yamlNeedsQuote(s)) return s;
  return "'" + s.replace(/'/g, "''") + "'";
}

function indent(n) { return '  '.repeat(n); }

function buildProxyEntry(cfg, name) {
  const p = cfg.params || {};
  const net = p.type || p.net || 'tcp';

  if (cfg.protocol === 'vless') {
    const security = p.security || '';
    const isReality = security === 'reality';
    const entry = {
      name,
      type: 'vless',
      server: cfg.server,
      port: +cfg.port,
      uuid: cfg.userinfo,
      udp: true,
      tls: security === 'tls' || isReality,
      flow: p.flow || undefined,
      servername: p.sni || p.host || undefined,
    };
    if (isReality) {
      entry['reality-opts'] = { 'public-key': p.pbk || '', 'short-id': p.sid || '' };
    }
    if (p.fp) entry['client-fingerprint'] = p.fp;
    if (net === 'ws') entry['ws-opts'] = { path: p.path || '/', headers: p.host ? { Host: p.host } : undefined };
    if (net === 'grpc') entry['grpc-opts'] = { 'grpc-service-name': p.serviceName || p.path || '' };
    return entry;
  }
  if (cfg.protocol === 'trojan') {
    const entry = {
      name,
      type: 'trojan',
      server: cfg.server,
      port: +cfg.port,
      password: cfg.userinfo,
      udp: true,
      sni: p.sni || p.host || cfg.server,
    };
    if (p.allowInsecure === '1' || p.insecure === '1') entry['skip-cert-verify'] = true;
    if (net === 'ws') entry['ws-opts'] = { path: p.path || '/', headers: p.host ? { Host: p.host } : undefined };
    return entry;
  }
  if (cfg.protocol === 'vmess') {
    const j = cfg.vmessJson;
    const isTls = j.tls === 'tls';
    const entry = {
      name,
      type: 'vmess',
      server: j.add,
      port: +j.port,
      uuid: j.id,
      alterId: +(j.aid || 0),
      cipher: j.scy || 'auto',
      udp: true,
      tls: isTls,
    };
    if (isTls) entry.servername = j.sni || j.host || undefined;
    if (j.net === 'ws') entry['ws-opts'] = { path: j.path || '/', headers: j.host ? { Host: j.host } : undefined };
    else if (j.net === 'grpc') entry['grpc-opts'] = { 'grpc-service-name': j.path || '' };
    return entry;
  }
  if (cfg.protocol === 'hysteria2') {
    return {
      name,
      type: 'hysteria2',
      server: cfg.server,
      port: +cfg.port,
      password: cfg.userinfo,
      sni: p.sni || cfg.server,
      'skip-cert-verify': p.insecure === '1',
      udp: true,
    };
  }
  if (cfg.protocol === 'ss') {
    return { name, type: 'ss', server: cfg.server, port: +cfg.port, cipher: cfg.method, password: cfg.password, udp: true };
  }
  return null;
}

function serializeMap(obj, level) {
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    if (v === null) {
      out += `${indent(level)}${k}: null\n`;
    } else if (Array.isArray(v)) {
      if (v.length === 0) {
        out += `${indent(level)}${k}: []\n`;
      } else {
        out += `${indent(level)}${k}:\n`;
        for (const item of v) out += serializeListItem(item, level);
      }
    } else if (typeof v === 'object') {
      out += `${indent(level)}${k}:\n` + serializeMap(v, level + 1);
    } else if (typeof v === 'boolean' || typeof v === 'number') {
      out += `${indent(level)}${k}: ${v}\n`;
    } else {
      out += `${indent(level)}${k}: ${yamlStr(v)}\n`;
    }
  }
  return out;
}

// یک آیتم لیست رو سریالایز می‌کنه؛ دَش هم‌سطح کلید والده (نه یه سطح تو رفته‌تر)،
// و اولین کلید همون خط دَش می‌آد — دقیقاً مطابق سبک نمونه‌ی کلش
function serializeListItem(item, level) {
  if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
    const entries = Object.entries(item).filter(([, v]) => v !== undefined);
    let out = '';
    entries.forEach(([k, v], idx) => {
      const prefix = idx === 0 ? `${indent(level)}- ` : indent(level + 1);
      if (v === null) {
        out += `${prefix}${k}: null\n`;
      } else if (Array.isArray(v)) {
        if (v.length === 0) {
          out += `${prefix}${k}: []\n`;
        } else {
          out += `${prefix}${k}:\n`;
          for (const sub of v) out += serializeListItem(sub, level + 1);
        }
      } else if (typeof v === 'object') {
        out += `${prefix}${k}:\n` + serializeMap(v, level + 2);
      } else if (typeof v === 'boolean' || typeof v === 'number') {
        out += `${prefix}${k}: ${v}\n`;
      } else {
        out += `${prefix}${k}: ${yamlStr(v)}\n`;
      }
    });
    return out;
  }
  return `${indent(level)}- ${yamlStr(item)}\n`;
}

function buildClash(numberedConfigs, options = {}, remarkBase) {
  const urltestName = options.urltestName || 'بهترین پینگ';
  const selectorName = remarkBase;

  const proxies = [];
  const names = [];
  numberedConfigs.forEach(({ cfg, remark }, i) => {
    const name = remark || `node-${i}`;
    const entry = buildProxyEntry(cfg, name);
    if (entry) {
      proxies.push(entry);
      names.push(name);
    }
  });

  const proxyGroups = [
    { name: selectorName, type: 'select', proxies: [urltestName, ...names, 'DIRECT'] },
    {
      name: urltestName,
      type: 'url-test',
      proxies: names,
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      tolerance: 50,
    },
  ];

  const rules = [
    'GEOSITE,category-ads-all,REJECT',
    'DOMAIN-SUFFIX,ir,DIRECT',
    'GEOIP,IR,DIRECT',
    `MATCH,${selectorName}`,
  ];

  let yaml = '';
  yaml += 'mixed-port: 7890\n';
  yaml += 'allow-lan: false\n';
  yaml += 'mode: rule\n';
  yaml += 'log-level: warning\n';
  yaml += 'ipv6: false\n';
  yaml += 'unified-delay: true\n';
  yaml += 'tcp-concurrent: true\n';
  yaml += 'dns:\n';
  yaml += '  enable: true\n';
  yaml += '  ipv6: false\n';
  yaml += '  default-nameserver:\n';
  yaml += '  - 1.1.1.1\n';
  yaml += '  - 8.8.8.8\n';
  yaml += '  nameserver:\n';
  yaml += '  - https://dns.google/dns-query\n';
  yaml += '  - https://cloudflare-dns.com/dns-query\n';

  yaml += 'proxies:\n';
  for (const p of proxies) yaml += serializeListItem(p, 0);

  yaml += 'proxy-groups:\n';
  for (const g of proxyGroups) yaml += serializeListItem(g, 0);

  yaml += 'rules:\n';
  for (const r of rules) yaml += `- ${r}\n`;

  return yaml;
}

async function fetchCleanIpList(url) {
  if (!url) return [];
  try {
    const res = await fetch(url);
    if (!res.ok) return [];
    const text = await res.text();
    return text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  } catch (e) {
    return [];
  }
}

function parseIpEntry(entry) {
  const idx = entry.lastIndexOf(':');
  if (idx > 0 && /^\d+$/.test(entry.slice(idx + 1))) {
    return { ip: entry.slice(0, idx), port: entry.slice(idx + 1) };
  }
  return { ip: entry, port: null };
}

async function buildCdnCleanIp(numberedConfigs, cleanIpListUrl, remarkBase, numberingStyle) {
  const ipList = await fetchCleanIpList(cleanIpListUrl);
  if (ipList.length === 0) {
    return '# لیست IP تمیز خالی است یا در دسترس نیست\n';
  }

  const workerConfigs = numberedConfigs.filter(({ cfg }) => isCloudflareWorkerConfig(cfg));
  if (workerConfigs.length === 0) {
    return '# هیچ کانفیگ ورکر کلادفلری (ws+tls با SNI پایان‌یابنده به workers.dev) در منبع پیدا نشد\n';
  }

  const renumbered = workerConfigs.map((item, i) => {
    const num = formatNumber(i + 1, numberingStyle);
    const remark = `${num} - ${remarkBase} ${item.flag}`.trim();
    return { cfg: item.cfg, flag: item.flag, remark };
  });

  const lines = [];
  for (const { cfg, remark } of renumbered) {
    const { ip, port } = parseIpEntry(pickRandom(ipList));
    const newCfg = cloneWithServer(cfg, ip, port || cfg.port);
    lines.push(rebuildLink(newCfg, remark));
  }

  return lines.join('\n') + '\n';
}

// ---------- ابزارهای اصلی ----------
function vpnIdentityKey(cfg) {
  if (cfg.protocol === 'vmess') {
    const j = cfg.vmessJson || {};
    return `vmess|${j.add}|${j.port}|${j.id}`;
  }
  if (cfg.protocol === 'ss') {
    return `ss|${cfg.server}|${cfg.port}|${cfg.method}|${cfg.password}`;
  }
  return `${cfg.protocol}|${cfg.server}|${cfg.port}|${cfg.userinfo}`;
}

function plainIdentityKey(cfg) {
  return `${cfg.protocol}|${cfg.server}|${cfg.port}|${cfg.username || ''}|${cfg.password || ''}`;
}

function dedupeBy(list, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

// برای خروجی‌هایی که skipGeo فعاله: بدون هیچ درخواست شبکه‌ای (نه DNS، نه ipinfo/ip-api)
// مستقیم پرچم خالی برمی‌گردونه — نه کند می‌کنه، نه به سقف API فشار میاره.
function enrichWithoutGeo(items) {
  return items.map(({ cfg, identity }) => ({ cfg, flag: '', country: null, identity }));
}

// جایگزینِ حلقه‌ی سریالِ getCountryAndFlag: تشخیص لوکیشن را با همزمانی محدود انجام می‌دهد
// و هر ۲۰ آیتم یک لاگ پیشرفت چاپ می‌کند. items: [{ cfg, identity }]
// نکته: اگه cfg.remark از قبل ایموجی پرچم داشته باشه، getCountryAndFlag همون‌جا (بدون شبکه) برمی‌گردونه
async function enrichWithGeo(items, label) {
  const total = items.length;
  if (total === 0) return [];
  let done = 0;
  const startedAt = Date.now();
  console.log(`🌍 [${label}] شروع تشخیص لوکیشن برای ${total} کانفیگ (همزمانی: ${GEO_CONCURRENCY})...`);
  const results = await mapWithConcurrency(items, GEO_CONCURRENCY, async ({ cfg, identity }) => {
    const { countryCode, flag } = await getCountryAndFlag(cfg, identity);
    done++;
    if (done % 20 === 0 || done === total) {
      const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
      console.log(`   [${label}] ${done}/${total} پردازش شد (${secs}s)`);
    }
    return { cfg, flag, country: countryCode, identity };
  });
  return results;
}

// انتخاب نهایی کانفیگ‌ها قبل از هر گونه تشخیص لوکیشن، تا API فقط روی همون maxCount نهایی
// صدا زده بشه، نه روی کل چند هزار کانفیگ خامِ گروه.
// اولویت با کانفیگ‌های تازه‌ست: اگه تعداد جدیدها کمتر از maxCount باشه، بقیه‌ی ظرفیت با
// کانفیگ‌های «قدیمی ولی هنوز معتبر» از خروجی دور قبل (history) پر می‌شه — این‌ها از قبل
// flag/country مشخص دارن و نیازی به درخواست دوباره ندارن.
// keepPrevious کنترل می‌کنه این carry-over اصلاً انجام بشه یا نه؛ پیش‌فرض خاموشه یعنی
// هر اجرا فقط همون کانفیگ‌های تازه‌ی همین دور رو نگه می‌داره و خروجی قبلی کامل بازنویسی می‌شه.
function selectForOutput(outputId, rawConfigs, identityKeyFn, prefix, maxCount, keepPrevious) {
  const fresh = rawConfigs.map(cfg => ({ cfg, identity: `${prefix}:${identityKeyFn(cfg)}` }));
  if (!keepPrevious) {
    const toEnrich = (!maxCount || maxCount <= 0) ? fresh : fresh.slice(0, maxCount);
    return { toEnrich, carriedOver: [] };
  }
  if (!maxCount || maxCount <= 0) {
    return { toEnrich: fresh, carriedOver: [] };
  }
  if (fresh.length >= maxCount) {
    return { toEnrich: fresh.slice(0, maxCount), carriedOver: [] };
  }
  const freshIds = new Set(fresh.map(it => it.identity));
  const prevHistory = outputHistory[outputId] || [];
  const carryOver = prevHistory.filter(it => !freshIds.has(it.identity));
  const needed = maxCount - fresh.length;
  const carriedOver = carryOver.slice(0, needed);
  if (carriedOver.length > 0) {
    console.log(`   ♻️  [${outputId}] ${fresh.length} کانفیگ جدید + ${carriedOver.length} کانفیگ قدیمی نگه‌داشته‌شده (سقف ${maxCount})`);
  }
  return { toEnrich: fresh, carriedOver };
}

async function numberAndTagFinal(results, remarkBase, numberingStyle) {
  return results.map((item, i) => {
    const num = formatNumber(i + 1, numberingStyle);
    const remark = `${num} - ${remarkBase} ${item.flag}`.trim();
    return { cfg: item.cfg, remark };
  });
}


// ---------- پردازش اصلی ----------
async function processConfigs(config) {
  const { remarkBase, numberingStyle, sourceGroups, outputs, cleanIpListUrl } = config;

  await loadGeoCache();
  await loadOutputHistory();

  const groupCache = {};
  async function getGroupConfigs(groupId, kind) {
    const key = `${groupId}:${kind}`;
    if (groupCache[key]) return groupCache[key];
    const urls = sourceGroups[groupId] || [];
    let raw, result;
    if (kind === 'socks5' || kind === 'http') {
      raw = await fetchAndParsePlainGroup(urls, kind);
      result = dedupeBy(raw, plainIdentityKey);
    } else {
      raw = await fetchAndParseVpnGroup(urls);
      result = dedupeBy(raw, vpnIdentityKey);
    }
    groupCache[key] = result;
    return result;
  }

  const results = {};
  console.log(`📦 ${outputs.filter(o => o.enabled !== false).length} خروجی فعال برای پردازش وجود دارد`);
  for (const output of outputs) {
    if (output.enabled === false) continue;
    // اگه maxCount توی این خروجی مشخص نشده باشه، از سقف پیش‌فرض استفاده می‌شه.
    // مقدار ۰ (یا منفی) صریح یعنی «بدون سقف» — همون رفتار قبلی.
    const maxCount = (output.maxCount === undefined || output.maxCount === null)
      ? DEFAULT_MAX_COUNT
      : output.maxCount;
    // پیش‌فرض خاموش: کانفیگ‌های دور قبل نگه داشته نمی‌شن، هر اجرا فقط همون کانفیگ‌های
    // تازه‌ی همین ساب رو می‌ریزه توی فایل خروجی و قدیمی‌ها کامل پاک/بازنویسی می‌شن.
    // با گذاشتن "keepPrevious": true روی یک خروجی توی config.json می‌شه این رفتار رو
    // به همون شکل قبلی (نگه‌داشتن کانفیگ‌های قدیمیِ هنوز معتبر تا سقف maxCount) برگردوند.
    const keepPrevious = output.keepPrevious === true;
    console.log(`\n▶️  شروع پردازش خروجی: ${output.id} (${output.format}) — سقف: ${maxCount > 0 ? maxCount : 'بدون سقف'} — نگه‌داری قدیمی‌ها: ${keepPrevious ? 'روشن' : 'خاموش'}`);
    try {
      let content;
      let numberedConfigs = [];

      if (output.format === 'txt' || output.format === 'cdn-clean-ip') {
        const raw = await getGroupConfigs(output.group, 'vpn');
        const { toEnrich, carriedOver } = selectForOutput(output.id, raw, vpnIdentityKey, 'vpn', maxCount, keepPrevious);
        if (output.skipGeo) console.log(`   ⏭️  [${output.id}] تشخیص لوکیشن برای این خروجی غیرفعاله، رد شد`);
        const enriched = output.skipGeo ? enrichWithoutGeo(toEnrich) : await enrichWithGeo(toEnrich, output.id);
        const finalItems = enriched.concat(carriedOver);
        if (keepPrevious && maxCount > 0) outputHistory[output.id] = finalItems;
        else delete outputHistory[output.id];
        numberedConfigs = await numberAndTagFinal(finalItems, remarkBase, numberingStyle);

        if (output.format === 'txt') {
          content = buildTxt(numberedConfigs);
        } else {
          content = await buildCdnCleanIp(finalItems, cleanIpListUrl, remarkBase, numberingStyle);
        }
      } else if (output.format === 'socks5' || output.format === 'http') {
        const raw = await getGroupConfigs(output.group, output.format);
        const { toEnrich, carriedOver } = selectForOutput(output.id, raw, plainIdentityKey, 'plain', maxCount, keepPrevious);
        if (output.skipGeo) console.log(`   ⏭️  [${output.id}] تشخیص لوکیشن برای این خروجی غیرفعاله، رد شد`);
        const enriched = output.skipGeo ? enrichWithoutGeo(toEnrich) : await enrichWithGeo(toEnrich, output.id);
        const finalItems = enriched.concat(carriedOver);
        if (keepPrevious && maxCount > 0) outputHistory[output.id] = finalItems;
        else delete outputHistory[output.id];
        numberedConfigs = await numberAndTagFinal(finalItems, remarkBase, numberingStyle);
        content = buildPlainProxyList(numberedConfigs);
      } else {
        // خروجی‌های پیشرفته
        const raw = await getGroupConfigs(output.group, 'vpn');
        const { toEnrich, carriedOver } = selectForOutput(output.id, raw, vpnIdentityKey, 'vpn', maxCount, keepPrevious);
        if (output.skipGeo) console.log(`   ⏭️  [${output.id}] تشخیص لوکیشن برای این خروجی غیرفعاله، رد شد`);
        const enriched = output.skipGeo ? enrichWithoutGeo(toEnrich) : await enrichWithGeo(toEnrich, output.id);
        const finalItems = enriched.concat(carriedOver);
        if (keepPrevious && maxCount > 0) outputHistory[output.id] = finalItems;
        else delete outputHistory[output.id];
        numberedConfigs = await numberAndTagFinal(finalItems, remarkBase, numberingStyle);

        if (output.format === 'xray-lb') content = buildXrayLoadBalanced(numberedConfigs, remarkBase);
        else if (output.format === 'singbox') content = buildSingbox(numberedConfigs, output.options, remarkBase);
        else if (output.format === 'clash') content = buildClash(numberedConfigs, output.options, remarkBase);
        else throw new Error(`فرمت ناشناخته: ${output.format}`);
      }

      results[output.id] = { content, filename: output.filename || `${output.id}.txt`, count: numberedConfigs.length };
      console.log(`✔️  ${output.id} تمام شد — ${numberedConfigs.length} کانفیگ`);
    } catch (e) {
      results[output.id] = { error: e.message };
      console.error(`❌ ${output.id} خطا خورد: ${e.message}`);
    }
    // ذخیره‌ی موقت کش بعد از هر خروجی، تا اگر یکی از خروجی‌های بعدی گیر کرد
    // نتایج lookupهای انجام‌شده تا اینجا از دست نره
    await saveGeoCache();
    await saveOutputHistory();
  }

  return results;
}

// ---------- کامیت به مخزن ----------
async function verifyDestRepo(token, repo, branch) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
    });
    if (res.status === 401) {
      console.error(`   ❌ توکن PUBLIC_REPO_TOKEN معتبر نیست یا منقضی شده (401).`);
      return false;
    }
    if (res.status === 404) {
      console.error(`   ❌ ریپوی "${repo}" پیدا نشد یا توکن به‌ش دسترسی نداره (404). PUBLIC_REPO باید دقیقاً به شکل "owner/repo-name" باشه و توکن باید دسترسی write به همون ریپو داشته باشه.`);
      return false;
    }
    if (!res.ok) {
      console.error(`   ❌ بررسی ریپوی مقصد با کد ${res.status} مواجه شد.`);
      return false;
    }
    const branchRes = await fetch(`https://api.github.com/repos/${repo}/branches/${branch}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
    });
    if (branchRes.status === 404) {
      console.error(`   ❌ برنچ "${branch}" توی "${repo}" وجود نداره. یا برنچ رو بساز یا BRANCH_NAME رو توی سیکرت‌ها/env درست کن.`);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`   ❌ خطا در بررسی ریپوی مقصد: ${e.message}`);
    return false;
  }
}

async function commitToRepo(token, repo, branch, files, message) {
  const failures = [];
  for (const file of files) {
    const url = `https://api.github.com/repos/${repo}/contents/${file.path}`;
    const content = b64EncodeUnicode(file.content);
    let sha = '';
    try {
      const res = await fetch(`${url}?ref=${branch}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
      });
      if (res.ok) {
        const data = await res.json();
        sha = data.sha;
      } else if (res.status !== 404) {
        console.warn(`   ⚠️ گرفتن sha فعلی ${file.path} با کد ${res.status} مواجه شد`);
      }
    } catch (e) {
      console.warn(`   ⚠️ خطا در گرفتن sha فعلی ${file.path}: ${e.message}`);
    }

    const body = { message, content, branch };
    if (sha) body.sha = sha;

    try {
      const putRes = await fetch(url, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' },
        body: JSON.stringify(body)
      });
      if (!putRes.ok) {
        const err = await putRes.text();
        console.error(`   ❌ Push ${file.path} failed (status ${putRes.status}): ${err}`);
        failures.push(file.path);
      } else {
        console.log(`   ✅ ${file.path} کامیت شد`);
      }
    } catch (e) {
      console.error(`   ❌ Push ${file.path} failed: ${e.message}`);
      failures.push(file.path);
    }
  }
  return failures;
}

// ---------- تابع اصلی ----------
async function main() {
  console.log('🚀 Starting pipeline...');

  // خواندن تنظیمات
  const configRaw = await fs.readFile('config.json', 'utf-8');
  const config = JSON.parse(configRaw);

  // اجرای پردازش
  const results = await processConfigs(config);

  // تولید فایل‌های خروجی
  const outputFiles = [];
  await fs.mkdir('outputs', { recursive: true });

  const erroredIds = [];
  for (const [id, data] of Object.entries(results)) {
    if (data.error) {
      console.error(`❌ ${id}: ${data.error}`);
      erroredIds.push(id);
      continue;
    }
    const outPath = path.join('outputs', data.filename);
    await fs.writeFile(outPath, data.content);
    outputFiles.push({ path: outPath, content: data.content });
    console.log(`✅ ${id} -> ${data.filename} (${data.count} configs)`);
  }

  // کامیت فقط به مخزن مقصد (خارج از ریپوی فعلی) با PUBLIC_REPO_TOKEN و PUBLIC_REPO
  const token = process.env.PUBLIC_REPO_TOKEN;
  const repo = process.env.PUBLIC_REPO;
  const branch = process.env.BRANCH_NAME || 'main';
  let commitFailed = false;

  console.log(`🔑 PUBLIC_REPO_TOKEN: ${token ? `ست شده (${token.length} کاراکتر)` : '❌ ست نشده'}`);
  console.log(`📦 PUBLIC_REPO: ${repo || '❌ ست نشده'} — برنچ: ${branch}`);
  console.log(`📄 ${outputFiles.length} فایل از ${Object.keys(results).length} خروجی آماده‌ی کامیت است${erroredIds.length ? ` (${erroredIds.length} خروجی خطا خورد و ساخته نشد: ${erroredIds.join(', ')})` : ''}`);

  if (!token || !repo) {
    console.error('⚠️ PUBLIC_REPO_TOKEN یا PUBLIC_REPO ست نشده — کامیت انجام نشد. مطمئن شو هر دو به‌عنوان GitHub Secrets تنظیم شدن (PUBLIC_REPO مثلاً به شکل "owner/repo-name") و توی workflow زیر همون استپی که node index.js رو اجرا می‌کنه با env: پاس داده شدن.');
  } else if (outputFiles.length === 0) {
    console.error('⚠️ هیچ فایلی برای کامیت آماده نیست (همه‌ی خروجی‌های فعال خطا خوردن یا هیچ خروجی enabled:true نداری) — کامیت انجام نشد.');
    if (erroredIds.length > 0) commitFailed = true;
  } else {
    console.log(`📤 بررسی دسترسی به ${repo} ...`);
    const repoOk = await verifyDestRepo(token, repo, branch);
    if (!repoOk) {
      commitFailed = true;
    } else {
      console.log(`📤 Committing ${outputFiles.length} file(s) to ${repo}/${branch} (پوشه‌ی configs/ و proxies/) ...`);
      const PROXIES_FOLDER_FILES = new Set(['http.txt', 'socks5.txt']);
      const filesToCommit = outputFiles.map(f => {
        const baseName = f.path.replace(/^outputs\//, '');
        const folder = PROXIES_FOLDER_FILES.has(baseName) ? 'proxies' : 'configs';
        return { path: `${folder}/${baseName}`, content: f.content };
      });
      const failures = await commitToRepo(token, repo, branch, filesToCommit, 'Auto-update configs');
      if (failures.length > 0) {
        console.error(`❌ کامیت ${failures.length} فایل ناموفق بود: ${failures.join(', ')}`);
        commitFailed = true;
      } else {
        console.log('✅ Commit successful.');
      }
    }
  }

  console.log('🎉 Done.');
  if (commitFailed) process.exitCode = 1;
}

// اجرا
main().catch(err => {
  console.error('❌ Fatal error:', err);
  process.exit(1);
});