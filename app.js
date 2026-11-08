/* MD Mobile — companion PWA for Moneydance (via the MD Mobile Bridge script).
 * All data stays encrypted in your own Dropbox App folder; decryption happens on the phone.
 */
'use strict';

const APP_VERSION = '1.0.0';
const FILES = { export: '/export.json.enc', budgets: '/budgets.json.enc', inbox: '/inbox' };
const CAT = new Set(['EXPENSE', 'INCOME']);
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ------------------------------------------------------------ storage */
const LS = {
  get(k, d = null) { try { const v = localStorage.getItem('mdm.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { if (v == null) localStorage.removeItem('mdm.' + k); else localStorage.setItem('mdm.' + k, JSON.stringify(v)); } catch { } },
};
const IDB = {
  db: null,
  async open() {
    if (this.db) return this.db;
    this.db = await new Promise((res, rej) => {
      const r = indexedDB.open('mdmobile', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
    return this.db;
  },
  async get(k) {
    try { const db = await this.open(); return await new Promise((res, rej) => { const r = db.transaction('kv').objectStore('kv').get(k); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); } catch { return null; }
  },
  async set(k, v) {
    try { const db = await this.open(); await new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite'); if (v == null) t.objectStore('kv').delete(k); else t.objectStore('kv').put(v, k); t.oncomplete = res; t.onerror = () => rej(t.error); }); } catch { }
  },
  async clear() { try { const db = await this.open(); db.transaction('kv', 'readwrite').objectStore('kv').clear(); } catch { } },
};

/* ------------------------------------------------------------ crypto (matches bridge script) */
const TE = new TextEncoder(), TD = new TextDecoder();
const b64 = { enc(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); },
  dec(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; } };
const keyCache = new Map();
async function deriveKey(pass, salt, iter) {
  const ck = pass + '|' + b64.enc(salt) + '|' + iter;
  if (keyCache.has(ck)) return keyCache.get(ck);
  const base = await crypto.subtle.importKey('raw', TE.encode(pass), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  keyCache.set(ck, k);
  return k;
}
async function gunzip(u8) { return new Uint8Array(await new Response(new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer()); }
async function decryptEnvelope(text, pass) {
  const env = JSON.parse(text);
  if (env.v !== 1) throw new Error('Unknown file version');
  const key = await deriveKey(pass, b64.dec(env.salt), env.iter || 200000);
  let data;
  try { data = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(env.iv) }, key, b64.dec(env.ct))); }
  catch { const e = new Error('Wrong passphrase (or the file was changed)'); e.code = 'pass'; throw e; }
  if (env.z) data = await gunzip(data);
  return TD.decode(data);
}
async function encryptEnvelope(text, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const iter = 200000;
  const key = await deriveKey(pass, salt, iter);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, TE.encode(text)));
  return JSON.stringify({ v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iter, z: 0, salt: b64.enc(salt), iv: b64.enc(iv), ct: b64.enc(ct) });
}

/* ------------------------------------------------------------ Dropbox (OAuth PKCE, no server) */
const Dbx = {
  redirectUri() { return location.origin + location.pathname.replace(/index\.html$/, ''); },
  connected() { return !!LS.get('tok'); },
  async login() {
    const key = LS.get('cfg', {}).appKey;
    if (!key) throw new Error('Enter your Dropbox app key first');
    const ver = b64.enc(crypto.getRandomValues(new Uint8Array(48))).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', TE.encode(ver)));
    const chal = b64.enc(hash).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    LS.set('pkce', ver);
    const u = new URL('https://www.dropbox.com/oauth2/authorize');
    u.search = new URLSearchParams({ client_id: key, response_type: 'code', code_challenge: chal, code_challenge_method: 'S256', redirect_uri: this.redirectUri(), token_access_type: 'offline' });
    location.href = u.toString();
  },
  async handleRedirect() {
    const p = new URLSearchParams(location.search);
    if (!p.has('code') && !p.has('error')) return false;
    history.replaceState(null, '', this.redirectUri());
    if (p.has('error')) { toast('Dropbox: ' + (p.get('error_description') || p.get('error'))); return false; }
    const ver = LS.get('pkce'); const key = LS.get('cfg', {}).appKey;
    const r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams({ code: p.get('code'), grant_type: 'authorization_code', client_id: key, redirect_uri: this.redirectUri(), code_verifier: ver }) });
    const j = await r.json();
    if (!r.ok) throw new Error('Dropbox login failed: ' + (j.error_description || j.error || r.status));
    LS.set('pkce', null);
    LS.set('tok', { access: j.access_token, refresh: j.refresh_token, exp: Date.now() + (j.expires_in - 60) * 1000 });
    return true;
  },
  async token(force) {
    const t = LS.get('tok');
    if (!t) throw new Error('Not connected to Dropbox');
    if (!force && t.exp > Date.now()) return t.access;
    const r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.refresh, client_id: LS.get('cfg', {}).appKey }) });
    const j = await r.json();
    if (!r.ok) { if (r.status === 400 || r.status === 401) LS.set('tok', null); throw new Error('Dropbox session expired — please connect again'); }
    t.access = j.access_token; t.exp = Date.now() + (j.expires_in - 60) * 1000; LS.set('tok', t);
    return t.access;
  },
  argHeader(o) { return JSON.stringify(o).replace(/[\u007f-￿]/g, c => '\\u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4)); },
  async call(url, opts, retry = true) {
    opts.headers = Object.assign({ Authorization: 'Bearer ' + await this.token() }, opts.headers || {});
    const r = await fetch(url, opts);
    if (r.status === 401 && retry) { await this.token(true); return this.call(url, opts, false); }
    if (r.status === 409) { const j = await r.json().catch(() => ({})); const e = new Error(j.error_summary || 'not found'); e.code = 409; e.summary = j.error_summary || ''; throw e; }
    if (!r.ok) throw new Error('Dropbox error ' + r.status);
    return r;
  },
  async rpc(ep, args) {
    const r = await this.call('https://api.dropboxapi.com/2/' + ep, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args) });
    return r.json();
  },
  async meta(path) { try { return await this.rpc('files/get_metadata', { path }); } catch (e) { if (e.code === 409) return null; throw e; } },
  async download(path) {
    try { const r = await this.call('https://content.dropboxapi.com/2/files/download', { method: 'POST', headers: { 'Dropbox-API-Arg': this.argHeader({ path }) } }); return await r.text(); }
    catch (e) { if (e.code === 409) return null; throw e; }
  },
  async upload(path, text, overwrite) {
    const r = await this.call('https://content.dropboxapi.com/2/files/upload', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'Dropbox-API-Arg': this.argHeader({ path, mode: overwrite ? 'overwrite' : 'add', autorename: false, mute: true }) }, body: TE.encode(text) });
    return r.json();
  },
  async list(path) {
    try { const j = await this.rpc('files/list_folder', { path }); return j.entries || []; }
    catch (e) { if (e.code === 409) return []; throw e; }
  },
};

/* ------------------------------------------------------------ state */
const S = {
  raw: null, M: null, pass: null, demo: false, view: 'home', syncing: false,
  f: { q: '', period: 'm0', acct: '', cat: '', type: '', min: '', max: '', status: '', from: '', to: '', limit: 150 },
  addType: 'expense', budgetMonth: null, editBudgets: false,
};

/* ------------------------------------------------------------ dates & formatting */
const pad = n => String(n).padStart(2, '0');
const dInt = dt => dt.getFullYear() * 10000 + (dt.getMonth() + 1) * 100 + dt.getDate();
const toDate = d => new Date(Math.floor(d / 10000), Math.floor(d / 100) % 100 - 1, d % 100);
const isoToInt = s => s ? +s.replace(/-/g, '') : 0;
const intToIso = d => `${Math.floor(d / 10000)}-${pad(Math.floor(d / 100) % 100)}-${pad(d % 100)}`;
const today = () => dInt(new Date());
const ym = d => Math.floor(d / 100);
const ymAdd = (m, k) => { let y = Math.floor(m / 100), mo = m % 100 - 1 + k; y += Math.floor(mo / 12); mo = ((mo % 12) + 12) % 12; return y * 100 + mo + 1; };
const ymLabel = (m, long) => new Date(Math.floor(m / 100), m % 100 - 1, 1).toLocaleDateString(undefined, long ? { month: 'long', year: 'numeric' } : { month: 'short' });
const dayLabel = d => { const t = today(); if (d === t) return 'Today'; const y = dInt(new Date(Date.now() - 864e5)); if (d === y) return 'Yesterday'; return toDate(d).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: Math.floor(d / 10000) !== new Date().getFullYear() ? 'numeric' : undefined }); };
const daysIn = m => new Date(Math.floor(m / 100), m % 100, 0).getDate();
const ago = iso => { const s = (Date.now() - new Date(iso).getTime()) / 1000; if (!isFinite(s)) return ''; if (s < 90) return 'just now'; if (s < 3600) return Math.round(s / 60) + ' min ago'; if (s < 86400 * 2) return Math.round(s / 3600) + ' h ago'; return Math.round(s / 86400) + ' days ago'; };
const fmtCache = new Map();
function money(v, code, opts = {}) {
  code = code || (S.M && S.M.baseCode) || 'EUR';
  const k = code + (opts.compact ? 'c' : '') + (opts.sign ? 's' : '') + (opts.whole ? 'w' : '');
  if (!fmtCache.has(k)) {
    let f;
    const cur = S.raw && S.raw.currencies[code];
    try {
      if (!/^[A-Z]{3}$/.test(code)) throw 0;
      f = new Intl.NumberFormat(undefined, { style: 'currency', currency: code, notation: opts.compact ? 'compact' : 'standard', maximumFractionDigits: opts.compact ? 1 : opts.whole ? 0 : (cur ? Math.min(cur.dp, 2) : 2), minimumFractionDigits: opts.compact || opts.whole ? 0 : (cur ? Math.min(cur.dp, 2) : 2), signDisplay: opts.sign ? 'exceptZero' : 'auto' });
    } catch {
      const nf = new Intl.NumberFormat(undefined, { notation: opts.compact ? 'compact' : 'standard', maximumFractionDigits: opts.compact ? 1 : 2, minimumFractionDigits: opts.compact ? 0 : 2, signDisplay: opts.sign ? 'exceptZero' : 'auto' });
      f = { format: v => (cur ? cur.prefix : '') + nf.format(v) + (cur && cur.suffix ? ' ' + cur.suffix : (cur && !cur.prefix ? ' ' + code : '')) };
    }
    fmtCache.set(k, f);
  }
  return fmtCache.get(k).format(Math.abs(v) < 0.005 ? 0 : v);
}
const num = (v, dp = 4) => new Intl.NumberFormat(undefined, { maximumFractionDigits: dp }).format(v);
const pct = v => new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 0 }).format(v);
const parseAmt = s => { s = String(s || '').trim().replace(/\s/g, ''); if (!s) return NaN; if (/,\d{1,2}$/.test(s)) s = s.replace(/\./g, '').replace(',', '.'); else s = s.replace(/,/g, ''); return parseFloat(s); };

/* ------------------------------------------------------------ data model */
function buildModel(raw) {
  const M = { baseCode: raw.base, generated: raw.generated };
  const A = raw.accounts.map((a, i) => Object.assign({}, a, { i, kids: [], rate: (raw.currencies[a.cur] || {}).toBase || 1 }));
  A.forEach(a => { if (a.parent != null && A[a.parent]) A[a.parent].kids.push(a.i); });
  A.forEach(a => {
    let t = a; while (t.parent != null && A[t.parent]) t = A[t.parent];
    a.top = t.i; a.isCat = CAT.has(a.type);
    a.label = (a.full || a.name).split(':').join(' › ');
    a.depth = (a.full || a.name).split(':').length - 1;
  });
  M.A = A;
  M.byId = new Map(A.map(a => [a.id, a]));
  const T = raw.txns.map(r => ({ d: r[0], a: r[1], v: r[2], p: r[3] || '', m: r[4] || '', st: r[5] || '', chk: r[6] || '', sp: (r[7] || []).map(s => ({ a: s[0], v: s[1], p: s[2] || '' })), mid: r[8] || null }));
  T.forEach(t => {
    const cats = t.sp.filter(s => A[s.a] && A[s.a].isCat);
    t.kind = cats.length === 0 ? 'xfer' : (t.v < 0 ? 'exp' : 'inc');
  });
  T.sort((x, y) => y.d - x.d);
  M.T = T;
  M.mids = new Set(T.filter(t => t.mid).map(t => t.mid));

  // monthly income / spending and per-category spending, in base currency
  const spend = new Map(), income = new Map(), catSpend = new Map();
  for (const t of T) {
    const m = ym(t.d);
    for (const s of t.sp) {
      const c = A[s.a]; if (!c || !c.isCat) continue;
      const v = s.v * c.rate;
      if (c.type === 'EXPENSE') {
        spend.set(m, (spend.get(m) || 0) + v);
        let cm = catSpend.get(m); if (!cm) catSpend.set(m, cm = new Map());
        cm.set(c.i, (cm.get(c.i) || 0) + v);
      } else income.set(m, (income.get(m) || 0) - v);
    }
  }
  Object.assign(M, { spend, income, catSpend });

  // effects on real accounts, for history
  const td = today();
  const later = new Map(); // month -> Map(acct -> sum of effects after month end)
  M.real = A.filter(a => !a.isCat);
  M.netWorth = M.real.reduce((s, a) => s + (a.balBase || 0), 0);
  const months = []; const cm = ym(td); for (let k = 12; k >= 1; k--) months.push(ymAdd(cm, -k));
  const ends = months.map(m => m * 100 + 31);
  const deltaAfter = ends.map(() => 0);
  for (const t of T) {
    if (t.d > td) continue;
    const eff = [[t.a, t.v]].concat(t.sp.filter(s => A[s.a] && !A[s.a].isCat).map(s => [s.a, s.v]));
    for (const [ai, v] of eff) {
      const a = A[ai]; if (!a || a.isCat) continue;
      const vb = v * a.rate;
      for (let k = 0; k < ends.length; k++) if (t.d > ends[k]) deltaAfter[k] += vb;
    }
  }
  M.nwHistory = { months: months.concat([cm]), values: ends.map((_, k) => M.netWorth - deltaAfter[k]).concat([M.netWorth]) };
  // 30-day delta
  const d30 = dInt(new Date(Date.now() - 30 * 864e5));
  let after30 = 0;
  for (const t of T) { if (t.d <= d30) break; if (t.d > td) continue; const eff = [[t.a, t.v]].concat(t.sp.map(s => [s.a, s.v])); for (const [ai, v] of eff) { const a = A[ai]; if (a && !a.isCat) after30 += v * a.rate; } }
  M.nw30 = M.netWorth - after30;

  // payees for autocomplete
  const pay = new Map();
  for (const t of T) { if (!t.p) continue; const k = t.p.trim(); const e = pay.get(k); if (e) e.n++; else pay.set(k, { n: 1, t }); }
  M.payees = Array.from(pay.entries()).sort((a, b) => b[1].n - a[1].n).slice(0, 400);
  M.payeeMap = pay;
  return M;
}
const acctOf = i => S.M.A[i];
function descendants(i) { const out = new Set([i]); const st = [i]; while (st.length) { const a = S.M.A[st.pop()]; for (const k of a.kids) if (!out.has(k)) { out.add(k); st.push(k); } } return out; }
function txSearch(t) {
  if (t._s == null) {
    const A = S.M.A;
    t._s = [t.p, t.m, t.chk, A[t.a] && A[t.a].label, ...t.sp.map(s => (A[s.a] ? A[s.a].label : '') + ' ' + s.p), Math.abs(t.v).toFixed(2), Math.abs(t.v).toFixed(2).replace('.', ',')].join(' ').toLowerCase();
  }
  return t._s;
}

/* ------------------------------------------------------------ UI helpers */
let toastTimer;
function toast(msg, ms = 2800) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), ms); }
function openSheet(html) { $('#sheetBody').innerHTML = html; $('#sheetBg').classList.add('open'); $('#sheet').classList.add('open'); history.pushState({ sheet: 1 }, ''); }
function closeSheet(fromPop) { if (!$('#sheet').classList.contains('open')) return; $('#sheetBg').classList.remove('open'); $('#sheet').classList.remove('open'); if (!fromPop && history.state && history.state.sheet) history.back(); }
window.addEventListener('popstate', () => closeSheet(true));
$('#sheetBg').addEventListener('click', () => closeSheet());

const TITLES = { home: 'Overview', txns: 'Activity', add: 'New entry', budgets: 'Budgets', invest: 'Investments', settings: 'Settings', lock: 'MD Mobile' };
function show(v) {
  S.view = v;
  $$('.view').forEach(e => e.classList.toggle('active', e.id === 'v-' + v));
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.v === v));
  $('#title').textContent = TITLES[v] || '';
  $('#tabs').style.display = v === 'lock' ? 'none' : '';
  render();
  window.scrollTo(0, 0);
}
$$('#tabs button').forEach(b => b.addEventListener('click', () => { if (!S.M && b.dataset.v !== 'settings') { show('settings'); return; } show(b.dataset.v); }));
$('#settingsBtn').addEventListener('click', () => show('settings'));
$('#refreshBtn').addEventListener('click', () => sync(true));

function render() {
  updateSyncInfo();
  if (S.view === 'settings') return renderSettings();
  if (S.view === 'lock') return;
  if (!S.M) return;
  ({ home: renderHome, txns: renderTxns, add: renderAdd, budgets: renderBudgets, invest: renderInvest })[S.view]();
}
function updateSyncInfo() {
  const el = $('#syncInfo');
  if (S.demo) el.innerHTML = 'Demo data';
  else if (S.raw) el.innerHTML = 'PC update<br>' + esc(ago(S.raw.generated));
  else el.textContent = '';
  $('#refreshBtn').classList.toggle('spin', S.syncing);
}

/* ------------------------------------------------------------ charts */
function niceTicks(min, max, count = 4) {
  if (min === max) { min -= 1; max += 1; }
  const span = max - min; let step = Math.pow(10, Math.floor(Math.log10(span / count)));
  const err = span / count / step; if (err >= 7.5) step *= 10; else if (err >= 3.5) step *= 5; else if (err >= 1.5) step *= 2;
  const lo = Math.floor(min / step) * step, hi = Math.ceil(max / step) * step; const t = [];
  for (let v = lo; v <= hi + step / 2; v += step) t.push(+v.toFixed(8));
  return t;
}
function lineChart(host, o) {
  host.classList.add('chart'); host.innerHTML = '';
  const W = Math.max(280, host.clientWidth || 320), H = o.height || 170, pl = 48, pr = o.endLabels ? 66 : 14, pt = 10, pb = 24;
  const all = o.series.flatMap(s => s.values).filter(v => v != null && isFinite(v));
  if (!all.length) { host.innerHTML = '<div class="empty">No data yet</div>'; return; }
  let mn = Math.min(...all), mx = Math.max(...all); if (o.zero) mn = Math.min(0, mn);
  const ticks = niceTicks(mn, mx); mn = ticks[0]; mx = ticks[ticks.length - 1];
  const n = o.labels.length, iw = W - pl - pr;
  const x = i => pl + (n <= 1 ? iw / 2 : i * iw / (n - 1)), y = v => pt + (H - pt - pb) * (1 - (v - mn) / ((mx - mn) || 1));
  const cf = v => money(v, null, { compact: true });
  let s = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="${esc(o.title || 'chart')}">`;
  for (const t of ticks) s += `<line x1="${pl}" x2="${W - pr}" y1="${y(t)}" y2="${y(t)}" style="stroke:${t === 0 && mn < 0 ? 'var(--axis)' : 'var(--grid)'}" stroke-width="1"/><text x="${pl - 6}" y="${y(t) + 4}" text-anchor="end" style="fill:var(--muted);font-size:11px" class="tnum">${esc(cf(t))}</text>`;
  const k = Math.max(1, Math.ceil(n / Math.floor(iw / 44)));
  o.labels.forEach((l, i) => { if ((n - 1 - i) % k === 0) s += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle" style="fill:var(--muted);font-size:11px">${esc(l)}</text>`; });
  o.series.forEach(se => {
    const pts = se.values.map((v, i) => [x(i), y(v)]);
    const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('');
    if (o.area && o.series.length === 1) s += `<path d="${d}L${x(n - 1)} ${H - pb}L${x(0)} ${H - pb}Z" style="fill:${se.color};opacity:.1"/>`;
    s += `<path d="${d}" fill="none" style="stroke:${se.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    const lp = pts[pts.length - 1];
    s += `<circle cx="${lp[0]}" cy="${lp[1]}" r="4" style="fill:${se.color};stroke:var(--surface)" stroke-width="2"/>`;
  });
  if (o.endLabels) {
    const ys = o.series.map(se => y(se.values[n - 1]));
    const collide = ys.some((a, i) => ys.some((b, j) => i !== j && Math.abs(a - b) < 15));
    if (!collide) o.series.forEach((se, i) => { s += `<text x="${x(n - 1) + 8}" y="${ys[i] + 4}" style="fill:var(--ink-2);font-size:11.5px">${esc(se.name)}</text>`; });
  }
  s += `<g class="xh" style="display:none"><line y1="${pt}" y2="${H - pb}" style="stroke:var(--axis)" stroke-width="1"/>${o.series.map(se => `<circle r="4" style="fill:${se.color};stroke:var(--surface)" stroke-width="2"/>`).join('')}</g>`;
  s += `<rect x="${pl - 10}" y="0" width="${iw + 20}" height="${H}" fill="transparent" class="hit"/></svg><div class="tip"></div>`;
  host.innerHTML = s;
  const svg = host.querySelector('svg'), xh = host.querySelector('.xh'), tip = host.querySelector('.tip');
  const move = ev => {
    const r = svg.getBoundingClientRect(); const px = (ev.touches ? ev.touches[0].clientX : ev.clientX) - r.left; const sx = px * W / r.width;
    const i = Math.max(0, Math.min(n - 1, Math.round((sx - pl) / (iw / Math.max(1, n - 1)))));
    xh.style.display = ''; const ln = xh.querySelector('line'); ln.setAttribute('x1', x(i)); ln.setAttribute('x2', x(i));
    xh.querySelectorAll('circle').forEach((c, j) => { c.setAttribute('cx', x(i)); c.setAttribute('cy', y(o.series[j].values[i])); });
    tip.innerHTML = `<div style="color:var(--ink-2)">${esc(o.tipLabels ? o.tipLabels[i] : o.labels[i])}</div>` + o.series.map(se => `<div>${o.series.length > 1 ? `<i style="display:inline-block;width:10px;height:3px;border-radius:2px;background:${se.color};vertical-align:middle;margin-right:5px"></i>${esc(se.name)} ` : ''}<b class="tnum">${esc(money(se.values[i]))}</b></div>`).join('');
    tip.style.display = 'block';
    const tx = x(i) * r.width / W; const tw = tip.offsetWidth;
    tip.style.left = Math.max(0, Math.min(r.width - tw, tx - tw / 2)) + 'px'; tip.style.top = '-8px'; tip.style.transform = 'translateY(-100%)';
  };
  const leave = () => { xh.style.display = 'none'; tip.style.display = 'none'; };
  svg.addEventListener('pointermove', move); svg.addEventListener('pointerdown', move);
  svg.addEventListener('touchmove', move, { passive: true }); svg.addEventListener('pointerleave', leave); svg.addEventListener('touchend', () => setTimeout(leave, 1500));
}
function barsHtml(items, onKey) {
  const max = Math.max(...items.map(i => i.value), 0) || 1;
  return `<div class="bars">${items.map(it => `<div class="b" ${it.key != null ? `data-k="${esc(it.key)}"` : ''} title="${esc(it.label + ': ' + money(it.value))}"><div class="bl">${esc(it.label)}${it.sub ? ` <span style="color:var(--muted);font-size:12px">${esc(it.sub)}</span>` : ''}</div><div class="bv tnum">${esc(it.text || money(it.value))}</div><div class="track"><div class="fill${it.value < 0 ? ' neg' : ''}" style="width:${Math.max(0, it.value) / max * 100}%"></div></div></div>`).join('')}</div>`;
}

/* ------------------------------------------------------------ Overview */
function renderHome() {
  const M = S.M, el = $('#v-home'), cm = ym(today()), lm = ymAdd(cm, -1), dom = new Date().getDate();
  const spentNow = M.spend.get(cm) || 0, incNow = M.income.get(cm) || 0;
  // last month up to the same day, for a fair comparison
  let spentLastSame = 0; for (const t of M.T) { if (ym(t.d) !== lm || t.d % 100 > dom) continue; for (const s of t.sp) { const c = M.A[s.a]; if (c && c.type === 'EXPENSE') spentLastSame += s.v * c.rate; } }
  const d = M.netWorth - M.nw30;
  const cats = new Map(); const cmMap = M.catSpend.get(cm) || new Map();
  cmMap.forEach((v, ci) => { const top = M.A[ci].top; cats.set(top, (cats.get(top) || 0) + v); });
  let items = Array.from(cats.entries()).map(([i, v]) => ({ key: i, label: M.A[i].name, value: v })).filter(x => Math.abs(x.value) > 0.004).sort((a, b) => b.value - a.value);
  if (items.length > 8) { const rest = items.slice(7).reduce((s, x) => s + x.value, 0); items = items.slice(0, 7).concat([{ label: 'Other', value: rest }]); }
  const months = []; for (let k = 12; k >= 1; k--) months.push(ymAdd(cm, -k));
  const inc = months.map(m => M.income.get(m) || 0), sp = months.map(m => M.spend.get(m) || 0);

  const groups = [['BANK', 'Bank'], ['CREDIT_CARD', 'Credit cards'], ['INVESTMENT', 'Investments'], ['ASSET', 'Assets'], ['LIABILITY', 'Liabilities'], ['LOAN', 'Loans']];
  let acctHtml = '';
  for (const [type, label] of groups) {
    const list = M.A.filter(a => a.type === type && !(a.inactive && Math.abs(a.bal || 0) < 0.005));
    if (!list.length) continue;
    const val = a => a.type === 'INVESTMENT' ? a.kids.reduce((s, k) => s + (M.A[k].balBase || 0), a.balBase || 0) : (a.balBase || 0);
    const tot = list.reduce((s, a) => s + val(a), 0);
    acctHtml += `<div class="group-h"><span>${label}</span><span class="tnum">${esc(money(tot))}</span></div>` + list.map(a => `<div class="acct" data-a="${a.i}"><div class="n">${esc(a.name)}</div><div class="a tnum ${val(a) < 0 ? 'neg' : ''}">${esc(a.type === 'INVESTMENT' ? money(val(a)) : money(a.bal || 0, a.cur))}</div></div>`).join('');
  }

  el.innerHTML = `
    <div class="card">
      <div class="hero-label">Net worth</div>
      <div class="hero tnum">${esc(money(M.netWorth))}</div>
      <div class="delta ${d > 0.5 ? 'up' : d < -0.5 ? 'down' : ''}">${d >= 0 ? '▲' : '▼'} ${esc(money(Math.abs(d)))} in the last 30 days</div>
      <div id="nwChart" style="margin-top:10px"></div>
      <p class="sub" style="margin:4px 0 0">Month-end values. Investments at today’s prices.</p>
    </div>
    <div class="tiles">
      <div class="tile"><div class="l">Spent</div><div class="v tnum">${esc(money(spentNow, null, { compact: spentNow >= 100000, whole: true }))}</div><div class="d">${spentLastSame ? (spentNow <= spentLastSame ? '▼ ' : '▲ ') + esc(pct(Math.abs(spentNow / spentLastSame - 1))) + ' vs same day last month' : 'this month'}</div></div>
      <div class="tile"><div class="l">Income</div><div class="v tnum">${esc(money(incNow, null, { compact: incNow >= 100000, whole: true }))}</div><div class="d">this month</div></div>
      <div class="tile"><div class="l">Saved</div><div class="v tnum ${incNow - spentNow < 0 ? 'neg' : ''}">${esc(money(incNow - spentNow, null, { compact: Math.abs(incNow - spentNow) >= 100000, whole: true }))}</div><div class="d">${incNow > 0 ? esc(pct(Math.max(-9, (incNow - spentNow) / incNow))) + ' of income' : 'this month'}</div></div>
    </div>
    <div class="card">
      <h2>Spending in ${esc(ymLabel(cm, true))}</h2><p class="sub">By category — tap one to see its transactions</p>
      <div id="catBars">${items.length ? barsHtml(items) : '<div class="empty">No spending yet this month</div>'}</div>
    </div>
    <div class="card">
      <h2>Income and spending</h2><p class="sub">Last 12 full months</p>
      <div class="legend"><span><i style="background:var(--s1)"></i>Income</span><span><i style="background:var(--s2)"></i>Spending</span></div>
      <div id="isChart"></div>
      <details><summary>Show as table</summary><table class="data tnum"><tr><th>Month</th><th>Income</th><th>Spending</th><th>Saved</th></tr>${months.map((m, i) => `<tr><td>${esc(ymLabel(m, true))}</td><td>${esc(money(inc[i]))}</td><td>${esc(money(sp[i]))}</td><td>${esc(money(inc[i] - sp[i]))}</td></tr>`).reverse().join('')}</table></details>
    </div>
    <div class="card"><h2>Accounts</h2>${acctHtml || '<div class="empty">No accounts</div>'}</div>`;

  lineChart($('#nwChart'), { title: 'Net worth', labels: M.nwHistory.months.map(m => ymLabel(m)), tipLabels: M.nwHistory.months.map((m, i) => i === M.nwHistory.months.length - 1 ? 'Today' : 'End of ' + ymLabel(m, true)), series: [{ name: 'Net worth', color: 'var(--s1)', values: M.nwHistory.values }], area: true, height: 150 });
  lineChart($('#isChart'), { title: 'Income and spending', labels: months.map(m => ymLabel(m)), tipLabels: months.map(m => ymLabel(m, true)), series: [{ name: 'Income', color: 'var(--s1)', values: inc }, { name: 'Spending', color: 'var(--s2)', values: sp }], zero: true, endLabels: true, height: 180 });
  $$('#catBars .b[data-k]').forEach(b => b.addEventListener('click', () => { Object.assign(S.f, { cat: b.dataset.k, acct: '', period: 'm0', q: '', type: '' }); show('txns'); }));
  $$('#v-home .acct').forEach(b => b.addEventListener('click', () => { Object.assign(S.f, { acct: b.dataset.a, cat: '', period: 'd90', q: '', type: '' }); show('txns'); }));
}

/* ------------------------------------------------------------ Activity */
function periodRange(p) {
  const t = new Date(), td = today(), cm = ym(td);
  switch (p) {
    case 'm0': return [cm * 100 + 1, 99991231];
    case 'm1': { const m = ymAdd(cm, -1); return [m * 100 + 1, m * 100 + 31]; }
    case 'd90': return [dInt(new Date(t - 90 * 864e5)), 99991231];
    case 'y0': return [t.getFullYear() * 10000 + 101, 99991231];
    case 'd365': return [dInt(new Date(t - 365 * 864e5)), 99991231];
    case 'custom': return [isoToInt(S.f.from) || 0, isoToInt(S.f.to) || 99991231];
    default: return [0, 99991231];
  }
}
function fillFilterSelects() {
  const M = S.M;
  const ac = M.A.filter(a => !a.isCat && a.type !== 'SECURITY' && !(a.inactive && Math.abs(a.bal || 0) < 0.005));
  $('#fAcct').innerHTML = '<option value="">All accounts</option>' + ac.map(a => `<option value="${a.i}">${esc(a.name)}</option>`).join('');
  const cats = M.A.filter(a => a.isCat).sort((a, b) => a.type.localeCompare(b.type) || a.full.localeCompare(b.full));
  $('#fCat').innerHTML = '<option value="">All categories</option><optgroup label="Spending">' + cats.filter(c => c.type === 'EXPENSE').map(c => `<option value="${c.i}">${' '.repeat(c.depth)}${esc(c.name)}</option>`).join('') + '</optgroup><optgroup label="Income">' + cats.filter(c => c.type === 'INCOME').map(c => `<option value="${c.i}">${' '.repeat(c.depth)}${esc(c.name)}</option>`).join('') + '</optgroup>';
}
function filterTx() {
  const f = S.f, M = S.M, [d0, d1] = periodRange(f.period);
  const aSet = f.acct !== '' ? descendants(+f.acct) : null, cSet = f.cat !== '' ? descendants(+f.cat) : null;
  const q = f.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const mn = parseAmt(f.min), mx = parseAmt(f.max);
  const out = [];
  for (const t of M.T) {
    if (t.d > d1) continue; if (t.d < d0) break;
    let amt = t.v, cur = M.A[t.a].cur;
    if (aSet) {
      if (aSet.has(t.a)) amt = t.v;
      else { const ss = t.sp.filter(s => aSet.has(s.a)); if (!ss.length) continue; amt = ss.reduce((x, s) => x + s.v, 0); cur = M.A[ss[0].a].cur; }
    }
    if (cSet) { const ss = t.sp.filter(s => cSet.has(s.a)); if (!ss.length) continue; if (!aSet) { amt = -ss.reduce((x, s) => x + s.v, 0); cur = M.A[ss[0].a].cur; } }
    if (f.type && t.kind !== f.type) continue;
    if (f.status) { if (f.status === 'U' ? t.st !== '' : t.st !== f.status) continue; }
    if (!isNaN(mn) && Math.abs(amt) < mn) continue;
    if (!isNaN(mx) && Math.abs(amt) > mx) continue;
    if (q.length) { const s = txSearch(t); if (!q.every(w => s.includes(w))) continue; }
    out.push({ t, amt, cur });
  }
  return out;
}
function txRowHtml(t, amt, cur, cls, extra) {
  const M = S.M;
  let cat;
  if (t.sp.length === 1) { const a = M.A[t.sp[0].a]; cat = a ? (a.isCat ? a.label : (t.v < 0 ? 'To ' : 'From ') + a.name) : ''; }
  else cat = 'Split · ' + t.sp.length;
  const sub = S.f.acct === '' ? cat + ' · ' + M.A[t.a].name : cat;
  return `<div class="tx ${cls}" data-t="${extra != null ? extra : ''}"><div class="main"><div class="p">${esc(t.p || '(no payee)')}${t.st === 'R' ? '' : ''}</div><div class="c">${esc(sub)}</div></div><div class="amt tnum ${amt > 0 ? 'pos' : ''}">${esc(money(amt, cur, { sign: amt > 0 }))}</div></div>`;
}
function renderTxns() {
  if (!$('#fAcct').options.length) fillFilterSelects();
  const f = S.f;
  $('#q').value = f.q; $('#fPeriod').value = f.period; $('#fAcct').value = f.acct; $('#fCat').value = f.cat; $('#fType').value = f.type;
  $('#fFrom').value = f.from; $('#fTo').value = f.to; $('#fMin').value = f.min; $('#fMax').value = f.max; $('#fStatus').value = f.status;
  ['fPeriod', 'fAcct', 'fCat', 'fType'].forEach(id => $('#' + id).classList.toggle('on', id === 'fPeriod' ? f.period !== 'all' : !!$('#' + id).value));
  $('#fMore').classList.toggle('on', !!(f.min || f.max || f.status || f.period === 'custom'));
  const res = filterTx();
  let inflow = 0, outflow = 0;
  for (const r of res) { const v = r.amt * ((S.raw.currencies[r.cur] || {}).toBase || 1); if (v > 0) inflow += v; else outflow += v; }
  $('#txSummary').innerHTML = `<span><b>${res.length.toLocaleString()}</b> transactions</span><span>In <b class="tnum pos">${esc(money(inflow))}</b></span><span>Out <b class="tnum">${esc(money(-outflow))}</b></span>`;
  // phone entries not yet in Moneydance
  const pend = pendingWithStatus().filter(p => p.status !== 'imported');
  let html = '';
  if (pend.length && !f.q && f.acct === '' && f.cat === '') {
    html += `<div class="day-h"><span>From this phone — not in Moneydance yet</span></div>` + pend.map((p, i) => {
      const e = p.entry, a = S.M.byId.get(e.account), tg = S.M.byId.get(e.target);
      const amt = e.type === 'income' ? e.amount : -e.amount;
      return `<div class="tx ${i === 0 ? 'first' : ''} ${i === pend.length - 1 ? 'last' : ''}" data-p="${esc(p.id)}"><div class="main"><div class="p">${esc(e.payee || '(no payee)')} <span class="badge ${p.status === 'failed' ? 'fail' : ''}">${esc(p.label)}</span></div><div class="c">${esc((tg ? tg.label : '?') + ' · ' + (a ? a.name : '?') + ' · ' + dayLabel(e.date))}</div></div><div class="amt tnum ${amt > 0 ? 'pos' : ''}">${esc(money(amt, a && a.cur, { sign: amt > 0 }))}</div></div>`;
    }).join('');
  }
  const lim = Math.min(res.length, f.limit);
  let lastD = null;
  for (let i = 0; i < lim; i++) {
    const r = res[i]; const first = r.t.d !== lastD; const last = i === lim - 1 || res[i + 1].t.d !== r.t.d;
    if (first) { let dayTot = 0; for (let j = i; j < res.length && res[j].t.d === r.t.d; j++) dayTot += res[j].amt; html += `<div class="day-h"><span>${esc(dayLabel(r.t.d))}</span><span class="tnum" style="font-weight:500">${esc(money(dayTot, r.cur, { sign: dayTot > 0 }))}</span></div>`; }
    html += txRowHtml(r.t, r.amt, r.cur, (first ? 'first ' : '') + (last ? 'last' : ''), i);
    lastD = r.t.d;
  }
  if (!res.length) html += '<div class="empty">No transactions match these filters.</div>';
  if (res.length > lim) html += `<div style="text-align:center;margin:12px"><button class="btn ghost small" id="moreTx">Show more (${(res.length - lim).toLocaleString()} left)</button></div>`;
  $('#txList').innerHTML = html;
  $$('#txList .tx[data-t]').forEach(e => { if (e.dataset.t !== '') e.addEventListener('click', () => txDetail(res[+e.dataset.t].t)); });
  $$('#txList .tx[data-p]').forEach(e => e.addEventListener('click', () => pendingDetail(e.dataset.p)));
  const mb = $('#moreTx'); if (mb) mb.addEventListener('click', () => { f.limit += 300; renderTxns(); });
}
function txDetail(t) {
  const M = S.M, a = M.A[t.a];
  const st = { R: 'Reconciled', C: 'Cleared', '': 'Uncleared' }[t.st] || t.st;
  openSheet(`<div class="hero-label">${esc(dayLabel(t.d))}</div><div class="hero tnum ${t.v > 0 ? 'pos' : ''}" style="font-size:28px">${esc(money(t.v, a.cur, { sign: t.v > 0 }))}</div>
    <div style="font-size:17px;font-weight:600;margin-bottom:8px">${esc(t.p || '(no payee)')}</div>
    <div class="kv"><span>Account</span><span>${esc(a.label)}</span></div>
    ${t.sp.map(s => { const c = M.A[s.a]; return `<div class="kv"><span>${esc(c ? (c.isCat ? c.label : 'Transfer · ' + c.label) : '?')}${s.p ? `<br><small style="color:var(--muted)">${esc(s.p)}</small>` : ''}</span><span class="tnum">${esc(c && c.type === 'SECURITY' ? num(s.v) + ' shares' : money(-s.v, c && c.cur))}</span></div>`; }).join('')}
    ${t.m ? `<div class="kv"><span>Memo</span><span>${esc(t.m)}</span></div>` : ''}
    ${t.chk ? `<div class="kv"><span>Check #</span><span>${esc(t.chk)}</span></div>` : ''}
    <div class="kv"><span>Status</span><span>${esc(st)}</span></div>
    ${t.mid ? '<div class="kv"><span>Source</span><span>Entered on phone</span></div>' : ''}
    <div class="row" style="margin-top:14px;gap:8px"><button class="btn ghost" id="dupTx">Enter again</button><button class="btn ghost" id="payeeTx">All from this payee</button></div>`);
  $('#dupTx').addEventListener('click', () => {
    if (t.sp.length !== 1) { toast('Split transactions can’t be copied yet'); return; }
    const tg = M.A[t.sp[0].a]; closeSheet();
    S.addPrefill = { type: tg.isCat ? (tg.type === 'INCOME' ? 'income' : 'expense') : 'transfer', amount: Math.abs(t.v), payee: t.p, account: a.id, target: tg.id, memo: t.m };
    show('add');
  });
  $('#payeeTx').addEventListener('click', () => { closeSheet(); Object.assign(S.f, { q: t.p, acct: '', cat: '', period: 'all', type: '' }); show('txns'); });
}
(function bindFilters() {
  let qt;
  $('#q').addEventListener('input', e => { clearTimeout(qt); qt = setTimeout(() => { S.f.q = e.target.value; S.f.limit = 150; renderTxns(); }, 180); });
  const bind = (id, k) => $('#' + id).addEventListener('change', e => { S.f[k] = e.target.value; S.f.limit = 150; if (k === 'period' && e.target.value === 'custom') $('#moreBox').classList.add('open'); renderTxns(); });
  bind('fPeriod', 'period'); bind('fAcct', 'acct'); bind('fCat', 'cat'); bind('fType', 'type'); bind('fStatus', 'status');
  ['fFrom', 'fTo'].forEach((id, i) => $('#' + id).addEventListener('change', e => { S.f[i ? 'to' : 'from'] = e.target.value; S.f.period = 'custom'; renderTxns(); }));
  ['fMin', 'fMax'].forEach((id, i) => $('#' + id).addEventListener('input', e => { clearTimeout(qt); qt = setTimeout(() => { S.f[i ? 'max' : 'min'] = e.target.value; renderTxns(); }, 300); }));
  $('#fMore').addEventListener('click', () => $('#moreBox').classList.toggle('open'));
  $('#fReset').addEventListener('click', () => { Object.assign(S.f, { q: '', period: 'm0', acct: '', cat: '', type: '', min: '', max: '', status: '', from: '', to: '', limit: 150 }); renderTxns(); });
})();

/* ------------------------------------------------------------ Add entry + phone queue */
function pendingList() { return LS.get('pending', []); }
function savePending(l) { LS.set('pending', l); }
function pendingWithStatus() {
  const log = new Map(((S.raw && S.raw.log) || []).map(r => [r.id, r]));
  return pendingList().map(p => {
    let status = p.state === 'queued' ? 'queued' : 'sent', label = p.state === 'queued' ? 'Not uploaded yet' : 'Waiting for PC', msg = '';
    if (S.demo && p.state === 'queued') { label = 'Demo — not sent'; }
    if (S.M && S.M.mids.has(p.id)) { status = 'imported'; label = 'In Moneydance'; }
    else if (log.has(p.id)) { const r = log.get(p.id); if (r.status === 'failed') { status = 'failed'; label = 'Failed'; msg = r.msg; } else { status = 'imported'; label = 'In Moneydance'; } }
    return Object.assign({}, p, { status, label, msg });
  }).sort((a, b) => b.created - a.created);
}
async function flushQueue() {
  if (S.demo || !Dbx.connected() || !S.pass || !navigator.onLine) return 0;
  const list = pendingList(); let n = 0;
  for (const p of list) {
    if (p.state !== 'queued') continue;
    try { await Dbx.upload(`${FILES.inbox}/${p.id}.json.enc`, await encryptEnvelope(JSON.stringify(p.entry), S.pass), false); p.state = 'sent'; n++; }
    catch (e) { if (e.code === 409 && /conflict/.test(e.summary)) { p.state = 'sent'; } else { console.warn(e); break; } }
  }
  savePending(list);
  return n;
}
function prunePending() {
  const cut = Date.now() - 14 * 864e5;
  const st = new Map(pendingWithStatus().map(p => [p.id, p.status]));
  savePending(pendingList().filter(p => !(st.get(p.id) === 'imported' && p.created < cut)));
}
function acctOptions(list, sel) { return list.map(a => `<option value="${esc(a.id)}" ${a.id === sel ? 'selected' : ''}>${esc(a.isCat ? ' '.repeat(a.depth) + a.name : a.name)}</option>`).join(''); }
function renderAdd() {
  const M = S.M, t = S.addType, pre = S.addPrefill; S.addPrefill = null;
  if (pre) S.addType = pre.type;
  $$('#addType button').forEach(b => b.classList.toggle('on', b.dataset.t === S.addType));
  const real = M.A.filter(a => !a.isCat && !['SECURITY', 'ASSET'].includes(a.type) && !a.inactive);
  const lastAcct = (pre && pre.account) || $('#aAcct').value || LS.get('lastAcct') || (real[0] && real[0].id);
  $('#aAcct').innerHTML = acctOptions(real, lastAcct);
  fillTargets((pre && pre.target) || $('#aTarget').value);
  $('#aAcctLbl').textContent = S.addType === 'income' ? 'To account' : 'From account';
  $('#aTargetLbl').textContent = S.addType === 'transfer' ? 'To account' : 'Category';
  if (!$('#aDate').value) $('#aDate').value = intToIso(today());
  if (pre) { $('#aAmount').value = String(pre.amount); $('#aPayee').value = pre.payee || ''; $('#aMemo').value = pre.memo || ''; $('#aDate').value = intToIso(today()); }
  $('#payeeList').innerHTML = M.payees.map(([p]) => `<option value="${esc(p)}">`).join('');
  renderPending();
}
function fillTargets(sel) {
  const M = S.M, t = S.addType;
  let list;
  if (t === 'transfer') list = M.A.filter(a => !a.isCat && a.type !== 'SECURITY' && !a.inactive);
  else list = M.A.filter(a => a.type === (t === 'income' ? 'INCOME' : 'EXPENSE') && !a.inactive).sort((a, b) => a.full.localeCompare(b.full));
  $('#aTarget').innerHTML = (t === 'transfer' ? '' : '<option value="">Choose a category…</option>') + acctOptions(list, sel);
}
$$('#addType button').forEach(b => b.addEventListener('click', () => { S.addType = b.dataset.t; $$('#addType button').forEach(x => x.classList.toggle('on', x === b)); fillTargets(); $('#aAcctLbl').textContent = S.addType === 'income' ? 'To account' : 'From account'; $('#aTargetLbl').textContent = S.addType === 'transfer' ? 'To account' : 'Category'; }));
$('#aPayee').addEventListener('change', e => {
  if (!S.M) return; const hit = S.M.payeeMap.get(e.target.value.trim()); if (!hit) return;
  const t = hit.t; if (t.sp.length !== 1) return; const tg = S.M.A[t.sp[0].a];
  const kind = tg.isCat ? (tg.type === 'INCOME' ? 'income' : 'expense') : 'transfer';
  if (kind !== S.addType) { S.addType = kind; $$('#addType button').forEach(x => x.classList.toggle('on', x.dataset.t === kind)); }
  fillTargets(tg.id); $('#aAcct').value = S.M.A[t.a].id;
  $('#aAcctLbl').textContent = S.addType === 'income' ? 'To account' : 'From account'; $('#aTargetLbl').textContent = S.addType === 'transfer' ? 'To account' : 'Category';
  $('#aMsg').textContent = 'Filled in from your last “' + t.p + '” entry';
});
$('#addForm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const amount = parseAmt($('#aAmount').value), account = $('#aAcct').value, target = $('#aTarget').value, date = isoToInt($('#aDate').value);
  const msg = $('#aMsg');
  if (!(amount > 0)) { msg.textContent = 'Enter an amount above zero.'; $('#aAmount').focus(); return; }
  if (!target) { msg.textContent = 'Choose a category.'; return; }
  if (account === target) { msg.textContent = 'Pick two different accounts.'; return; }
  const a = S.M.byId.get(account), tg = S.M.byId.get(target);
  if (a && tg && a.cur !== tg.cur) { msg.textContent = 'Both sides must use the same currency.'; return; }
  if (!date) { msg.textContent = 'Choose a date.'; return; }
  const entry = { id: crypto.randomUUID(), v: 1, type: S.addType, date, account, target, amount: Math.round(amount * 100) / 100, payee: $('#aPayee').value.trim(), memo: $('#aMemo').value.trim(), created: new Date().toISOString() };
  const list = pendingList(); list.push({ id: entry.id, entry, state: 'queued', created: Date.now() }); savePending(list);
  LS.set('lastAcct', account);
  $('#aAmount').value = ''; $('#aPayee').value = ''; $('#aMemo').value = ''; msg.textContent = '';
  const n = await flushQueue().catch(() => 0);
  toast(S.demo ? 'Saved (demo — nothing is sent)' : n ? 'Sent — it will appear in Moneydance on the next bridge run' : 'Saved on this phone — will upload when online');
  renderPending();
});
function renderPending() {
  const l = pendingWithStatus().slice(0, 30);
  $('#pendingList').innerHTML = l.length ? l.map(p => { const e = p.entry, a = S.M.byId.get(e.account), tg = S.M.byId.get(e.target); const amt = e.type === 'income' ? e.amount : -e.amount;
    return `<div class="acct" data-p="${esc(p.id)}"><div class="n">${esc(e.payee || '(no payee)')} <span class="badge ${p.status === 'failed' ? 'fail' : p.status === 'imported' ? 'ok' : ''}">${p.status === 'imported' ? '✓ ' : p.status === 'failed' ? '✕ ' : ''}${esc(p.label)}</span><div style="font-size:12.5px;color:var(--muted)">${esc((tg ? tg.label : '?') + ' · ' + dayLabel(e.date))}</div></div><div class="a tnum ${amt > 0 ? 'pos' : ''}">${esc(money(amt, a && a.cur, { sign: amt > 0 }))}</div></div>`; }).join('') : '<div class="empty" style="padding:14px">Nothing entered on this phone yet.</div>';
  $$('#pendingList .acct').forEach(e => e.addEventListener('click', () => pendingDetail(e.dataset.p)));
}
function pendingDetail(id) {
  const p = pendingWithStatus().find(x => x.id === id); if (!p) return;
  const e = p.entry, a = S.M.byId.get(e.account), tg = S.M.byId.get(e.target);
  openSheet(`<div class="hero-label">${esc(dayLabel(e.date))} · entered on this phone</div><div class="hero tnum" style="font-size:28px">${esc(money(e.type === 'income' ? e.amount : -e.amount, a && a.cur))}</div>
    <div style="font-size:17px;font-weight:600;margin-bottom:8px">${esc(e.payee || '(no payee)')}</div>
    <div class="kv"><span>${e.type === 'transfer' ? 'To account' : 'Category'}</span><span>${esc(tg ? tg.label : '?')}</span></div>
    <div class="kv"><span>${e.type === 'income' ? 'To account' : 'From account'}</span><span>${esc(a ? a.label : '?')}</span></div>
    ${e.memo ? `<div class="kv"><span>Memo</span><span>${esc(e.memo)}</span></div>` : ''}
    <div class="kv"><span>Status</span><span>${esc(p.label)}${p.msg ? '<br><small style="color:var(--critical)">' + esc(p.msg) + '</small>' : ''}</span></div>
    ${p.status === 'imported' ? '' : `<p class="note">${p.status === 'failed' ? 'Moneydance couldn’t add this entry. Edit it and send it again.' : p.status === 'sent' ? 'Uploaded. Moneydance adds it the next time the bridge script runs on your PC. To change it now, edit it in Moneydance after it arrives.' : 'Still on this phone only. It uploads automatically when you’re online.'}</p>`}
    <div class="row" style="gap:8px;margin-top:10px">${p.status === 'failed' || p.status === 'queued' ? '<button class="btn ghost" id="pEdit">Edit</button>' : ''}${p.status !== 'sent' ? '<button class="btn ghost" id="pDel">Remove from list</button>' : ''}</div>`);
  const ed = $('#pEdit'), dl = $('#pDel');
  if (ed) ed.addEventListener('click', () => { savePending(pendingList().filter(x => x.id !== id)); closeSheet(); S.addPrefill = { type: e.type, amount: e.amount, payee: e.payee, account: e.account, target: e.target, memo: e.memo }; show('add'); });
  if (dl) dl.addEventListener('click', () => { savePending(pendingList().filter(x => x.id !== id)); closeSheet(); render(); });
}

/* ------------------------------------------------------------ Budgets */
function budgets() { return LS.get('budgets', { v: 1, updated: 0, items: {} }); }
async function saveBudgets(b) {
  b.updated = Date.now(); LS.set('budgets', b);
  if (!S.demo && Dbx.connected() && S.pass) { try { await Dbx.upload(FILES.budgets, await encryptEnvelope(JSON.stringify(b), S.pass), true); } catch (e) { toast('Budgets saved on phone; Dropbox upload failed'); } }
}
function budgetCalc(m) {
  const M = S.M, items = budgets().items, byIdx = new Map();
  for (const [id, amt] of Object.entries(items)) { const c = M.byId.get(id); if (c && amt > 0) byIdx.set(c.i, { c, budget: amt, spent: 0 }); }
  let unbudgeted = 0; const cm = M.catSpend.get(m) || new Map();
  cm.forEach((v, ci) => { let a = M.A[ci]; while (a && !byIdx.has(a.i)) a = a.parent != null ? M.A[a.parent] : null; if (a) byIdx.get(a.i).spent += v; else unbudgeted += v; });
  return { rows: Array.from(byIdx.values()).sort((a, b) => b.budget - a.budget), unbudgeted };
}
function renderBudgets() {
  const el = $('#v-budgets'), M = S.M, cm = ym(today());
  if (S.budgetMonth == null) S.budgetMonth = cm;
  const m = S.budgetMonth;
  if (S.editBudgets) return renderBudgetEdit();
  const { rows, unbudgeted } = budgetCalc(m);
  const frac = m === cm ? new Date().getDate() / daysIn(m) : m < cm ? 1 : 0;
  const tb = rows.reduce((s, r) => s + r.budget, 0), ts = rows.reduce((s, r) => s + r.spent, 0);
  const rowHtml = r => {
    const ratio = r.budget ? r.spent / r.budget : 0;
    const over = r.spent > r.budget + 0.004, warn = !over && frac < 1 && ratio > frac * 1.1 && ratio > 0.25;
    const left = r.budget - r.spent;
    return `<div class="bud"><div class="top-l"><span>${esc(r.c.label)}</span><span class="tnum"><b>${esc(money(r.spent))}</b> <span style="color:var(--muted)">/ ${esc(money(r.budget))}</span></span></div>
      <div class="meter ${over ? 'over' : warn ? 'warn' : ''}"><div class="f" style="width:${Math.min(100, Math.max(0, ratio) * 100)}%"></div>${frac > 0 && frac < 1 ? `<div class="pace" style="left:${frac * 100}%"></div>` : ''}</div>
      <div class="meta"><span>${over ? `<span class="status over">▲ Over by ${esc(money(-left))}</span>` : warn ? `<span class="status warn">⚠ Ahead of pace</span>` : esc(money(left)) + ' left'}</span><span>${esc(pct(Math.max(0, ratio)))}</span></div></div>`;
  };
  el.innerHTML = `<div class="month-nav"><button class="icon-btn" id="bPrev" aria-label="Previous month">‹</button><b>${esc(ymLabel(m, true))}</b><button class="icon-btn" id="bNext" aria-label="Next month" ${m >= cm ? 'disabled style="opacity:.3"' : ''}>›</button></div>
    ${rows.length ? `<div class="card"><div class="hero-label">Spent of budget</div><div class="hero tnum">${esc(money(ts))} <span style="font-size:18px;color:var(--muted);font-weight:500">/ ${esc(money(tb))}</span></div>
      <div class="meter ${ts > tb ? 'over' : ''}" style="height:12px"><div class="f" style="width:${Math.min(100, tb ? ts / tb * 100 : 0)}%"></div>${frac > 0 && frac < 1 ? `<div class="pace" style="left:${frac * 100}%"></div>` : ''}</div>
      <p class="sub" style="margin:8px 0 0">${frac > 0 && frac < 1 ? 'The thin mark shows where you’d be at an even pace for today. ' : ''}Unbudgeted spending: <b class="tnum">${esc(money(unbudgeted))}</b></p></div>
    <div class="card">${rows.map(rowHtml).join('')}</div>` : `<div class="card"><h2>No budgets yet</h2><p class="note">Set a monthly amount for the categories you want to keep an eye on. A budget on a parent category (like Food) also covers its subcategories.</p></div>`}
    <button class="btn ${rows.length ? 'ghost' : ''}" id="bEdit">${rows.length ? 'Edit budgets' : 'Set up budgets'}</button>
    <p class="note" style="text-align:center">Budgets are stored encrypted in your Dropbox app folder, so they’re the same on any phone you use.</p>`;
  $('#bPrev').addEventListener('click', () => { S.budgetMonth = ymAdd(m, -1); renderBudgets(); });
  $('#bNext').addEventListener('click', () => { if (m < cm) { S.budgetMonth = ymAdd(m, 1); renderBudgets(); } });
  $('#bEdit').addEventListener('click', () => { S.editBudgets = true; renderBudgets(); });
}
function renderBudgetEdit() {
  const M = S.M, el = $('#v-budgets'), b = budgets(), cm = ym(today());
  const cats = M.A.filter(a => a.type === 'EXPENSE' && !a.inactive).sort((a, x) => a.full.localeCompare(x.full));
  const avg = new Map(); for (let k = 1; k <= 3; k++) { const mm = M.catSpend.get(ymAdd(cm, -k)) || new Map(); cats.forEach(c => { let s = 0; descendants(c.i).forEach(d => s += mm.get(d) || 0); avg.set(c.i, (avg.get(c.i) || 0) + s / 3); }); }
  el.innerHTML = `<div class="card"><h2>Monthly budgets</h2><p class="sub">Leave empty for no budget. Grey numbers are your average over the last 3 months.</p>
    <button class="btn ghost small" id="bSuggest" style="margin-bottom:8px">Fill top-level categories from averages</button>
    ${cats.map(c => `<div class="bedit"><div class="n" style="padding-left:${c.depth * 14}px">${esc(c.name)}<small class="tnum">avg ${esc(money(avg.get(c.i) || 0))}</small></div><input class="inp tnum" inputmode="decimal" data-id="${esc(c.id)}" data-avg="${(avg.get(c.i) || 0).toFixed(2)}" data-top="${c.depth === 0 ? 1 : 0}" value="${b.items[c.id] ? b.items[c.id] : ''}" placeholder="—"></div>`).join('')}
    </div><div class="row" style="gap:8px"><button class="btn ghost" id="bCancel">Cancel</button><button class="btn" id="bSave">Save budgets</button></div>`;
  $('#bSuggest').addEventListener('click', () => $$('#v-budgets input[data-top="1"]').forEach(i => { const a = +i.dataset.avg; if (a > 0 && !i.value) i.value = Math.ceil(a / 10) * 10; }));
  $('#bCancel').addEventListener('click', () => { S.editBudgets = false; renderBudgets(); });
  $('#bSave').addEventListener('click', async () => {
    const items = {}; $$('#v-budgets input[data-id]').forEach(i => { const v = parseAmt(i.value); if (v > 0) items[i.dataset.id] = Math.round(v * 100) / 100; });
    await saveBudgets({ v: 1, items }); S.editBudgets = false; renderBudgets(); toast('Budgets saved');
  });
}

/* ------------------------------------------------------------ Investments */
function renderInvest() {
  const M = S.M, el = $('#v-invest');
  const inv = M.A.filter(a => a.type === 'INVESTMENT');
  if (!inv.length) { el.innerHTML = '<div class="card"><div class="empty">No investment accounts in Moneydance.</div></div>'; return; }
  let total = 0; const holdings = [];
  const cards = inv.map(a => {
    const secs = a.kids.map(k => M.A[k]).filter(s => s.type === 'SECURITY' && Math.abs(s.bal || 0) > 1e-9);
    const val = secs.reduce((s, x) => s + (x.balBase || 0), 0) + (a.balBase || 0);
    total += val; secs.forEach(s => holdings.push(s));
    if (a.inactive && Math.abs(val) < 0.005) return '';
    return `<div class="card"><div class="row"><h2 class="grow">${esc(a.name)}</h2><b class="tnum">${esc(money(val))}</b></div>
      ${secs.map(s => `<div class="hold"><div class="n">${esc(s.name)}${s.ticker ? ` <span style="color:var(--muted);font-size:12px">${esc(s.ticker)}</span>` : ''}</div><div class="v tnum">${esc(money(s.balBase || 0))}</div><div class="s tnum">${esc(num(s.bal))} × ${s.price != null ? esc(money(s.price)) : '?'}</div><div class="s r tnum">${val ? esc(pct((s.balBase || 0) / val)) : ''}</div></div>`).join('')}
      <div class="hold"><div class="n">Cash</div><div class="v tnum">${esc(money(a.bal || 0, a.cur))}</div></div></div>`;
  }).join('');
  holdings.sort((a, b) => (b.balBase || 0) - (a.balBase || 0));
  let items = holdings.map(h => ({ label: h.name, value: h.balBase || 0, text: pct(total ? (h.balBase || 0) / total : 0) }));
  if (items.length > 8) { const r = items.slice(7).reduce((s, x) => s + x.value, 0); items = items.slice(0, 7).concat([{ label: 'Other', value: r, text: pct(r / total) }]); }
  el.innerHTML = `<div class="card"><div class="hero-label">Total investments</div><div class="hero tnum">${esc(money(total))}</div><p class="sub" style="margin:0">Prices from Moneydance as of ${esc(ago(S.raw.generated))}</p></div>
    ${items.length ? `<div class="card"><h2>Allocation</h2><p class="sub">Share of all invested money, by holding</p>${barsHtml(items)}</div>` : ''}${cards}`;
}

/* ------------------------------------------------------------ Settings */
function renderSettings() {
  const el = $('#v-settings'), cfg = LS.get('cfg', {}), con = Dbx.connected();
  const chk = S.raw && S.raw.check;
  el.innerHTML = `
    ${!S.M && !S.demo ? `<div class="card"><h2>Welcome</h2><p class="note">This app shows your Moneydance data on your phone. It reads an encrypted file that the bridge script on your PC writes to Dropbox. Follow SETUP.md to create your Dropbox app, then fill in the key below.</p><button class="link" id="sDemo">Or look around with demo data first →</button></div>` : ''}
    <div class="card"><h2>Dropbox</h2><p class="sub">${con ? '✓ Connected' : 'Not connected'}</p>
      <div class="field"><span>App key (from the Dropbox App Console)</span><input class="inp" id="sKey" value="${esc(cfg.appKey || '')}" autocapitalize="off" autocomplete="off" spellcheck="false"></div>
      <div class="field"><span>Redirect URI to register in the App Console</span><div class="row"><code class="note grow" style="overflow-wrap:anywhere">${esc(Dbx.redirectUri())}</code><button class="btn ghost small" id="sCopy">Copy</button></div></div>
      ${con ? '<button class="btn ghost" id="sDisc">Disconnect Dropbox</button>' : '<button class="btn" id="sConn">Connect Dropbox</button>'}
    </div>
    <div class="card"><h2>Passphrase</h2><p class="sub">The same one you set in the bridge script. It never leaves this phone.</p>
      <div class="field"><input class="inp" type="password" id="sPass" placeholder="${S.pass ? '•••••••• (unlocked)' : 'Passphrase'}" autocomplete="current-password"></div>
      <label class="note" style="display:flex;gap:8px;align-items:center;margin-bottom:10px"><input type="checkbox" id="sRem" ${LS.get('pass') ? 'checked' : ''}> Remember on this phone (otherwise asked each time the app opens)</label>
      <div class="row" style="gap:8px"><button class="btn ghost" id="sPassSave">Save</button><button class="btn ghost" id="sLock">Lock now</button></div>
    </div>
    ${S.raw ? `<div class="card"><h2>Data from your PC</h2>
      <div class="kv"><span>Last update</span><span>${esc(new Date(S.raw.generated).toLocaleString())}</span></div>
      <div class="kv"><span>Transactions</span><span class="tnum">${S.M.T.length.toLocaleString()}</span></div>
      <div class="kv"><span>Accounts & categories</span><span class="tnum">${S.M.A.length}</span></div>
      <div class="kv"><span>Bridge version</span><span>${esc(S.raw.bridge || '?')}</span></div>
      ${chk ? `<div class="kv"><span>Balance check</span><span>${chk.bad ? `<span class="status over">⚠ ${chk.bad} account(s) differ</span>` : `✓ ${chk.ok} accounts match`}</span></div>` : ''}
      ${chk && chk.bad ? '<div class="warnbox">Some balances computed from the exported transactions don’t match Moneydance. Totals on this phone may be off for those accounts. The Moneybot console on your PC lists them.</div>' : ''}
    </div>` : ''}
    <div class="card"><h2>Appearance</h2><select class="inp" id="sTheme"><option value="">Follow phone setting</option><option value="light">Light</option><option value="dark">Dark</option></select></div>
    <div class="card"><h2>This phone</h2>
      ${S.demo ? '<button class="btn ghost" id="sExitDemo" style="margin-bottom:8px">Exit demo</button>' : ''}
      <button class="btn ghost" id="sWipe">Remove all app data from this phone</button>
      <p class="note">Removes the cached copy, passphrase, Dropbox login and unsent entries from this phone. Your Moneydance data and Dropbox files are not touched.</p>
      <p class="note" style="color:var(--muted)">MD Mobile ${APP_VERSION}</p></div>`;
  $('#sTheme').value = LS.get('theme') || '';
  $('#sTheme').addEventListener('change', e => { LS.set('theme', e.target.value || null); applyTheme(); });
  $('#sKey').addEventListener('change', e => { const c = LS.get('cfg', {}); c.appKey = e.target.value.trim(); LS.set('cfg', c); });
  $('#sCopy').addEventListener('click', () => navigator.clipboard.writeText(Dbx.redirectUri()).then(() => toast('Copied'), () => toast('Copy failed — select the text instead')));
  const cn = $('#sConn'); if (cn) cn.addEventListener('click', () => { const c = LS.get('cfg', {}); c.appKey = $('#sKey').value.trim(); LS.set('cfg', c); Dbx.login().catch(e => toast(e.message)); });
  const dc = $('#sDisc'); if (dc) dc.addEventListener('click', () => { LS.set('tok', null); renderSettings(); toast('Disconnected'); });
  $('#sPassSave').addEventListener('click', async () => { const p = $('#sPass').value; if (p) await unlock(p, $('#sRem').checked); else { LS.set('pass', $('#sRem').checked && S.pass ? S.pass : null); toast('Saved'); } });
  $('#sLock').addEventListener('click', () => { S.pass = null; LS.set('pass', null); keyCache.clear(); S.raw = S.M = null; showLock(); });
  const dm = $('#sDemo'); if (dm) dm.addEventListener('click', () => startDemo());
  const xd = $('#sExitDemo'); if (xd) xd.addEventListener('click', () => { LS.set('demo', null); location.hash = ''; location.reload(); });
  $('#sWipe').addEventListener('click', async () => {
    if (!$('#sWipe').dataset.sure) { $('#sWipe').dataset.sure = 1; $('#sWipe').textContent = 'Tap again to confirm'; $('#sWipe').style.color = 'var(--critical)'; return; }
    try { Object.keys(localStorage).filter(k => k.startsWith('mdm.')).forEach(k => localStorage.removeItem(k)); } catch { }
    await IDB.clear(); location.reload();
  });
}
function applyTheme() { const t = LS.get('theme'); if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; }

/* ------------------------------------------------------------ lock / unlock / sync */
function showLock() { show('lock'); $('#unlockPass').value = ''; $('#unlockErr').textContent = ''; setTimeout(() => $('#unlockPass').focus(), 50); }
$('#unlockForm').addEventListener('submit', async ev => { ev.preventDefault(); await unlock($('#unlockPass').value, $('#unlockRemember').checked); });
async function unlock(pass, remember) {
  const env = await IDB.get('export');
  if (env) {
    try { await load(await decryptEnvelope(env.text, pass)); }
    catch (e) { $('#unlockErr').textContent = e.code === 'pass' ? 'That passphrase doesn’t open your data.' : e.message; toast(e.code === 'pass' ? 'Wrong passphrase' : e.message); return false; }
  }
  S.pass = pass; LS.set('pass', remember ? pass : null);
  if (S.view === 'lock') show(S.M ? 'home' : 'settings');
  sync(false);
  return true;
}
async function load(text) {
  const raw = JSON.parse(text);
  if (raw.v !== 1) throw new Error('This export needs a newer app version');
  S.raw = raw; S.M = buildModel(raw); fmtCache.clear();
  $('#fAcct').innerHTML = ''; // refill filter lists on next view
}
async function sync(manual) {
  if (S.demo) { if (manual) toast('Demo data — nothing to sync'); return; }
  if (S.syncing) return;
  if (!Dbx.connected()) { if (manual) { toast('Connect Dropbox in Settings first'); show('settings'); } return; }
  if (!S.pass) { showLock(); return; }
  if (!navigator.onLine) { if (manual) toast('You’re offline — showing the last downloaded data'); return; }
  S.syncing = true; updateSyncInfo();
  const hadData = !!S.M;
  try {
    await flushQueue();
    const meta = await Dbx.meta(FILES.export);
    if (!meta) { toast('No export in Dropbox yet — run the bridge script on your PC'); }
    else {
      const cached = await IDB.get('export');
      if (!cached || cached.rev !== meta.rev || manual) {
        const text = await Dbx.download(FILES.export);
        const json = await decryptEnvelope(text, S.pass);
        await IDB.set('export', { rev: meta.rev, text });
        await load(json);
      }
    }
    // budgets: newest wins
    const bt = await Dbx.download(FILES.budgets).catch(() => null);
    if (bt) { try { const rb = JSON.parse(await decryptEnvelope(bt, S.pass)); if ((rb.updated || 0) > (budgets().updated || 0)) LS.set('budgets', rb); } catch { } }
    else if (Object.keys(budgets().items).length) saveBudgets(budgets());
    prunePending();
    if (!hadData && S.M && S.view === 'settings') { S.syncing = false; show('home'); }
    if (manual) toast('Up to date');
  } catch (e) {
    console.error(e);
    toast(e.code === 'pass' ? 'The passphrase doesn’t match the file on Dropbox' : e.message || 'Sync failed');
    if (e.code === 'pass') { S.pass = null; LS.set('pass', null); showLock(); }
  } finally {
    S.syncing = false;
    if (S.M && S.view === 'settings' && !manual) { /* stay */ }
    render();
  }
}
window.addEventListener('online', () => sync(false));
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && S.raw && Date.now() - (S._lastAuto || 0) > 120000) { S._lastAuto = Date.now(); sync(false); } });

/* ------------------------------------------------------------ demo data */
function demoExport() {
  let seed = 7; const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const r = (a, b) => Math.round((a + rnd() * (b - a)) * 100) / 100;
  const acc = [];
  const add = (name, type, parent, extra) => { const i = acc.length; const p = parent != null ? acc[parent] : null; acc.push(Object.assign({ id: 'demo-' + i, name, full: p ? p.full + ':' + name : name, type, parent: parent != null ? parent : null, cur: 'EUR', inactive: false }, extra || {})); return i; };
  const cur = add('Current account', 'BANK'), sav = add('Savings', 'BANK'), cc = add('Credit card', 'CREDIT_CARD'), brk = add('Brokerage', 'INVESTMENT');
  const etf = add('Global Equity ETF', 'SECURITY', brk, { cur: 'GEQ', ticker: 'GEQ', price: 112.4 }), bond = add('Euro Bond Fund', 'SECURITY', brk, { cur: 'EBF', ticker: 'EBF', price: 48.9 });
  const car = add('Car', 'ASSET'), loan = add('Car loan', 'LOAN');
  const H = add('Housing', 'EXPENSE'), rent = add('Rent', 'EXPENSE', H), energy = add('Energy', 'EXPENSE', H), net = add('Internet & phone', 'EXPENSE', H);
  const F = add('Food', 'EXPENSE'), groc = add('Groceries', 'EXPENSE', F), rest = add('Restaurants', 'EXPENSE', F);
  const Tr = add('Transport', 'EXPENSE'), fuel = add('Fuel', 'EXPENSE', Tr), pt = add('Public transport', 'EXPENSE', Tr);
  const L = add('Leisure', 'EXPENSE'), subs = add('Subscriptions', 'EXPENSE', L), travel = add('Travel', 'EXPENSE', L), sport = add('Sport', 'EXPENSE', L);
  const health = add('Health', 'EXPENSE'), shop = add('Shopping', 'EXPENSE'), gifts = add('Gifts', 'EXPENSE'), interest = add('Loan interest', 'EXPENSE');
  const sal = add('Salary', 'INCOME'), intInc = add('Interest', 'INCOME'), side = add('Handmade sales', 'INCOME');
  const T = []; const td = today();
  const tx = (d, a, v, p, sp, m) => { if (d <= td) T.push([d, a, Math.round(v * 100) / 100, p, m || '', d < td - 20 ? 'R' : '', '', sp]); };
  const exp = (d, a, cat, amt, p) => tx(d, a, -amt, p, [[cat, amt]]);
  const start = ymAdd(ym(td), -17);
  for (let k = 0; k < 18; k++) {
    const m = ymAdd(start, k), D = day => m * 100 + Math.min(day, daysIn(m));
    tx(D(10), cur, 2850, 'Employer s.r.o.', [[sal, -2850]], 'Salary');
    exp(D(1), cur, rent, 850, 'Landlord'); exp(D(15), cur, energy, r(85, 140), 'Energy supplier'); exp(D(18), cur, net, 32.9, 'Telecom');
    exp(D(3), cc, subs, 12.99, 'Streaming service'); exp(D(7), cc, subs, 5.99, 'Cloud storage');
    for (let i = 0; i < 9; i++) exp(D(1 + Math.floor(rnd() * 28)), rnd() < .6 ? cc : cur, groc, r(18, 95), ['Supermarket', 'Corner shop', 'Bakery', 'Farmers market', 'Discount store'][Math.floor(rnd() * 5)]);
    for (let i = 0; i < 4; i++) exp(D(1 + Math.floor(rnd() * 28)), cc, rest, r(12, 68), ['Bistro', 'Pizzeria', 'Café', 'Sushi bar'][Math.floor(rnd() * 4)]);
    for (let i = 0; i < 2; i++) exp(D(5 + Math.floor(rnd() * 20)), cc, fuel, r(48, 72), 'Fuel station');
    exp(D(2), cur, pt, 26, 'City transport pass'); exp(D(12), cc, sport, 39, 'Gym');
    if (rnd() < .5) exp(D(20), cc, shop, r(25, 180), ['Online store', 'Bookshop', 'Hardware store'][Math.floor(rnd() * 3)]);
    if (rnd() < .3) exp(D(22), cc, health, r(15, 70), 'Pharmacy');
    if (m % 100 === 7 || m % 100 === 12) exp(D(14), cc, travel, r(400, 900), 'Holiday booking');
    if (m % 100 === 12) exp(D(18), cc, gifts, r(150, 300), 'Gift shop');
    if (rnd() < .6) tx(D(25), cur, r(40, 160), 'Etsy payout', [[side, 0]]);
    tx(D(11), cur, -300, 'Transfer to savings', [[sav, 300]]);
    tx(D(28), sav, r(3, 6), 'Interest', [[intInc, 0]]);
    tx(D(16), cur, -250, 'Car loan payment', [[loan, 215], [interest, 35]]);
    tx(D(12), cur, -200, 'Transfer to broker', [[brk, 200]]);
    const sh = Math.round(150 / r(95, 113) * 10000) / 10000; tx(D(13), brk, -150, 'Buy Global Equity ETF', [[etf, sh]]);
    const sb = Math.round(50 / r(46, 50) * 10000) / 10000; tx(D(13), brk, -50, 'Buy Euro Bond Fund', [[bond, sb]]);
  }
  // fix zero-amount income splits (amount = -parent), and credit card payments
  T.forEach(t => t[7].forEach(s => { if (s[1] === 0) s[1] = -t[2]; }));
  for (let k = 1; k < 18; k++) { const m = ymAdd(start, k), pm = ymAdd(m, -1); let owed = 0; T.forEach(t => { if (t[1] === cc && ym(t[0]) === pm) owed += t[2]; }); if (owed < 0) tx(m * 100 + 5, cur, owed, 'Credit card payment', [[cc, -owed]]); }
  const startBal = { [cur]: 3200, [sav]: 6000, [cc]: 0, [brk]: 0, [etf]: 20, [bond]: 10, [car]: 14000, [loan]: -9500 };
  const bal = Object.assign({}, startBal);
  T.forEach(t => { bal[t[1]] = (bal[t[1]] || 0) + t[2]; t[7].forEach(s => { if (!CAT.has(acc[s[0]].type)) bal[s[0]] = (bal[s[0]] || 0) + s[1]; }); });
  acc.forEach((a, i) => { if (CAT.has(a.type)) return; const b = Math.round((bal[i] || 0) * 10000) / 10000; a.bal = b; a.balBase = a.type === 'SECURITY' ? Math.round(b * a.price * 100) / 100 : b; });
  const pid = 'demo-phone-1';
  T.push([td - (td % 100 > 1 ? 1 : 0), cc, -23.4, 'Bakery', 'entered on phone', '', '', [[groc, 23.4]], pid]);
  return { v: 1, bridge: 'demo', generated: new Date(Date.now() - 25 * 60000).toISOString(), base: 'EUR',
    currencies: { EUR: { name: 'Euro', dp: 2, prefix: '€', suffix: '', toBase: 1 }, GEQ: { name: 'Global Equity ETF', dp: 4, toBase: 112.4 }, EBF: { name: 'Euro Bond Fund', dp: 4, toBase: 48.9 } },
    accounts: acc, txns: T, check: { ok: 8, bad: 0, sign: 1 }, log: [{ id: pid, status: 'imported', at: new Date().toISOString() }] };
}
async function startDemo() {
  S.demo = true; LS.set('demo', 1);
  if (!Object.keys(budgets().items).length) LS.set('budgets', { v: 1, updated: 1, items: { 'demo-12': 450, 'demo-8': 1050, 'demo-15': 220, 'demo-19': 150 } });
  await load(JSON.stringify(demoExport()));
  show('home');
}

/* ------------------------------------------------------------ boot */
(async function boot() {
  applyTheme();
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => { });
  if (location.hash === '#demo' || LS.get('demo')) { await startDemo(); return; }
  try { if (await Dbx.handleRedirect()) toast('Dropbox connected'); } catch (e) { toast(e.message); }
  S.pass = LS.get('pass');
  const env = await IDB.get('export');
  if (env && S.pass) {
    try { await load(await decryptEnvelope(env.text, S.pass)); show('home'); }
    catch (e) { S.pass = null; showLock(); return; }
    sync(false); return;
  }
  if (env || (Dbx.connected() && !S.pass)) { showLock(); return; }
  show('settings');
  if (Dbx.connected() && S.pass) sync(false);
})();
