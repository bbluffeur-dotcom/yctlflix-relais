/*
 * yctlflix — relais + catalogue (tourne sur votre ordinateur)
 * -----------------------------------------------------------
 *  - garde les sources Xtream (identifiants chiffrés) et le catalogue (SQLite)
 *  - importe tout une fois, puis seulement les nouveautés
 *  - répond au site base44 : catalogue, recherche, jaquettes, fiches
 *  - relaie la lecture (jeton signé, Range, HLS réécrit) et convertit le son en AAC
 *  - vérifie les codes d'accès et les quotas (connexions, appareils, téléchargements)
 *
 *  Aucune dépendance à installer : Node 22.13 ou plus récent, et ffmpeg (facultatif).
 */
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { parseLine } from './parse.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA = process.env.DATA || path.join(HERE, 'data');
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';           // 0.0.0.0 pour un hébergeur en ligne (Railway, Docker…)
const FFMPEG = process.env.FFMPEG || 'ffmpeg';
const FFPROBE = process.env.FFPROBE || 'ffprobe';
const UA = 'VLC/3.0.20 LibVLC/3.0.20';
const VERSION = '1.0.0';

fs.mkdirSync(path.join(DATA, 'img'), { recursive: true });

/* ------------------------------------------------------------------ */
/* Réglages et clé (générés au premier démarrage, jamais saisis)       */
/* ------------------------------------------------------------------ */
const CFG_FILE = path.join(DATA, 'config.json');
const PW_FILE = path.join(DATA, 'MOT-DE-PASSE-ADMIN.txt');
let cfg;
function saveCfg() { fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 }); }
function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPw(pw, stored) {
  const [salt, h] = String(stored || '').split(':');
  if (!salt || !h) return false;
  const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(String(pw), salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
let firstPassword = null;
if (fs.existsSync(CFG_FILE)) cfg = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
else {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  firstPassword = Array.from(crypto.randomBytes(12), b => alphabet[b % alphabet.length]).join('');
  cfg = {
    secret: crypto.randomBytes(32).toString('hex'),     // 64 caractères hexadécimaux
    adminHash: hashPw(firstPassword),
    origins: [],                                         // sites autorisés (CORS) ; vide = tous
    adminRemote: false,                                  // admin depuis l'extérieur : non par défaut
    importParallel: 3,
    listTimeoutSec: 120,
  };
  saveCfg();
  fs.writeFileSync(PW_FILE, `Mot de passe administrateur du relais :\n\n${firstPassword}\n\n(Supprimez ce fichier après l'avoir noté.)\n`);
}
if (process.env.ADMIN_REMOTE === '1') cfg.adminRemote = true;   // administration depuis Internet (protégée par mot de passe)
if (process.env.ADMIN_REMOTE === '0') cfg.adminRemote = false;
if (process.env.SECRET && process.env.SECRET.length >= 32) cfg.secret = process.env.SECRET;        // mode sans disque : réglages dans les variables
if (process.env.ADMIN_PASSWORD && process.env.ADMIN_PASSWORD.length >= 8) cfg.adminHash = hashPw(process.env.ADMIN_PASSWORD);
const KEY = crypto.createHash('sha256').update(cfg.secret).digest();
const enc = (t) => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(String(t), 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString('base64url')).join('.');
};
const dec = (s) => {
  const [iv, tag, ct] = String(s).split('.').map(x => Buffer.from(x, 'base64url'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
};
const hmac = (s) => crypto.createHmac('sha256', cfg.secret).update(s).digest('base64url');

/* ------------------------------------------------------------------ */
/* Base de données                                                     */
/* ------------------------------------------------------------------ */
const db = new DatabaseSync(path.join(DATA, 'yctlflix.db'));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS sources(n INTEGER PRIMARY KEY, name TEXT, server TEXT, user TEXT, pass TEXT,
  active INTEGER DEFAULT 1, expiry INTEGER, maxconn TEXT, last_error TEXT);
CREATE TABLE IF NOT EXISTS titles(src INTEGER, type TEXT, sid TEXT, title TEXT, norm TEXT, cat TEXT, img TEXT,
  rating TEXT, added INTEGER, ext TEXT, status TEXT DEFAULT 'actif', PRIMARY KEY(src,type,sid)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS t_list ON titles(type,status,added);
CREATE INDEX IF NOT EXISTS t_src  ON titles(src,type,status);
CREATE INDEX IF NOT EXISTS t_cat  ON titles(type,cat);
CREATE INDEX IF NOT EXISTS t_az   ON titles(type,status,norm);
CREATE TABLE IF NOT EXISTS codes(code TEXT PRIMARY KEY, label TEXT, active INTEGER DEFAULT 1, max_conn INTEGER DEFAULT 1,
  max_devices INTEGER DEFAULT -1, can_download INTEGER DEFAULT 0, max_dl_day INTEGER DEFAULT 0, expires INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS devices(code TEXT, device TEXT, last INTEGER, PRIMARY KEY(code,device));
CREATE TABLE IF NOT EXISTS dl(code TEXT, day TEXT, n INTEGER, PRIMARY KEY(code,day));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS log(t INTEGER, who TEXT, what TEXT);
CREATE TABLE IF NOT EXISTS profiles(code TEXT, id INTEGER, name TEXT, kids INTEGER DEFAULT 0, color TEXT, PRIMARY KEY(code,id));
CREATE TABLE IF NOT EXISTS favs(code TEXT, profile INTEGER, src INTEGER, type TEXT, sid TEXT, title TEXT, img TEXT, ts INTEGER,
  PRIMARY KEY(code,profile,src,type,sid));
CREATE TABLE IF NOT EXISTS hist(code TEXT, profile INTEGER, src INTEGER, type TEXT, sid TEXT, title TEXT, img TEXT, pos REAL, dur REAL, meta TEXT, ts INTEGER,
  PRIMARY KEY(code,profile,src,type,sid));
`);
try { db.exec('ALTER TABLE codes ADD COLUMN max_profiles INTEGER DEFAULT 5'); } catch {}
const q = (sql, ...a) => db.prepare(sql).all(...a);
const q1 = (sql, ...a) => db.prepare(sql).get(...a);
const run = (sql, ...a) => db.prepare(sql).run(...a);
const setMeta = (k, v) => run('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, JSON.stringify(v));
const getMeta = (k) => { const r = q1('SELECT v FROM meta WHERE k=?', k); return r ? JSON.parse(r.v) : null; };
const audit = (who, what) => run('INSERT INTO log(t,who,what) VALUES(?,?,?)', Date.now(), who, what);

const fold = (s) => String(s ?? '').normalize('NFD').replace(/\p{M}/gu, '').toLowerCase()
  .replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const TYPES = ['film', 'serie', 'chaine'];

function srcRow(n) {
  const r = q1('SELECT * FROM sources WHERE n=?', n);
  if (!r) return null;
  return { ...r, user: dec(r.user), pass: dec(r.pass) };
}
let activeCache = null;
const activeSources = () => (activeCache ??= q('SELECT n FROM sources WHERE active=1').map(r => r.n));
const catsCache = new Map();
const resetCaches = () => { activeCache = null; fuzzy.clear(); countsCache = null; catsCache.clear(); };

/* ------------------------------------------------------------------ */
/* Appels Xtream (toujours depuis ce programme, jamais du navigateur)   */
/* ------------------------------------------------------------------ */
class SrcErr extends Error { constructor(m, retry = false) { super(m); this.retry = retry; } }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function xcall(src, action, { timeout = 120000, tries = 3, extra = {} } = {}) {
  const p = new URLSearchParams({ username: src.user, password: src.pass, ...extra });
  if (action) p.set('action', action);
  const url = `${src.server}/player_api.php?${p}`;
  let last;
  for (let a = 1; a <= tries; a++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/json' }, signal: AbortSignal.timeout(timeout) });
      if ([401, 403, 884].includes(r.status)) throw new SrcErr(`Le fournisseur refuse la connexion (HTTP ${r.status}) : identifiants refusés ou adresse de ce serveur bloquée`);
      if (r.status === 404) throw new SrcErr('player_api.php introuvable (HTTP 404) : ce n\'est pas un serveur Xtream Codes');
      if (r.status >= 500) throw new SrcErr(`Erreur du fournisseur (HTTP ${r.status})`, true);
      if (!r.ok) throw new SrcErr(`Réponse HTTP ${r.status}`);
      const text = await r.text();
      try { return JSON.parse(text); }
      catch {
        const t = text.slice(0, 160).replace(/\s+/g, ' ');
        if (/stalker|mag\d|portal/i.test(text)) throw new SrcErr('Portail Stalker / adresse MAC : format non pris en charge (il faut un compte Xtream Codes)');
        throw new SrcErr(`Le serveur n'a pas répondu comme un serveur Xtream : « ${t} »`);
      }
    } catch (e) {
      const timeoutErr = e?.name === 'TimeoutError' || e?.name === 'AbortError';
      const net = !(e instanceof SrcErr);
      const msg = timeoutErr ? `Délai dépassé (${Math.round(timeout / 1000)} s)` : net ? `Serveur injoignable (${e?.cause?.code || e.message})` : e.message;
      last = new SrcErr(msg, timeoutErr || net || e.retry);
      if (!last.retry || a === tries) break;
      await sleep(1000 * 2 ** (a - 1));
    }
  }
  throw last;
}

async function testSource(row) {
  try {
    const j = await xcall(row, null, { timeout: 15000, tries: 1 });
    const ui = j?.user_info;
    if (!ui) return { ok: false, message: 'Réponse sans user_info : ce n\'est pas un serveur Xtream' };
    if (Number(ui.auth) !== 1) return { ok: false, message: 'Identifiants refusés par le fournisseur' };
    const exp = ui.exp_date ? new Date(Number(ui.exp_date) * 1000) : null;
    const st = String(ui.status || '').toLowerCase();
    if (st && st !== 'active') return { ok: false, message: `Abonnement ${ui.status}`, exp };
    if (exp && exp < new Date()) return { ok: false, message: `Abonnement expiré le ${exp.toLocaleDateString('fr-FR')}`, exp };
    run('UPDATE sources SET expiry=?, maxconn=?, last_error=NULL WHERE n=?', exp ? exp.getTime() : null, String(ui.max_connections ?? ''), row.n);
    return { ok: true, message: `OK — abonnement actif${exp ? ' jusqu\'au ' + exp.toLocaleDateString('fr-FR') : ''}, ${ui.max_connections ?? '?'} connexion(s) autorisée(s)` };
  } catch (e) {
    run('UPDATE sources SET last_error=? WHERE n=?', e.message, row.n);
    return { ok: false, message: e.message };
  }
}

/* ------------------------------------------------------------------ */
/* Import : complet une fois, puis nouveautés                          */
/* ------------------------------------------------------------------ */
const MAP = {
  film: { act: 'get_vod_streams', cats: 'get_vod_categories', id: x => x.stream_id,
    row: x => ({ img: x.stream_icon, rating: x.rating, added: x.added, ext: x.container_extension || 'mp4' }) },
  serie: { act: 'get_series', cats: 'get_series_categories', id: x => x.series_id,
    row: x => ({ img: x.cover, rating: x.rating, added: x.last_modified, ext: '' }) },
  chaine: { act: 'get_live_streams', cats: 'get_live_categories', id: x => x.stream_id,
    row: x => ({ img: x.stream_icon, rating: '', added: x.added, ext: '' }) },
};
const imp = { running: false, startedAt: null, finishedAt: null, mode: null, items: [], log: [] };
const ilog = (m) => { imp.log.push(`${new Date().toLocaleTimeString('fr-FR')}  ${m}`); if (imp.log.length > 300) imp.log.shift(); };

const insertSql = (upsert) => `INSERT INTO titles(src,type,sid,title,norm,cat,img,rating,added,ext,status) VALUES(?,?,?,?,?,?,?,?,?,?,'actif')` +
  (upsert ? ` ON CONFLICT(src,type,sid) DO UPDATE SET title=excluded.title,norm=excluded.norm,cat=excluded.cat,img=excluded.img,rating=excluded.rating,added=excluded.added,ext=excluded.ext,status='actif'`
    : ' ON CONFLICT(src,type,sid) DO NOTHING');

async function writeBatches(rows, upsert, onBatch) {
  const st = db.prepare(insertSql(upsert));
  for (let i = 0; i < rows.length; i += 500) {
    const part = rows.slice(i, i + 500);
    let tries = 0;
    for (;;) {
      try {
        db.exec('BEGIN');
        for (const r of part) st.run(...r);
        db.exec('COMMIT');
        break;
      } catch (e) {
        try { db.exec('ROLLBACK'); } catch {}
        if (++tries >= 3) throw new Error('Écriture impossible après 3 essais : ' + e.message);
        await sleep(500 * tries);
      }
    }
    onBatch(part.length);
    await new Promise(r => setImmediate(r));
  }
}

async function importType(src, type, mode, it) {
  const M = MAP[type];
  it.state = 'lecture';
  let catList = [];
  try { catList = await xcall(src, M.cats, { timeout: cfg.listTimeoutSec * 1000 }); } catch {}
  const catName = new Map((Array.isArray(catList) ? catList : []).map(c => [String(c.category_id), String(c.category_name || '').trim()]));
  const list = await xcall(src, M.act, { timeout: cfg.listTimeoutSec * 1000 });
  if (!Array.isArray(list)) throw new Error('Liste de titres absente dans la réponse du fournisseur');

  const rows = new Map();                                  // sid -> ligne prête
  for (const x of list) {
    const id = M.id(x);
    if (id == null || !x?.name) continue;
    const sid = String(id);
    if (rows.has(sid)) continue;
    const e = M.row(x);
    const cat = catName.get(String(x.category_id)) || 'Sans catégorie';
    rows.set(sid, [src.n, type, sid, String(x.name).trim(), fold(x.name), cat, String(e.img || ''), String(e.rating || ''), Number(e.added) || 0, e.ext]);
  }
  it.expected = rows.size;
  setMeta(`expected:${src.n}:${type}`, { n: rows.size, at: Date.now() });

  const existing = new Map(q('SELECT sid,status FROM titles WHERE src=? AND type=?', src.n, type).map(r => [r.sid, r.status]));
  if (rows.size === 0 && existing.size > 0) throw new Error('Le fournisseur a renvoyé une liste vide : les anciens titres sont conservés');

  it.state = 'écriture';
  const full = mode === 'full';
  const toWrite = [...rows.entries()].filter(([sid]) => full || !existing.has(sid)).map(([, r]) => r);
  it.added = [...rows.keys()].filter(s => !existing.has(s)).length;
  await writeBatches(toWrite, full, () => {});

  // retirés / revenus : jamais de suppression
  const gone = [...existing].filter(([sid, s]) => !rows.has(sid) && s === 'actif').map(([sid]) => sid);
  const back = [...existing].filter(([sid, s]) => rows.has(sid) && s === 'retire').map(([sid]) => sid);
  const flip = (ids, status) => {
    const st = db.prepare('UPDATE titles SET status=? WHERE src=? AND type=? AND sid=?');
    for (let i = 0; i < ids.length; i += 500) {
      db.exec('BEGIN'); for (const s of ids.slice(i, i + 500)) st.run(status, src.n, type, s); db.exec('COMMIT');
    }
  };
  flip(gone, 'retire'); flip(back, 'actif');
  it.removed = gone.length; it.returned = back.length;

  // contrôle : attendu / enregistré, seuls les manquants sont réécrits (5 essais)
  it.state = 'contrôle';
  let missing = [];
  for (let k = 0; k < 5; k++) {
    const have = new Set(q(`SELECT sid FROM titles WHERE src=? AND type=? AND status='actif'`, src.n, type).map(r => r.sid));
    missing = [...rows.keys()].filter(s => !have.has(s));
    it.saved = rows.size - missing.length;
    if (!missing.length) break;
    await writeBatches(missing.map(s => rows.get(s)), true, () => {});
  }
  it.missing = missing.length;
  it.state = missing.length ? 'incomplet' : 'terminé';
  if (missing.length) it.error = `${missing.length} titre(s) manquant(s) après 5 essais`;
  ilog(`Source ${src.n} ${type} : ${it.saved}/${it.expected}` + (mode === 'news' ? ` (+${it.added}, −${it.removed}, ↺${it.returned})` : ''));
}

async function runImport(mode, only) {
  if (imp.running) throw httpErr(409, 'Un import est déjà en cours');
  const list = q('SELECT n FROM sources WHERE active=1' + (only ? ' AND n=?' : ' ORDER BY n'), ...(only ? [only] : []));
  if (!list.length) throw httpErr(400, 'Aucune source active à importer');
  imp.running = true; imp.mode = mode; imp.startedAt = Date.now(); imp.finishedAt = null; imp.log = [];
  imp.items = list.flatMap(({ n }) => TYPES.map(type => ({ src: n, type, state: 'attente', expected: 0, saved: 0, missing: 0, added: 0, removed: 0, returned: 0, error: null })));
  ilog(mode === 'full' ? 'Import complet' : 'Import des nouveautés');
  const queue = list.map(r => r.n);
  const worker = async () => {
    while (queue.length) {
      const n = queue.shift();
      const src = srcRow(n);
      const mine = imp.items.filter(i => i.src === n);
      const t = await testSource(src);
      if (!t.ok) { for (const it of mine) { it.state = 'échec'; it.error = t.message; } ilog(`Source ${n} : ${t.message}`); continue; }
      for (const it of mine) {
        try { await importType(src, it.type, mode, it); }
        catch (e) { it.state = 'échec'; it.error = e.message; ilog(`Source ${n} ${it.type} : ${e.message}`); run('UPDATE sources SET last_error=? WHERE n=?', e.message, n); }
      }
    }
  };
  (async () => {
    try { await Promise.all(Array.from({ length: Math.min(cfg.importParallel, queue.length) }, worker)); }
    finally {
      imp.running = false; imp.finishedAt = Date.now();
      resetCaches();
      setMeta('lastImport', { mode, at: imp.finishedAt, items: imp.items });
      audit('admin', `import ${mode}`);
      ilog('Terminé');
    }
  })();
}

/* ------------------------------------------------------------------ */
/* Recherche souple                                                    */
/* ------------------------------------------------------------------ */
const fuzzy = new Map();
function lev1(a, b) {                     // distance de Levenshtein ≤ 1 ?
  if (a === b) return true;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  let i = 0, j = 0, d = 0;
  while (i < la && j < lb) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++d > 1) return false;
    if (la > lb) i++; else if (lb > la) j++; else { i++; j++; }
  }
  return d + (la - i) + (lb - j) <= 1;
}
function fuzzyIds(type, tokens, limit) {
  let rows = fuzzy.get(type);
  if (!rows) {
    const act = activeSources().join(',') || '0';
    rows = q(`SELECT src,sid,norm FROM titles WHERE type=? AND status='actif' AND src IN (${act})`, type).map(r => ({ src: r.src, sid: r.sid, norm: r.norm }));
    fuzzy.set(type, rows);
  }
  const out = [];
  for (const r of rows) {
    const words = r.norm.split(' ');
    if (tokens.every(t => words.some(w => w.startsWith(t) || (t.length >= 4 && lev1(w, t))))) {
      out.push(r); if (out.length >= limit) break;
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Catalogue pour les visiteurs                                        */
/* ------------------------------------------------------------------ */
const itemOut = (r) => ({ id: r.sid, src: r.src, type: r.type, title: r.title, cat: r.cat,
  img: r.img ? `/img/${r.src}/${r.type}/${encodeURIComponent(r.sid)}` : null, rating: r.rating, added: r.added, ext: r.ext });

function catalogue({ type, src, cat, qs, offset, limit, sort, kids }) {
  if (!TYPES.includes(type)) throw httpErr(400, 'type inconnu');
  const act = activeSources();
  if (!act.length) return { total: 0, items: [] };
  const kc = kids ? (getMeta('kidsCats') || []) : null;
  if (kids && (type === 'chaine' || !kc.length || (cat && !kc.includes(cat)))) return { total: 0, capped: false, items: [] };
  const where = [`type=?`, `status='actif'`, `src IN (${act.join(',')})`]; const args = [type];
  if (src) { where.push('src=?'); args.push(Number(src)); }
  if (cat) { where.push('cat=?'); args.push(cat); }
  else if (kids) { where.push(`cat IN (${kc.map(() => '?').join(',')})`); args.push(...kc); }
  const tokens = fold(qs || '').split(' ').filter(Boolean);
  for (const t of tokens) { where.push('norm LIKE ?'); args.push(`%${t}%`); }
  const order = sort === 'az' ? 'norm ASC' : 'added DESC';          // les deux suivent un index : arrêt dès que la page est pleine
  const sql = `SELECT * FROM titles WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ? OFFSET ?`;
  let items = q(sql, ...args, limit, offset);
  let total = null, capped = false;
  if (offset === 0) {                                              // total plafonné à 5000 : pas de balayage complet pour rien
    total = q1(`SELECT COUNT(*) c FROM (SELECT 1 FROM titles WHERE ${where.join(' AND ')} LIMIT 5001)`, ...args).c;
    if (total > 5000) { total = 5000; capped = true; }
  }
  // recherche tolérante aux fautes si presque rien trouvé
  if (tokens.length && offset === 0 && total < 5 && fold(qs).length >= 4) {
    const seen = new Set(items.map(r => `${r.src}/${r.sid}`));
    const near = fuzzyIds(type, tokens, 120).filter(r => (!src || r.src === Number(src)) && !seen.has(`${r.src}/${r.sid}`));
    for (const r of near.slice(0, limit)) {
      const full = q1('SELECT * FROM titles WHERE src=? AND type=? AND sid=?', r.src, type, r.sid);
      if (full && (!cat || full.cat === cat) && (!kids || kc.includes(full.cat))) items.push(full);
    }
    total = items.length;
  }
  return { total, capped, items: items.map(itemOut) };
}
let countsCache = null;
function counts() {
  if (countsCache) return countsCache;
  const act = activeSources(); const by = {}; const all = { film: 0, serie: 0, chaine: 0 };
  if (act.length) for (const r of q(`SELECT src,type,COUNT(*) c FROM titles WHERE status='actif' AND src IN (${act.join(',')}) GROUP BY src,type`)) {
    (by[r.src] ??= { film: 0, serie: 0, chaine: 0 })[r.type] = r.c; all[r.type] += r.c;
  }
  return (countsCache = { all, bySource: by, sources: act });
}

/* ------------------------------------------------------------------ */
/* Aide HTTP                                                           */
/* ------------------------------------------------------------------ */
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const warned = new Set();
function cors(req) {
  const o = req.headers.origin, list = cfg.origins || [];
  if (list.length && o && !list.includes(o) && !warned.has(o)) {
    warned.add(o);
    console.log(`\n  ⚠ Le site ${o} est REFUSÉ : il n'est pas dans « Site autorisé » (admin → Réglages).\n    Ajoutez-le tel quel, ou videz la zone pour autoriser tous les sites.\n`);
  }
  return {
    'Access-Control-Allow-Origin': list.length ? (list.includes(o) ? o : list[0]) : '*',
    Vary: 'Origin',
    'Access-Control-Allow-Headers': 'X-Code,X-Device,X-Admin,Content-Type,Range',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Expose-Headers': 'Content-Length,Content-Range,Accept-Ranges',
    'Access-Control-Allow-Private-Network': 'true',
  };
}
function send(req, res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.writeHead(status, { ...cors(req), 'Content-Type': type, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const bodyOf = (req, max = 2_000_000) => new Promise((ok, ko) => {
  let b = ''; req.on('data', d => { b += d; if (b.length > max) { ko(httpErr(413, 'requête trop grande')); req.destroy(); } });
  req.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch { ko(httpErr(400, 'JSON invalide')); } });
});
const ipOf = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const isLocal = (req) => {
  const host = String(req.headers.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return ['localhost', '127.0.0.1', '::1'].includes(host) && !req.headers['x-forwarded-for'] && !req.headers['x-forwarded-host'];
};
const fails = new Map();
function throttled(key) { const f = fails.get(key); return f && f.n >= 8 && Date.now() - f.t < 60_000; }
function fail(key) { const f = fails.get(key) || { n: 0, t: 0 }; if (Date.now() - f.t > 60_000) f.n = 0; f.n++; f.t = Date.now(); fails.set(key, f); }

const cleanCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
function codeOf(req, url) {
  const ip = ipOf(req);
  if (throttled('c' + ip)) throw httpErr(429, 'Trop d\'essais, réessayez dans une minute');
  const c = cleanCode(req.headers['x-code'] || url.searchParams.get('c'));
  const row = c && q1('SELECT * FROM codes WHERE code=?', c);
  if (!row || !row.active || (row.expires && row.expires < Date.now())) { fail('c' + ip); throw httpErr(401, 'Code d\'accès invalide ou désactivé'); }
  return row;
}
function adminOnly(req) {
  if (!cfg.adminRemote && !isLocal(req)) throw httpErr(403, 'L\'administration n\'est disponible que depuis cet ordinateur (réglage « admin à distance » désactivé)');
  const ip = ipOf(req);
  if (throttled('a' + ip)) throw httpErr(429, 'Trop d\'essais, réessayez dans une minute');
  if (!checkPw(req.headers['x-admin'], cfg.adminHash)) { fail('a' + ip); throw httpErr(401, 'Mot de passe administrateur incorrect'); }
}

/* ------------------------------------------------------------------ */
/* Quotas : connexions simultanées, appareils, téléchargements          */
/* ------------------------------------------------------------------ */
const live = new Map();                                  // code -> Map(n -> dernier signal)
const ALIVE_MS = 45_000;
function activeStreams(code) {
  const m = live.get(code); if (!m) return 0;
  const now = Date.now(); let c = 0;
  for (const [n, t] of m) { if (now - t > ALIVE_MS) m.delete(n); else c++; }
  return c;
}
const liveDev = new Map();                               // n -> {c, dev}
const touch = (code, n) => { let m = live.get(code); if (!m) live.set(code, (m = new Map())); m.set(n, Date.now()); };

/* ------------------------------------------------------------------ */
/* Jetons de lecture                                                   */
/* ------------------------------------------------------------------ */
function sign(o) { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return `${p}.${hmac(p).slice(0, 32)}`; }
function verify(tok) {
  const [p, s] = String(tok).split('.');
  if (!p || !s) return null;
  const e = hmac(p).slice(0, 32);
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch { return null; }
}
function upstreamUrl(src, type, id, ext) {
  const sid = encodeURIComponent(String(id)), u = encodeURIComponent(src.user), p = encodeURIComponent(src.pass);
  if (type === 'chaine') return `${src.server}/live/${u}/${p}/${sid}.m3u8`;
  const e = String(ext || 'mp4').replace(/[^a-z0-9]/gi, '').slice(0, 5) || 'mp4';
  if (type === 'film') return `${src.server}/movie/${u}/${p}/${sid}.${e}`;
  if (type === 'episode') return `${src.server}/series/${u}/${p}/${sid}.${e}`;
  throw httpErr(400, 'type de lecture inconnu');
}
async function upstream(url, headers = {}, ms = 20000) {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), ms);
  try { const r = await fetch(url, { headers: { 'User-Agent': UA, ...headers }, redirect: 'follow', signal: ac.signal }); clearTimeout(t); return { r, ac }; }
  catch (e) { clearTimeout(t); throw httpErr(502, e.name === 'AbortError' ? 'Le fournisseur ne répond pas (délai dépassé)' : 'Le fournisseur est injoignable'); }
}
const upErr = (status) => httpErr(502, [401, 403, 884].includes(status) ? 'Le fournisseur refuse ce flux (connexions épuisées ou accès bloqué)'
  : status === 404 ? 'Ce flux n\'existe plus chez le fournisseur' : `Le fournisseur a répondu avec une erreur (${status})`);

function rewriteM3u8(text, base, tok, n) {
  const wrap = (u) => { const a = new URL(u, base).href; return `/s/${tok}/seg?u=${Buffer.from(a).toString('base64url')}&g=${hmac(n + a).slice(0, 24)}`; };
  return text.split(/\r?\n/).map(l => l.startsWith('#') ? l.replace(/URI="([^"]+)"/g, (_, u) => `URI="${wrap(u)}"`) : l.trim() ? wrap(l.trim()) : l).join('\n');
}
async function serveHls(req, res, r, tok, n) {
  const text = await r.text();
  if (!text.trimStart().startsWith('#EXTM3U')) throw httpErr(502, 'Le fournisseur ne propose pas de flux HLS pour cette chaîne (essayez le mode converti)');
  send(req, res, 200, rewriteM3u8(text, r.url, tok, n), 'application/vnd.apple.mpegurl', { 'Cache-Control': 'no-store' });
}

/* ------------------------------------------------------------------ */
/* ffmpeg / ffprobe                                                    */
/* ------------------------------------------------------------------ */
let ffVersion = null, ffprobeOk = false;
const firstLine = (cmd) => new Promise(ok => {
  const p = spawn(cmd, ['-version']); let o = '';
  p.stdout.on('data', d => (o += d)); p.on('error', () => ok(null)); p.on('close', () => ok((o.split('\n')[0] || '').trim() || null));
});
function probe(target) {
  return new Promise(ok => {
    const p = spawn(FFPROBE, ['-v', 'error', '-user_agent', UA, '-print_format', 'json', '-show_format', '-show_streams',
      '-analyzeduration', '4000000', '-probesize', '4000000', target]);
    let out = ''; const timer = setTimeout(() => p.kill('SIGKILL'), 25000);
    p.stdout.on('data', d => (out += d));
    p.on('error', () => { clearTimeout(timer); ok(null); });
    p.on('close', () => {
      clearTimeout(timer);
      try {
        const j = JSON.parse(out), all = j.streams || [], v = all.find(s => s.codec_type === 'video');
        const pick = (k) => all.filter(s => s.codec_type === k).map((s, i) => ({ i, codec: s.codec_name || null,
          lang: (s.tags?.language || '').toLowerCase() || null, title: s.tags?.title || null, channels: s.channels || null }));
        const audio = pick('audio');
        ok({ duration: Number(j.format?.duration) || 0, video: v?.codec_name || null, height: v?.height || null,
          audio: audio[0]?.codec || null, tracks: audio, subs: pick('subtitle'),
          audioPlayable: audio.length ? ['aac', 'mp3', 'opus', 'vorbis', 'flac'].includes(audio[0].codec) : false,
          hasAudio: audio.length > 0, videoPlayable: v ? ['h264', 'vp9', 'av1', 'vp8'].includes(v.codec_name) : false });
      } catch { ok(null); }
    });
  });
}

/* ------------------------------------------------------------------ */
/* Jaquettes (relayées et mises en cache : le navigateur bloque l'http) */
/* ------------------------------------------------------------------ */
const privateHost = (h) => !process.env.ALLOW_PRIVATE_IMG && /^(localhost|0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?$)/i.test(h);
let imgBusy = 0;
async function serveImage(req, res, src, type, sid) {
  const t = q1('SELECT img FROM titles WHERE src=? AND type=? AND sid=?', Number(src), type, sid);
  if (!t?.img) return send(req, res, 404, 'pas de jaquette', 'text/plain');
  const file = path.join(DATA, 'img', crypto.createHash('sha1').update(t.img).digest('hex'));
  const hdr = { 'Cache-Control': 'public, max-age=604800', ...cors(req) };
  if (fs.existsSync(file)) {
    const ct = fs.existsSync(file + '.t') ? fs.readFileSync(file + '.t', 'utf8') : 'image/jpeg';
    res.writeHead(200, { ...hdr, 'Content-Type': ct }); return fs.createReadStream(file).pipe(res);
  }
  let u; try { u = new URL(t.img); } catch { return send(req, res, 404, 'adresse invalide', 'text/plain'); }
  if (!/^https?:$/.test(u.protocol) || privateHost(u.hostname)) return send(req, res, 404, 'adresse refusée', 'text/plain');
  if (imgBusy >= 8) return send(req, res, 503, 'occupé', 'text/plain', { 'Retry-After': '1' });
  imgBusy++;
  try {
    const { r } = await upstream(t.img, {}, 10000);
    const ct = r.headers.get('content-type') || '';
    if (!r.ok || !ct.startsWith('image/')) return send(req, res, 404, 'jaquette introuvable', 'text/plain');
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > 3_000_000) return send(req, res, 404, 'image trop grande', 'text/plain');
    fs.writeFileSync(file, buf); fs.writeFileSync(file + '.t', ct);
    res.writeHead(200, { ...hdr, 'Content-Type': ct }); res.end(buf);
  } catch { send(req, res, 404, 'jaquette introuvable', 'text/plain'); }
  finally { imgBusy--; }
}

/* ------------------------------------------------------------------ */
/* Fiches (films et séries)                                            */
/* ------------------------------------------------------------------ */
const infoCache = new Map();
async function getInfo(kind, n, id) {
  const key = `${kind}:${n}:${id}`, hit = infoCache.get(key);
  if (hit && Date.now() - hit.t < 600_000) return hit.v;
  const src = srcRow(Number(n));
  if (!src || !src.active) throw httpErr(404, 'Source indisponible');
  const j = await xcall(src, kind === 'serie' ? 'get_series_info' : 'get_vod_info', { timeout: 30000, tries: 2, extra: kind === 'serie' ? { series_id: id } : { vod_id: id } });
  let v;
  if (kind === 'serie') {
    const eps = {};
    for (const [season, list] of Object.entries(j.episodes || {})) {
      eps[season] = (Array.isArray(list) ? list : Object.values(list)).map(e => ({ id: String(e.id), num: Number(e.episode_num) || 0,
        title: e.title || `Épisode ${e.episode_num}`, ext: e.container_extension || 'mp4', duration: e.info?.duration || '',
        plot: e.info?.plot || '', image: e.info?.movie_image || '' }));
    }
    const i = j.info || {};
    v = { plot: i.plot || '', genre: i.genre || '', year: i.releaseDate || i.release_date || '', rating: i.rating || '', cast: i.cast || '',
      backdrop: Array.isArray(i.backdrop_path) ? i.backdrop_path[0] || '' : '', episodes: eps };
  } else {
    const i = j.info || {};
    v = { plot: i.plot || i.description || '', genre: i.genre || '', year: i.releasedate || i.release_date || '', rating: i.rating || '',
      cast: i.cast || i.actors || '', duration: i.duration || '', backdrop: Array.isArray(i.backdrop_path) ? i.backdrop_path[0] || '' : '',
      ext: j.movie_data?.container_extension || '' };
  }
  infoCache.set(key, { t: Date.now(), v });
  return v;
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */
const ADMIN_HTML = path.join(HERE, 'admin.html');
const APP_HTML = path.join(HERE, 'app.html');
const safeName = (s) => String(s || 'video').replace(/[\\/:*?"<>|\u0000-\u001f]+/g, ' ').trim().slice(0, 120) || 'video';

async function handleStream(req, res, url, parts) {
  const tok = parts[1], what = parts[2];
  const t = verify(tok);
  if (!t) throw httpErr(401, 'Lien de lecture expiré : relancez la lecture');
  const code = q1('SELECT * FROM codes WHERE code=?', t.c);
  if (!code || !code.active) throw httpErr(401, 'Accès désactivé');
  touch(t.c, t.n);
  const src = srcRow(t.s);
  if (!src || !src.active) throw httpErr(404, 'Source indisponible');
  const target = upstreamUrl(src, t.t, t.i, t.e);

  if (what === 'seg') {
    const u = Buffer.from(url.searchParams.get('u') || '', 'base64url').toString();
    if (hmac(t.n + u).slice(0, 24) !== url.searchParams.get('g') || !/^https?:\/\//i.test(u)) throw httpErr(403, 'segment refusé');
    const { r, ac } = await upstream(u, req.headers.range ? { Range: req.headers.range } : {});
    if (r.status >= 400) throw upErr(r.status);
    const ct = r.headers.get('content-type') || '';
    if (/mpegurl/i.test(ct) || /\.m3u8(\?|$)/i.test(r.url)) return serveHls(req, res, r, tok, t.n);
    const out = { ...cors(req), 'Content-Type': ct || 'video/mp2t', 'Cache-Control': 'no-store' };
    for (const h of ['content-length', 'content-range']) { const v = r.headers.get(h); if (v) out[h] = v; }
    res.writeHead(r.status, out);
    if (!r.body) return res.end();
    const s = Readable.fromWeb(r.body); s.pipe(res); res.on('close', () => { ac.abort(); s.destroy(); }); s.on('error', () => res.end());
    return;
  }
  if (what === 'live.m3u8') {
    const { r } = await upstream(target);
    if (r.status >= 400) throw upErr(r.status);
    return serveHls(req, res, r, tok, t.n);
  }
  if (what === 'file' || what === 'download') {
    if (what === 'download' && !t.d) throw httpErr(403, 'Téléchargement non autorisé pour ce compte');
    const { r, ac } = await upstream(target, req.headers.range ? { Range: req.headers.range } : {});
    if (r.status >= 400) throw upErr(r.status);
    let ct = r.headers.get('content-type') || 'application/octet-stream';
    if (/octet-stream|text/i.test(ct) && t.e === 'mp4') ct = 'video/mp4';
    const out = { ...cors(req), 'Content-Type': ct, 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' };
    for (const h of ['content-length', 'content-range']) { const v = r.headers.get(h); if (v) out[h] = v; }
    if (what === 'download') out['Content-Disposition'] = `attachment; filename="${safeName(url.searchParams.get('name'))}.${t.e || 'mp4'}"`;
    res.writeHead(r.status, out);
    if (!r.body) return res.end();
    const s = Readable.fromWeb(r.body); s.pipe(res);
    res.on('close', () => { ac.abort(); s.destroy(); }); s.on('error', () => res.end());
    return;
  }
  if (what === 'probe') {
    if (!ffprobeOk) throw httpErr(503, 'ffprobe est introuvable sur cet ordinateur');
    const info = await probe(target);
    if (!info) throw httpErr(502, 'Analyse du flux impossible');
    return send(req, res, 200, info);
  }
  if (what === 'subs') {
    if (!ffVersion) throw httpErr(503, 'ffmpeg est introuvable sur cet ordinateur');
    const n = Math.max(0, Number(url.searchParams.get('s')) || 0);
    const ff = spawn(FFMPEG, ['-hide_banner', '-loglevel', 'error', '-user_agent', UA, '-i', target, '-map', `0:s:${n}`, '-f', 'webvtt', 'pipe:1'], { stdio: ['ignore', 'pipe', 'ignore'] });
    res.writeHead(200, { ...cors(req), 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'no-store' });
    ff.stdout.pipe(res); ff.on('error', () => res.end()); ff.on('close', () => res.end());
    const kill = () => { if (!ff.killed) ff.kill('SIGKILL'); }; req.on('close', kill); res.on('close', kill);
    return;
  }
  if (what === 'ff') {                                    // son converti en AAC (et vidéo réencodée si demandé)
    if (!ffVersion) throw httpErr(503, 'ffmpeg est introuvable sur cet ordinateur : la conversion du son est impossible');
    const start = Math.max(0, Number(url.searchParams.get('t')) || 0);
    const at = Math.max(0, Number(url.searchParams.get('a')) || 0);
    const recode = url.searchParams.get('vt') === '1';
    const args = ['-hide_banner', '-loglevel', 'error', '-user_agent', UA, '-fflags', '+genpts', ...(start ? ['-ss', String(start)] : []),
      '-i', target, '-map', '0:v:0?', '-map', `0:a:${at}?`, '-sn', '-dn',
      ...(recode ? ['-c:v', 'libx264', '-preset', 'veryfast', '-tune', 'zerolatency', '-crf', '23', '-pix_fmt', 'yuv420p'] : ['-c:v', 'copy']),
      '-c:a', 'aac', '-ac', '2', '-b:a', '192k', '-f', 'mp4', '-movflags', 'frag_keyframe+empty_moov+default_base_moof', 'pipe:1'];
    const ff = spawn(FFMPEG, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = ''; ff.stderr.on('data', d => { err += d; if (err.length > 4000) err = err.slice(-2000); });
    res.writeHead(200, { ...cors(req), 'Content-Type': 'video/mp4', 'Cache-Control': 'no-store' });
    ff.stdout.pipe(res);
    const beat = setInterval(() => touch(t.c, t.n), 15000);
    ff.on('error', () => res.end());
    ff.on('close', (c) => { clearInterval(beat); if (c && c !== 255) console.error(`ffmpeg arrêté (code ${c}) ${err.trim().split('\n').pop()}`); res.end(); });
    const kill = () => { clearInterval(beat); if (!ff.killed) ff.kill('SIGKILL'); }; req.on('close', kill); res.on('close', kill);
    return;
  }
  throw httpErr(404, 'route inconnue');
}

async function handleApi(req, res, url, parts) {
  const route = parts.slice(1).join('/');
  if (route === 'me') {
    const c = codeOf(req, url);
    return send(req, res, 200, { ok: true, label: c.label, maxConn: c.max_conn, maxDevices: c.max_devices,
      canDownload: !!c.can_download, maxDlDay: c.max_dl_day, maxProfiles: c.max_profiles, expires: c.expires, ffmpeg: !!ffVersion });
  }
  const c = codeOf(req, url);
  const profId = Number(req.headers['x-profile']) || null;
  const prof = profId ? q1('SELECT * FROM profiles WHERE code=? AND id=?', c.code, profId) : null;
  const kids = !!prof?.kids;
  const ownProfile = (pid) => { const p = q1('SELECT * FROM profiles WHERE code=? AND id=?', c.code, Number(pid)); if (!p) throw httpErr(404, 'Profil inconnu'); return p; };
  if (route === 'counts') return send(req, res, 200, counts());
  if (route === 'cats') {
    const type = url.searchParams.get('type'); if (!TYPES.includes(type)) throw httpErr(400, 'type inconnu');
    const act = activeSources(); if (!act.length) return send(req, res, 200, []);
    const src = url.searchParams.get('src');
    const ck = `${type}|${src || ''}`, hit = catsCache.get(ck);
    if (kids) {                                                  // profil enfants : seulement les catégories choisies par l'admin
      const kc = getMeta('kidsCats') || [];
      const all = hit || q(`SELECT cat,COUNT(*) n FROM titles WHERE type=? AND status='actif' AND src IN (${act.join(',')})${src ? ' AND src=?' : ''} GROUP BY cat ORDER BY cat COLLATE NOCASE`, type, ...(src ? [Number(src)] : []));
      return send(req, res, 200, type === 'chaine' ? [] : all.filter(x => kc.includes(x.cat)));
    }
    if (hit) return send(req, res, 200, hit);
    const out = q(`SELECT cat,COUNT(*) n FROM titles WHERE type=? AND status='actif' AND src IN (${act.join(',')})${src ? ' AND src=?' : ''} GROUP BY cat ORDER BY cat COLLATE NOCASE`,
      type, ...(src ? [Number(src)] : []));
    catsCache.set(ck, out);
    return send(req, res, 200, out);
  }
  if (route === 'catalogue') {
    const p = url.searchParams;
    return send(req, res, 200, catalogue({ type: p.get('type'), src: p.get('src'), cat: p.get('cat'), qs: p.get('q'),
      offset: Math.max(0, Number(p.get('offset')) || 0), limit: Math.min(120, Math.max(1, Number(p.get('limit')) || 60)), sort: p.get('sort'), kids }));
  }
  if (parts[1] === 'info' && parts.length === 5) {
    if (!['film', 'serie'].includes(parts[2])) throw httpErr(400, 'type inconnu');
    return send(req, res, 200, await getInfo(parts[2], parts[3], decodeURIComponent(parts[4])));
  }
  if (route === 'ticket' && req.method === 'POST') {
    const b = await bodyOf(req);
    const src = srcRow(Number(b.src));
    if (!src || !src.active) throw httpErr(404, 'Source indisponible');
    if (!['film', 'chaine', 'episode'].includes(b.type)) throw httpErr(400, 'type de lecture inconnu');
    const row = b.type !== 'episode' ? q1('SELECT cat FROM titles WHERE src=? AND type=? AND sid=?', src.n, b.type, String(b.id)) : null;
    if (b.type !== 'episode' && !row) throw httpErr(404, 'Titre inconnu');
    if (kids && (b.type === 'chaine' || (row && !(getMeta('kidsCats') || []).includes(row.cat)))) throw httpErr(403, 'Ce contenu n\'est pas disponible pour le profil enfants');
    // appareils
    const dev = String(b.device || req.headers['x-device'] || '').slice(0, 64) || 'inconnu';
    if (c.max_devices !== -1) {
      const known = q1('SELECT 1 FROM devices WHERE code=? AND device=?', c.code, dev);
      const n = q1('SELECT COUNT(*) n FROM devices WHERE code=?', c.code).n;
      if (!known && n >= c.max_devices) throw httpErr(403, `Nombre maximal d'appareils atteint (${c.max_devices})`);
    }
    run('INSERT INTO devices(code,device,last) VALUES(?,?,?) ON CONFLICT(code,device) DO UPDATE SET last=excluded.last', c.code, dev, Date.now());
    // une seule lecture par appareil : l'ancienne (page rechargée, titre changé) est libérée d'office
    for (const [n0, d0] of liveDev) if (d0.c === c.code && d0.dev === dev) { live.get(c.code)?.delete(n0); liveDev.delete(n0); }
    // connexions simultanées
    if (c.max_conn !== -1 && activeStreams(c.code) >= c.max_conn) throw httpErr(429, `Trop de lectures en même temps sur ce compte (${c.max_conn} maximum)`);
    // téléchargements
    if (b.download) {
      if (!c.can_download) throw httpErr(403, 'Le téléchargement n\'est pas autorisé pour ce compte');
      const day = new Date().toISOString().slice(0, 10);
      const used = q1('SELECT n FROM dl WHERE code=? AND day=?', c.code, day)?.n || 0;
      if (c.max_dl_day !== -1 && used >= c.max_dl_day) throw httpErr(429, `Limite de ${c.max_dl_day} téléchargement(s) par jour atteinte`);
      run('INSERT INTO dl(code,day,n) VALUES(?,?,1) ON CONFLICT(code,day) DO UPDATE SET n=n+1', c.code, day);
    }
    const n = crypto.randomBytes(6).toString('hex');
    const ext = b.type === 'film' ? (q1('SELECT ext FROM titles WHERE src=? AND type=? AND sid=?', src.n, 'film', String(b.id))?.ext || 'mp4') : String(b.ext || 'mp4');
    const tok = sign({ c: c.code, s: src.n, t: b.type, i: String(b.id), e: ext.replace(/[^a-z0-9]/gi, '').slice(0, 5), d: b.download ? 1 : 0, n, exp: Date.now() + 8 * 3600_000 });
    touch(c.code, n); liveDev.set(n, { c: c.code, dev });
    const base = `/s/${tok}`;
    return send(req, res, 200, { n, ext, hls: b.type === 'chaine' ? `${base}/live.m3u8` : null, file: b.type !== 'chaine' ? `${base}/file` : null,
      ff: `${base}/ff`, probe: `${base}/probe`, subs: `${base}/subs`, download: b.download ? `${base}/download` : null, ffmpeg: !!ffVersion });
  }
  const m = req.method, pid = () => Number(url.searchParams.get('profile'));
  if (route === 'profiles' && m === 'GET') return send(req, res, 200, q('SELECT id,name,kids,color FROM profiles WHERE code=? ORDER BY id', c.code).map(x => ({ ...x, kids: !!x.kids })));
  if (route === 'profiles' && m === 'POST') {
    const b = await bodyOf(req), name = String(b.name || '').trim().slice(0, 24);
    if (!name) throw httpErr(400, 'Donnez un nom au profil');
    const n = q1('SELECT COUNT(*) n FROM profiles WHERE code=?', c.code).n;
    if (c.max_profiles !== -1 && n >= c.max_profiles) throw httpErr(403, `Nombre maximal de profils atteint (${c.max_profiles})`);
    const id = (q1('SELECT COALESCE(MAX(id),0) m FROM profiles WHERE code=?', c.code).m) + 1;
    const color = String(b.color || '#C9A057').slice(0, 9);
    run('INSERT INTO profiles(code,id,name,kids,color) VALUES(?,?,?,?,?)', c.code, id, name, b.kids ? 1 : 0, color);
    return send(req, res, 200, { id, name, kids: !!b.kids, color });
  }
  if (parts[1] === 'profiles' && parts.length === 3 && m === 'DELETE') {
    const id = Number(parts[2]); ownProfile(id);
    for (const t of ['profiles', 'favs', 'hist']) run(`DELETE FROM ${t} WHERE code=? AND ${t === 'profiles' ? 'id' : 'profile'}=?`, c.code, id);
    return send(req, res, 200, { ok: true });
  }
  if (route === 'favs' && m === 'GET') {
    ownProfile(pid());
    return send(req, res, 200, q('SELECT src,type,sid,title,img FROM favs WHERE code=? AND profile=? ORDER BY ts DESC LIMIT 500', c.code, pid()).map(x => ({ src: x.src, type: x.type, id: x.sid, title: x.title, img: x.img })));
  }
  if (route === 'favs' && m === 'POST') {
    const b = await bodyOf(req); ownProfile(b.profile);
    run('INSERT INTO favs(code,profile,src,type,sid,title,img,ts) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(code,profile,src,type,sid) DO UPDATE SET ts=excluded.ts',
      c.code, Number(b.profile), Number(b.src), String(b.type), String(b.id), String(b.title || '').slice(0, 200), String(b.img || '').slice(0, 300), Date.now());
    return send(req, res, 200, { ok: true });
  }
  if (route === 'favs' && m === 'DELETE') {
    ownProfile(pid()); const p = url.searchParams;
    run('DELETE FROM favs WHERE code=? AND profile=? AND src=? AND type=? AND sid=?', c.code, pid(), Number(p.get('src')), p.get('type'), p.get('id'));
    return send(req, res, 200, { ok: true });
  }
  if (route === 'hist' && m === 'GET') {
    ownProfile(pid());
    return send(req, res, 200, q('SELECT src,type,sid,title,img,pos,dur,meta,ts FROM hist WHERE code=? AND profile=? ORDER BY ts DESC LIMIT 40', c.code, pid())
      .map(x => ({ src: x.src, type: x.type, id: x.sid, title: x.title, img: x.img, pos: x.pos, dur: x.dur, ts: x.ts, meta: x.meta ? JSON.parse(x.meta) : null })));
  }
  if (route === 'hist' && m === 'POST') {
    const b = await bodyOf(req); ownProfile(b.profile);
    run(`INSERT INTO hist(code,profile,src,type,sid,title,img,pos,dur,meta,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(code,profile,src,type,sid) DO UPDATE SET pos=excluded.pos,dur=excluded.dur,meta=excluded.meta,ts=excluded.ts,title=excluded.title,img=excluded.img`,
      c.code, Number(b.profile), Number(b.src), String(b.type), String(b.id), String(b.title || '').slice(0, 200), String(b.img || '').slice(0, 300),
      Number(b.pos) || 0, Number(b.dur) || 0, b.meta ? JSON.stringify(b.meta).slice(0, 2000) : null, Date.now());
    return send(req, res, 200, { ok: true });
  }
  if (route === 'hist' && m === 'DELETE') {
    ownProfile(pid()); const p = url.searchParams;
    run('DELETE FROM hist WHERE code=? AND profile=? AND src=? AND type=? AND sid=?', c.code, pid(), Number(p.get('src')), p.get('type'), p.get('id'));
    return send(req, res, 200, { ok: true });
  }
  if (route === 'release' && req.method === 'POST') {
    const b = await bodyOf(req); live.get(c.code)?.delete(String(b.n)); return send(req, res, 200, { ok: true });
  }
  throw httpErr(404, 'route inconnue');
}

async function handleAdmin(req, res, url, parts) {
  adminOnly(req);
  const r = parts.slice(2).join('/'), m = req.method;
  if (r === 'status') {
    const rows = q('SELECT n,name,server,active,expiry,maxconn,last_error FROM sources ORDER BY n');
    const have = q(`SELECT src,type,COUNT(*) c FROM titles WHERE status='actif' GROUP BY src,type`);
    const retired = q(`SELECT src,type,COUNT(*) c FROM titles WHERE status='retire' GROUP BY src,type`);
    const sources = rows.map(s => ({ ...s, types: Object.fromEntries(TYPES.map(t => [t, {
      expected: getMeta(`expected:${s.n}:${t}`)?.n ?? null, saved: have.find(h => h.src === s.n && h.type === t)?.c || 0,
      retired: retired.find(h => h.src === s.n && h.type === t)?.c || 0, at: getMeta(`expected:${s.n}:${t}`)?.at ?? null }])) }));
    const total = counts().all;
    return send(req, res, 200, { version: VERSION, ffmpeg: ffVersion, ffprobe: ffprobeOk, origins: cfg.origins, adminRemote: cfg.adminRemote,
      sources, total, lastImport: getMeta('lastImport')?.at || null, streams: [...live.keys()].reduce((a, k) => a + activeStreams(k), 0) });
  }
  if (r === 'sources/analyse' && m === 'POST') {
    const b = await bodyOf(req), seen = new Set();
    for (const s of q('SELECT server,user FROM sources')) seen.add(s.server + '|' + dec(s.user).toLowerCase());
    const out = String(b.text || '').split(/\r?\n/).map((raw, i) => ({ line: i + 1, raw })).filter(x => x.raw.trim()).map(x => {
      const p = parseLine(x.raw);
      if (p.error) return { line: x.line, status: 'illisible', reason: p.error };
      const k = p.server + '|' + p.user.toLowerCase();
      if (seen.has(k)) return { line: x.line, status: 'doublon', reason: 'même serveur et même identifiant', ...p };
      seen.add(k); return { line: x.line, status: 'prête', ...p };
    });
    return send(req, res, 200, out);
  }
  if (r === 'sources/save' && m === 'POST') {
    const b = await bodyOf(req); let n = q1('SELECT COALESCE(MAX(n),0) m FROM sources').m; const saved = [];
    for (const s of b.rows || []) {
      let u; try { u = new URL(s.server); } catch { throw httpErr(400, `Source « ${s.name} » : adresse invalide`); }
      if (!/^https?:$/.test(u.protocol)) throw httpErr(400, `Source « ${s.name} » : l'adresse doit commencer par http:// ou https://`);
      if (!s.user) throw httpErr(400, `Source « ${s.name} » : identifiant vide`);
      if (!s.pass) throw httpErr(400, `Source « ${s.name} » : mot de passe vide`);
      n++; run('INSERT INTO sources(n,name,server,user,pass,active) VALUES(?,?,?,?,?,1)', n, String(s.name || u.hostname), s.server.replace(/\/+$/, ''), enc(s.user), enc(s.pass));
      saved.push(n);
    }
    resetCaches(); audit('admin', `ajout sources ${saved.join(',')}`);
    return send(req, res, 200, { saved });
  }
  let mm;
  if ((mm = r.match(/^sources\/(\d+)\/test$/)) && m === 'POST') {
    const s = srcRow(Number(mm[1])); if (!s) throw httpErr(404, 'Source inconnue');
    return send(req, res, 200, await testSource(s));
  }
  if ((mm = r.match(/^sources\/(\d+)\/testplay$/)) && m === 'POST') {
    const s = srcRow(Number(mm[1])); if (!s) throw httpErr(404, 'Source inconnue');
    const t = q1(`SELECT sid FROM titles WHERE src=? AND type='chaine' AND status='actif' LIMIT 1`, s.n);
    if (!t) return send(req, res, 200, { ok: false, message: 'Aucune chaîne importée pour cette source : lancez d\'abord l\'import' });
    try {
      const { r: r1 } = await upstream(upstreamUrl(s, 'chaine', t.sid), {}, 15000);
      if (r1.status >= 400) return send(req, res, 200, { ok: false, message: upErr(r1.status).message });
      const txt = await r1.text();
      if (!txt.trimStart().startsWith('#EXTM3U')) return send(req, res, 200, { ok: false, message: 'Flux reçu mais ce n\'est pas du HLS : la lecture passera par le mode converti (ffmpeg)' });
      const info = ffprobeOk ? await probe(upstreamUrl(s, 'chaine', t.sid)) : null;
      if (!info) return send(req, res, 200, { ok: true, message: 'Le flux répond (HLS). ffprobe indisponible : codecs non vérifiés' });
      const bits = [`image ${info.video || 'inconnue'}`, info.hasAudio ? `son ${info.audio}` : 'AUCUN SON dans ce flux'];
      if (info.hasAudio && !info.audioPlayable) bits.push('codec audio non lu par les navigateurs → conversion AAC nécessaire (ffmpeg)');
      if (info.video && !info.videoPlayable) bits.push('vidéo à réencoder (H.265)');
      return send(req, res, 200, { ok: info.hasAudio, message: 'Flux OK — ' + bits.join(' ; ') });
    } catch (e) { return send(req, res, 200, { ok: false, message: e.message }); }
  }
  if ((mm = r.match(/^sources\/(\d+)\/active$/)) && m === 'POST') {
    const b = await bodyOf(req); run('UPDATE sources SET active=? WHERE n=?', b.active ? 1 : 0, Number(mm[1])); resetCaches(); return send(req, res, 200, { ok: true });
  }
  if ((mm = r.match(/^sources\/(\d+)$/)) && m === 'DELETE') {
    const n = Number(mm[1]); run('DELETE FROM titles WHERE src=?', n); run('DELETE FROM sources WHERE n=?', n); resetCaches(); audit('admin', `suppression source ${n}`);
    return send(req, res, 200, { ok: true });
  }
  if (r === 'import' && m === 'POST') {
    const b = await bodyOf(req);
    await runImport(b.mode === 'full' ? 'full' : 'news', b.src ? Number(b.src) : null);
    return send(req, res, 200, { ok: true });
  }
  if (r === 'import' && m === 'GET') return send(req, res, 200, imp);
  if (r === 'codes' && m === 'GET') return send(req, res, 200, q('SELECT * FROM codes ORDER BY created DESC').map(c => ({ ...c, active_streams: activeStreams(c.code),
    devices: q1('SELECT COUNT(*) n FROM devices WHERE code=?', c.code).n })));
  if (r === 'codes' && m === 'POST') {
    const b = await bodyOf(req), out = [];
    const labels = Array.isArray(b.labels) && b.labels.length ? b.labels : [b.label || 'sans nom'];
    const num = (v, d) => (v === '' || v == null ? d : Number(v));
    for (const label of labels) {
      const raw = Array.from(crypto.randomBytes(20), x => 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'[x % 31]).join('');
      run('INSERT INTO codes(code,label,max_conn,max_devices,can_download,max_dl_day,max_profiles,expires,created) VALUES(?,?,?,?,?,?,?,?,?)', raw, String(label).slice(0, 80),
        num(b.maxConn, 1), num(b.maxDevices, -1), b.canDownload ? 1 : 0, num(b.maxDlDay, 0), num(b.maxProfiles, 5), b.days ? Date.now() + Number(b.days) * 86400000 : null, Date.now());
      out.push({ label, code: raw.match(/.{5}/g).join('-') });
    }
    audit('admin', `création de ${out.length} code(s)`);
    return send(req, res, 200, out);
  }
  if ((mm = r.match(/^codes\/([A-Za-z0-9-]+)$/))) {
    const code = cleanCode(mm[1]);
    if (m === 'DELETE') { run('DELETE FROM codes WHERE code=?', code); live.delete(code); audit('admin', 'code supprimé'); return send(req, res, 200, { ok: true }); }
    if (m === 'PATCH') {
      const b = await bodyOf(req), f = { active: 'active', maxConn: 'max_conn', maxDevices: 'max_devices', canDownload: 'can_download', maxDlDay: 'max_dl_day', maxProfiles: 'max_profiles', label: 'label' };
      for (const [k, col] of Object.entries(f)) if (k in b) run(`UPDATE codes SET ${col}=? WHERE code=?`, typeof b[k] === 'boolean' ? +b[k] : b[k], code);
      if ('days' in b) run('UPDATE codes SET expires=? WHERE code=?', b.days ? Date.now() + Number(b.days) * 86400000 : null, code);
      audit('admin', 'code modifié'); return send(req, res, 200, { ok: true });
    }
  }
  if (r === 'config' && m === 'POST') {
    const b = await bodyOf(req);
    if (Array.isArray(b.origins)) cfg.origins = b.origins.map(s => String(s).trim().replace(/\/+$/, '')).filter(Boolean);
    if (typeof b.adminRemote === 'boolean') cfg.adminRemote = b.adminRemote;
    if (b.newPassword) {
      if (String(b.newPassword).length < 8) throw httpErr(400, 'Le mot de passe doit faire 8 caractères au moins');
      cfg.adminHash = hashPw(String(b.newPassword)); try { fs.unlinkSync(PW_FILE); } catch {}
    }
    saveCfg(); audit('admin', 'réglages modifiés'); return send(req, res, 200, { ok: true });
  }
  if (r === 'cats' && m === 'GET') {
    const type = url.searchParams.get('type'); if (!TYPES.includes(type)) throw httpErr(400, 'type inconnu');
    const act = activeSources(); if (!act.length) return send(req, res, 200, []);
    return send(req, res, 200, q(`SELECT cat,COUNT(*) n FROM titles WHERE type=? AND status='actif' AND src IN (${act.join(',')}) GROUP BY cat ORDER BY cat COLLATE NOCASE`, type));
  }
  if (r === 'kids' && m === 'GET') return send(req, res, 200, { cats: getMeta('kidsCats') || [] });
  if (r === 'kids' && m === 'POST') {
    const b = await bodyOf(req); setMeta('kidsCats', (Array.isArray(b.cats) ? b.cats : []).map(String).slice(0, 500));
    audit('admin', 'catégories enfants modifiées'); return send(req, res, 200, { ok: true });
  }
  if (r === 'log') return send(req, res, 200, q('SELECT * FROM log ORDER BY t DESC LIMIT 200'));
  throw httpErr(404, 'route inconnue');
}

process.stdout.on('error', () => {}); process.stderr.on('error', () => {});
process.on('uncaughtException', (e) => { try { console.error('Erreur inattendue :', e?.message || e); } catch {} });
process.on('unhandledRejection', (e) => { try { console.error('Erreur inattendue :', e?.message || e); } catch {} });
const server = http.createServer(async (req, res) => {
  const lp = req.url.split('?')[0];
  if (!/^\/(s|img)\//.test(lp)) res.on('finish', () => console.log(`  ${new Date().toLocaleTimeString('fr-FR')}  ${req.method} ${lp.slice(0, 70)} → ${res.statusCode}   site : ${req.headers.origin || '-'}`));
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204, cors(req)); return res.end(); }
    const url = new URL(req.url, 'http://x');
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts[0] === 'health') return send(req, res, 200, { ok: true, app: 'yctlflix-relais', version: VERSION, ffmpeg: !!ffVersion });
    if (parts[0] === 'favicon.ico') { res.writeHead(204); return res.end(); }
    if (!parts.length || parts[0] === 'app') {                       // le site lui-même
      if (!fs.existsSync(APP_HTML)) return send(req, res, 200, { ok: true, app: 'yctlflix-relais', version: VERSION, ffmpeg: !!ffVersion });
      return send(req, res, 200, fs.readFileSync(APP_HTML), 'text/html; charset=utf-8', { 'Cache-Control': 'no-store' });
    }
    if (parts[0] === 'admin' && parts.length === 1) {
      if (!cfg.adminRemote && !isLocal(req)) throw httpErr(403, 'L\'administration n\'est disponible que depuis cet ordinateur : ouvrez http://127.0.0.1:' + PORT + '/admin');
      return send(req, res, 200, fs.readFileSync(ADMIN_HTML), 'text/html; charset=utf-8', { 'Cache-Control': 'no-store' });
    }
    if (parts[0] === 'admin' && parts[1] === 'api') return await handleAdmin(req, res, url, parts);
    if (parts[0] === 'api') return await handleApi(req, res, url, parts);
    if (parts[0] === 's' && parts.length >= 3) return await handleStream(req, res, url, parts);
    if (parts[0] === 'img' && parts.length === 4) return await serveImage(req, res, parts[1], parts[2], decodeURIComponent(parts[3]));
    throw httpErr(404, 'route inconnue');
  } catch (e) {
    if (res.headersSent) return res.end();
    const status = e.status || 500;
    if (status === 500) console.error(e);
    send(req, res, status, { error: status === 500 ? 'Erreur interne du relais' : e.message });
  }
});
server.requestTimeout = 0; server.headersTimeout = 30000;

ffVersion = await firstLine(FFMPEG);
ffprobeOk = !!(await firstLine(FFPROBE));
server.on('error', (e) => {
  console.error(e.code === 'EADDRINUSE' ? `\n  Le port ${PORT} est déjà pris : yctlflix tourne peut-être déjà dans une autre fenêtre.\n` : '\n  Erreur : ' + e.message + '\n');
  process.exit(1);
});
// reprise après coupure : un import interrompu se relance avec « Importer les nouveautés » (n'écrit que les manquants)

/* Mode « hébergeur gratuit sans disque » : tout se reconstruit au démarrage depuis les variables d'environnement */
function bootstrapFromEnv() {
  let added = 0;
  const have = new Set(q('SELECT server,user FROM sources').map(s => s.server + '|' + dec(s.user).toLowerCase()));
  let n = q1('SELECT COALESCE(MAX(n),0) m FROM sources').m;
  for (const line of String(process.env.SOURCES || '').split(/\r?\n/).filter(l => l.trim())) {
    const p = parseLine(line); if (p.error) { console.log('  SOURCES : ligne ignorée (' + p.error + ')'); continue; }
    if (have.has(p.server + '|' + p.user.toLowerCase())) continue;
    n++; run('INSERT INTO sources(n,name,server,user,pass,active) VALUES(?,?,?,?,?,1)', n, p.name, p.server, enc(p.user), enc(p.pass)); added++;
  }
  for (const line of String(process.env.CODES || '').split(/\r?\n/).filter(l => l.trim())) {
    const [raw0, label = 'sans nom', mc, md, dl] = line.split(';').map(x => x.trim()); const raw = cleanCode(raw0);
    if (raw.length < 12) { console.log('  CODES : code trop court ignoré (12 caractères minimum)'); continue; }
    if (q1('SELECT 1 FROM codes WHERE code=?', raw)) continue;
    run('INSERT INTO codes(code,label,max_conn,max_devices,can_download,max_dl_day,max_profiles,expires,created) VALUES(?,?,?,?,?,?,?,?,?)', raw, label.slice(0, 80),
      mc ? Number(mc) : 2, md ? Number(md) : -1, dl === '1' ? 1 : 0, 0, 5, null, Date.now());
  }
  if (added) resetCaches();
  if (process.env.AUTO_IMPORT === '1' && activeSources().length && q1('SELECT COUNT(*) n FROM titles').n === 0) {
    console.log('  Catalogue vide : import automatique en cours…');
    runImport('full').catch(e => console.log('  Import automatique : ' + e.message));
  }
}
server.listen(PORT, HOST, () => {
  try { bootstrapFromEnv(); } catch (e) { console.log('  Démarrage automatique : ' + e.message); }
  console.log(`\n  yctlflix — relais prêt :  http://${HOST === '0.0.0.0' ? '127.0.0.1' : HOST}:${PORT}/admin`);
  console.log(ffVersion ? `  ${ffVersion}` : '  ffmpeg introuvable : le son AC-3 ne pourra pas être converti.');
  if (firstPassword && !process.env.ADMIN_PASSWORD) console.log(`\n  PREMIER DÉMARRAGE — mot de passe administrateur :  ${firstPassword}\n  (aussi dans data/MOT-DE-PASSE-ADMIN.txt)`);
  console.log('');
});
