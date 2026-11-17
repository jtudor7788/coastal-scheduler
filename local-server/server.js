'use strict';
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'scheduler.db');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// Stable signing secret, persisted so logins survive restarts
const SECRET_PATH = path.join(path.dirname(DB_PATH), '.secret');
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  if (!fs.existsSync(SECRET_PATH)) fs.writeFileSync(SECRET_PATH, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  SECRET = fs.readFileSync(SECRET_PATH, 'utf8');
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS cleaners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  pin TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS availability (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cleaner_id INTEGER NOT NULL REFERENCES cleaners(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  start_time TEXT NOT NULL DEFAULT '08:00',
  end_time TEXT NOT NULL DEFAULT '17:00',
  note TEXT,
  UNIQUE (cleaner_id, date)
);
CREATE TABLE IF NOT EXISTS cleans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT NOT NULL,
  start_time TEXT NOT NULL DEFAULT '10:00',
  duration_hours REAL NOT NULL DEFAULT 2,
  client TEXT NOT NULL,
  address TEXT,
  type TEXT NOT NULL DEFAULT 'Airbnb turnover',
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'open',      -- open | assigned | confirmed | done | cancelled
  cleaner_id INTEGER REFERENCES cleaners(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cleans_date ON cleans(date);
CREATE INDEX IF NOT EXISTS idx_avail_date ON availability(date);
`);

// ---------- helpers ----------
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const toMin = t => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };
const cleanEnd = c => toMin(c.start_time) + Math.round(c.duration_hours * 60);

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}
function verify(token) {
  if (!token) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(mac), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

function auth(role) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const p = verify(h.startsWith('Bearer ') ? h.slice(7) : null);
    if (!p) return bad(res, 'Not signed in', 401);
    if (role && p.role !== role) return bad(res, 'Not allowed', 403);
    req.user = p;
    next();
  };
}

// simple login throttle
const fails = new Map();
function throttled(key) {
  const f = fails.get(key);
  return f && f.n >= 8 && Date.now() - f.t < 10 * 60 * 1000;
}
function noteFail(key) {
  const f = fails.get(key) || { n: 0, t: 0 };
  fails.set(key, { n: f.n + 1, t: Date.now() });
}

// ---------- app ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ----- login -----
app.post('/api/login/admin', (req, res) => {
  const key = 'admin:' + req.ip;
  if (throttled(key)) return bad(res, 'Too many attempts, try again later', 429);
  if (!safeEq(req.body.password || '', ADMIN_PASSWORD)) { noteFail(key); return bad(res, 'Wrong password', 401); }
  res.json({ token: sign({ role: 'admin', exp: Date.now() + 30 * 864e5 }), role: 'admin' });
});

app.post('/api/login/cleaner', (req, res) => {
  const key = 'cleaner:' + req.ip;
  if (throttled(key)) return bad(res, 'Too many attempts, try again later', 429);
  const c = db.prepare('SELECT * FROM cleaners WHERE id = ? AND active = 1').get(req.body.cleaner_id);
  if (!c || !safeEq(req.body.pin || '', c.pin)) { noteFail(key); return bad(res, 'Wrong name or PIN', 401); }
  res.json({ token: sign({ role: 'cleaner', id: c.id, exp: Date.now() + 30 * 864e5 }), role: 'cleaner', name: c.name, id: c.id });
});

// public: names for the login dropdown (no PINs)
app.get('/api/cleaners/public', (req, res) => {
  res.json(db.prepare('SELECT id, name FROM cleaners WHERE active = 1 ORDER BY name').all());
});

// ----- cleaner endpoints -----
app.get('/api/me/availability', auth('cleaner'), (req, res) => {
  const from = req.query.from || new Date().toISOString().slice(0, 10);
  res.json(db.prepare('SELECT * FROM availability WHERE cleaner_id = ? AND date >= ? ORDER BY date').all(req.user.id, from));
});

app.post('/api/me/availability', auth('cleaner'), (req, res) => {
  // body: { dates: ['2026-11-20', ...], start_time, end_time, note }
  const { dates, start_time = '08:00', end_time = '17:00', note = '' } = req.body;
  if (!Array.isArray(dates) || !dates.length) return bad(res, 'Pick at least one date');
  if (!dates.every(d => DATE_RE.test(d))) return bad(res, 'Bad date format');
  if (!TIME_RE.test(start_time) || !TIME_RE.test(end_time) || toMin(end_time) <= toMin(start_time)) return bad(res, 'Bad times');
  const up = db.prepare(`INSERT INTO availability (cleaner_id, date, start_time, end_time, note) VALUES (?,?,?,?,?)
    ON CONFLICT(cleaner_id, date) DO UPDATE SET start_time=excluded.start_time, end_time=excluded.end_time, note=excluded.note`);
  db.transaction(() => dates.forEach(d => up.run(req.user.id, d, start_time, end_time, note)))();
  res.json({ ok: true, count: dates.length });
});

app.delete('/api/me/availability/:date', auth('cleaner'), (req, res) => {
  const mine = db.prepare('SELECT 1 FROM cleans WHERE cleaner_id = ? AND date = ? AND status IN (\'assigned\',\'confirmed\')').get(req.user.id, req.params.date);
  if (mine) return bad(res, 'You are assigned a clean that day. Ask Nicole to move it first.', 409);
  db.prepare('DELETE FROM availability WHERE cleaner_id = ? AND date = ?').run(req.user.id, req.params.date);
  res.json({ ok: true });
});

app.get('/api/me/cleans', auth('cleaner'), (req, res) => {
  const from = req.query.from || new Date().toISOString().slice(0, 10);
  res.json(db.prepare(`SELECT id, date, start_time, duration_hours, client, address, type, notes, status
    FROM cleans WHERE cleaner_id = ? AND date >= ? AND status != 'cancelled' ORDER BY date, start_time`).all(req.user.id, from));
});

app.post('/api/me/cleans/:id/confirm', auth('cleaner'), (req, res) => {
  const r = db.prepare(`UPDATE cleans SET status='confirmed' WHERE id = ? AND cleaner_id = ? AND status='assigned'`).run(req.params.id, req.user.id);
  r.changes ? res.json({ ok: true }) : bad(res, 'Nothing to confirm', 404);
});

// ----- admin: cleaners -----
app.get('/api/admin/cleaners', auth('admin'), (req, res) => {
  res.json(db.prepare('SELECT * FROM cleaners ORDER BY active DESC, name').all());
});
app.post('/api/admin/cleaners', auth('admin'), (req, res) => {
  const { name, phone = '', pin } = req.body;
  if (!name || !/^\d{4,8}$/.test(pin || '')) return bad(res, 'Name and a 4-8 digit PIN required');
  const r = db.prepare('INSERT INTO cleaners (name, phone, pin) VALUES (?,?,?)').run(name.trim(), phone, pin);
  res.json({ id: r.lastInsertRowid });
});
app.patch('/api/admin/cleaners/:id', auth('admin'), (req, res) => {
  const c = db.prepare('SELECT * FROM cleaners WHERE id = ?').get(req.params.id);
  if (!c) return bad(res, 'Not found', 404);
  const n = { ...c, ...req.body };
  if (!/^\d{4,8}$/.test(n.pin)) return bad(res, 'PIN must be 4-8 digits');
  db.prepare('UPDATE cleaners SET name=?, phone=?, pin=?, active=? WHERE id=?').run(n.name, n.phone, n.pin, n.active ? 1 : 0, c.id);
  res.json({ ok: true });
});

// ----- admin: cleans -----
function validateClean(b) {
  if (!DATE_RE.test(b.date || '')) return 'Bad date';
  if (b.start_time && !TIME_RE.test(b.start_time)) return 'Bad start time';
  if (!b.client) return 'Client / property name required';
  if (b.duration_hours != null && !(b.duration_hours > 0 && b.duration_hours <= 16)) return 'Bad duration';
  return null;
}

app.post('/api/admin/cleans', auth('admin'), (req, res) => {
  const b = { start_time: '10:00', duration_hours: 2, type: 'Airbnb turnover', ...req.body };
  const err = validateClean(b);
  if (err) return bad(res, err);
  const r = db.prepare('INSERT INTO cleans (date, start_time, duration_hours, client, address, type, notes) VALUES (?,?,?,?,?,?,?)')
    .run(b.date, b.start_time, b.duration_hours, b.client, b.address || '', b.type, b.notes || '');
  res.json({ id: r.lastInsertRowid });
});

app.patch('/api/admin/cleans/:id', auth('admin'), (req, res) => {
  const c = db.prepare('SELECT * FROM cleans WHERE id = ?').get(req.params.id);
  if (!c) return bad(res, 'Not found', 404);
  const n = { ...c, ...req.body, id: c.id, cleaner_id: c.cleaner_id };
  const err = validateClean(n);
  if (err) return bad(res, err);
  if (!['open', 'assigned', 'confirmed', 'done', 'cancelled'].includes(n.status)) return bad(res, 'Bad status');
  db.prepare('UPDATE cleans SET date=?, start_time=?, duration_hours=?, client=?, address=?, type=?, notes=?, status=? WHERE id=?')
    .run(n.date, n.start_time, n.duration_hours, n.client, n.address, n.type, n.notes, n.status, c.id);
  res.json({ ok: true });
});

app.delete('/api/admin/cleans/:id', auth('admin'), (req, res) => {
  db.prepare('DELETE FROM cleans WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Board for a date range: cleans + who is available each day
app.get('/api/admin/board', auth('admin'), (req, res) => {
  const from = req.query.from, to = req.query.to;
  if (!DATE_RE.test(from || '') || !DATE_RE.test(to || '')) return bad(res, 'from/to required (YYYY-MM-DD)');
  const cleans = db.prepare(`SELECT c.*, cl.name AS cleaner_name FROM cleans c LEFT JOIN cleaners cl ON cl.id = c.cleaner_id
    WHERE c.date BETWEEN ? AND ? AND c.status != 'cancelled' ORDER BY c.date, c.start_time`).all(from, to);
  const avail = db.prepare(`SELECT a.*, cl.name FROM availability a JOIN cleaners cl ON cl.id = a.cleaner_id
    WHERE a.date BETWEEN ? AND ? AND cl.active = 1 ORDER BY cl.name`).all(from, to);
  res.json({ cleans, availability: avail });
});

// Which cleaners could take this clean? (available that day, window covers it, no overlap)
function candidatesFor(clean) {
  const avail = db.prepare(`SELECT a.*, cl.name FROM availability a JOIN cleaners cl ON cl.id = a.cleaner_id
    WHERE a.date = ? AND cl.active = 1`).all(clean.date);
  const booked = db.prepare(`SELECT * FROM cleans WHERE date = ? AND cleaner_id IS NOT NULL AND status IN ('assigned','confirmed','done') AND id != ?`)
    .all(clean.date, clean.id);
  const s = toMin(clean.start_time), e = cleanEnd(clean);
  return avail.map(a => {
    const mine = booked.filter(x => x.cleaner_id === a.cleaner_id);
    const overlap = mine.find(x => toMin(x.start_time) < e && cleanEnd(x) > s);
    const inWindow = toMin(a.start_time) <= s && toMin(a.end_time) >= e;
    return { cleaner_id: a.cleaner_id, name: a.name, window: `${a.start_time}-${a.end_time}`, note: a.note,
      fits_window: inWindow, conflict: overlap ? `${overlap.client} ${overlap.start_time}` : null, jobs_that_day: mine.length };
  }).sort((x, y) => (!!x.conflict - !!y.conflict) || (y.fits_window - x.fits_window) || x.jobs_that_day - y.jobs_that_day);
}

app.get('/api/admin/cleans/:id/candidates', auth('admin'), (req, res) => {
  const c = db.prepare('SELECT * FROM cleans WHERE id = ?').get(req.params.id);
  if (!c) return bad(res, 'Not found', 404);
  res.json(candidatesFor(c));
});

app.post('/api/admin/cleans/:id/assign', auth('admin'), (req, res) => {
  const c = db.prepare('SELECT * FROM cleans WHERE id = ?').get(req.params.id);
  if (!c) return bad(res, 'Not found', 404);
  const cleaner = db.prepare('SELECT * FROM cleaners WHERE id = ? AND active = 1').get(req.body.cleaner_id);
  if (!cleaner) return bad(res, 'Cleaner not found');
  const cand = candidatesFor(c).find(x => x.cleaner_id === cleaner.id);
  const problems = [];
  if (!cand) problems.push(`${cleaner.name} did not post that day`);
  else {
    if (!cand.fits_window) problems.push(`${cleaner.name}'s hours that day are ${cand.window}`);
    if (cand.conflict) problems.push(`overlaps ${cand.conflict}`);
  }
  if (problems.length && !req.body.force) return res.status(409).json({ error: problems.join('; '), needs_force: true });
  db.prepare(`UPDATE cleans SET cleaner_id = ?, status = 'assigned' WHERE id = ?`).run(cleaner.id, c.id);
  res.json({ ok: true, warnings: problems });
});

app.post('/api/admin/cleans/:id/unassign', auth('admin'), (req, res) => {
  db.prepare(`UPDATE cleans SET cleaner_id = NULL, status = 'open' WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

if (require.main === module) {
  if (ADMIN_PASSWORD === 'changeme') console.warn('WARNING: ADMIN_PASSWORD not set, using default "changeme"');
  app.listen(PORT, () => console.log(`Coastal Cleaning scheduler on :${PORT}`));
}
module.exports = app;
