'use strict';
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── File I/O ─────────────────────────────────────────────
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

function read(file, def = null) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA, `${file}.json`), 'utf8')); }
  catch { return def; }
}
function write(file, data) {
  fs.writeFileSync(path.join(DATA, `${file}.json`), JSON.stringify(data, null, 2));
}

// ── Config (auto-generated on first run) ──────────────────────
function getConfig() {
  let c = read('config');
  if (!c) {
    c = { secret: crypto.randomBytes(32).toString('hex'), adminPw: null };
    write('config', c);
  }
  return c;
}

// ── Default template seed (Lun–Ven 15:00–19:00) ─────────────────
function seedTemplate() {
  if (read('template') !== null) return;
  const tpl = [];
  for (let dow = 1; dow <= 5; dow++)
    for (const time of ['15:00', '16:00', '17:00', '18:00', '19:00'])
      tpl.push({ dow, time });
  write('template', tpl);
}

// ── Password hash ────────────────────────────────────
function hashPw(pw) {
  return crypto.createHmac('sha256', 'rv-salt').update(pw).digest('hex');
}

// ── Token (HMAC-signed, 30 days) ─────────────────────────
function signToken(payload) {
  const { secret } = getConfig();
  const body = Buffer.from(JSON.stringify({
    ...payload,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  try {
    if (!token) return null;
    const dot = token.lastIndexOf('.');
    const body = token.slice(0, dot);
    const sig  = token.slice(dot + 1);
    const { secret } = getConfig();
    const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
    if (sig !== expected) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}

// ── Auth helpers ───────────────────────────────────
function authOf(req) {
  const h = req.headers.authorization || '';
  return verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');
}

function requireStudent(req, res, next) {
  const p = authOf(req);
  if (!p || p.type !== 'student') return res.status(401).json({ error: 'Non autenticato' });
  req.user = p; next();
}

function requireAdmin(req, res, next) {
  const p = authOf(req);
  if (!p || p.type !== 'admin') return res.status(401).json({ error: 'Non autorizzato' });
  next();
}

const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

// ── Slot logic ──────────────────────────────────────
function computeSlots(weeksAhead = 4) {
  const template   = read('template', []);
  const exceptions = read('exceptions', []);
  const bookings   = read('bookings', []);
  const booked = new Set(
    bookings.filter(b => b.status !== 'annullata').map(b => `${b.date}|${b.time}`)
  );
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const result = [];
  for (let i = 1; i <= weeksAhead * 7; i++) {
    const d   = new Date(today); d.setDate(today.getDate() + i);
    const ds  = d.toISOString().slice(0, 10);
    const dow = d.getDay();
    const times = new Set(template.filter(t => t.dow == dow).map(t => t.time));
    for (const e of exceptions.filter(x => x.date === ds)) {
      if (e.type === 'add') times.add(e.time);
      else                   times.delete(e.time);
    }
    for (const t of [...times].sort())
      result.push({ date: ds, time: t, available: !booked.has(`${ds}|${t}`) });
  }
  return result;
}

function computeRecurring(startDate, time, count) {
  const template   = read('template', []);
  const exceptions = read('exceptions', []);
  const bookings   = read('bookings', []);
  const booked = new Set(
    bookings.filter(b => b.status !== 'annullata').map(b => `${b.date}|${b.time}`)
  );
  const dates  = [startDate];
  const d      = new Date(startDate + 'T00:00:00');
  let   safety = 0;
  while (dates.length < count && safety < 120) {
    safety++;
    d.setDate(d.getDate() + 7);
    const ds  = d.toISOString().slice(0, 10);
    const dow = d.getDay();
    const dayExc = exceptions.filter(e => e.date === ds && e.time === time);
    let avail = template.some(t => t.dow == dow && t.time === time);
    for (const e of dayExc) {
      if (e.type === 'add')    avail = true;
      if (e.type === 'remove') avail = false;
    }
    if (avail && !booked.has(`${ds}|${time}`)) dates.push(ds);
  }
  return dates;
}

// ── Routes: Auth ───────────────────────────────────
app.post('/api/register', (req, res) => {
  const { nome, cognome, telefono, pw } = req.body;
  if (!nome || !cognome || !telefono || !pw)
    return res.status(400).json({ error: 'Dati mancanti' });
  if (pw.length < 6)
    return res.status(400).json({ error: 'Password troppo corta (min 6)' });
  const users = read('users', []);
  if (users.find(u => u.telefono === telefono))
    return res.status(400).json({ error: 'Numero già registrato' });
  const u = { id: uid(), nome, cognome, telefono, pwHash: hashPw(pw), createdAt: new Date().toISOString() };
  users.push(u); write('users', users);
  res.json({ token: signToken({ type: 'student', id: u.id, nome, cognome, telefono }), user: { id: u.id, nome, cognome, telefono } });
});

app.post('/api/login', (req, res) => {
  const { telefono, pw } = req.body;
  const u = read('users', []).find(x => x.telefono === telefono && x.pwHash === hashPw(pw));
  if (!u) return res.status(401).json({ error: 'Telefono o password errati' });
  res.json({ token: signToken({ type: 'student', id: u.id, nome: u.nome, cognome: u.cognome, telefono: u.telefono }), user: { id: u.id, nome: u.nome, cognome: u.cognome, telefono: u.telefono } });
});

app.get('/api/admin/status', (req, res) => {
  res.json({ configured: !!getConfig().adminPw });
});

app.post('/api/admin/setup', (req, res) => {
  const cfg = getConfig();
  if (cfg.adminPw) return res.status(400).json({ error: 'Admin già configurato' });
  const { pw } = req.body;
  if (!pw || pw.length < 6) return res.status(400).json({ error: 'Password troppo corta' });
  cfg.adminPw = hashPw(pw); write('config', cfg);
  res.json({ token: signToken({ type: 'admin' }) });
});

app.post('/api/admin/login', (req, res) => {
  const cfg = getConfig();
  if (!cfg.adminPw) return res.status(400).json({ error: 'Non configurato', needSetup: true });
  const { pw } = req.body;
  if (hashPw(pw) !== cfg.adminPw) return res.status(401).json({ error: 'Password errata' });
  res.json({ token: signToken({ type: 'admin' }) });
});

app.put('/api/admin/password', requireAdmin, (req, res) => {
  const { pw } = req.body;
  if (!pw || pw.length < 6) return res.status(400).json({ error: 'Password troppo corta' });
  const cfg = getConfig(); cfg.adminPw = hashPw(pw); write('config', cfg);
  res.json({ ok: true });
});

// ── Routes: Slots ──────────────────────────────────
app.get('/api/slots', requireStudent, (req, res) => {
  const weeks = Math.min(parseInt(req.query.weeks) || 4, 12);
  res.json(computeSlots(weeks));
});

app.get('/api/recurring', requireStudent, (req, res) => {
  const { startDate, time, count } = req.query;
  const n = Math.min(parseInt(count) || 1, 10);
  res.json(computeRecurring(startDate, time, n));
});

// ── Routes: Template ────────────────────────────────
app.get('/api/template', requireAdmin, (req, res) => res.json(read('template', [])));

app.post('/api/template', requireAdmin, (req, res) => {
  const { dow, time } = req.body;
  if (!time || dow === undefined) return res.status(400).json({ error: 'Dati mancanti' });
  const tpl = read('template', []);
  if (tpl.find(t => t.dow == dow && t.time === time))
    return res.status(400).json({ error: 'Slot già presente' });
  tpl.push({ dow: parseInt(dow), time }); write('template', tpl);
  res.json(tpl);
});

app.delete('/api/template', requireAdmin, (req, res) => {
  const { dow, time } = req.body;
  write('template', read('template', []).filter(t => !(t.dow == dow && t.time === time)));
  res.json(read('template', []));
});

// ── Routes: Exceptions ──────────────────────────────
app.get('/api/exceptions', requireAdmin, (req, res) => res.json(read('exceptions', [])));

app.post('/api/exceptions', requireAdmin, (req, res) => {
  const { date, time, type } = req.body;
  if (!date || !time || !type) return res.status(400).json({ error: 'Dati mancanti' });
  const exc = read('exceptions', []);
  if (exc.find(e => e.date === date && e.time === time && e.type === type))
    return res.status(400).json({ error: 'Eccezione già presente' });
  exc.push({ date, time, type }); write('exceptions', exc);
  res.json(exc);
});

app.delete('/api/exceptions', requireAdmin, (req, res) => {
  const { date, time, type } = req.body;
  write('exceptions', read('exceptions', []).filter(e =>
    !(e.date === date && e.time === time && e.type === type)
  ));
  res.json(read('exceptions', []));
});

// ── Routes: Bookings ───────────────────────────────
app.get('/api/bookings', (req, res) => {
  const p = authOf(req);
  if (!p) return res.status(401).json({ error: 'Non autenticato' });
  const bs = read('bookings', []);
  res.json(p.type === 'admin' ? bs : bs.filter(b => b.userId === p.id));
});

app.post('/api/bookings', requireStudent, (req, res) => {
  const { startDate, time, subject, topic, count } = req.body;
  if (!startDate || !time || !subject || !topic)
    return res.status(400).json({ error: 'Dati mancanti' });
  const n      = Math.min(parseInt(count) || 1, 10);
  const dates  = computeRecurring(startDate, time, n);
  const bs     = read('bookings', []);
  const booked = new Set(bs.filter(b => b.status !== 'annullata').map(b => `${b.date}|${b.time}`));
  const created = [];
  for (const date of dates) {
    if (booked.has(`${date}|${time}`)) continue;
    const b = {
      id: uid(), userId: req.user.id,
      nome: req.user.nome, cognome: req.user.cognome, telefono: req.user.telefono,
      date, time, subject, topic,
      status: 'confermata', createdAt: new Date().toISOString()
    };
    bs.push(b); created.push(b); booked.add(`${date}|${time}`);
  }
  write('bookings', bs);
  res.json(created);
});

app.patch('/api/bookings/:id', (req, res) => {
  const p = authOf(req);
  if (!p) return res.status(401).json({ error: 'Non autenticato' });
  const bs = read('bookings', []);
  const b  = bs.find(x => x.id === req.params.id);
  if (!b) return res.status(404).json({ error: 'Non trovata' });
  if (p.type === 'student' && b.userId !== p.id)
    return res.status(403).json({ error: 'Non autorizzato' });
  b.status = req.body.status;
  write('bookings', bs);
  res.json(b);
});

// ── Routes: Students (admin) ──────────────────────────
app.get('/api/students', requireAdmin, (req, res) => {
  const users = read('users', []).map(({ pwHash, ...u }) => u);
  const bs    = read('bookings', []);
  res.json(users.map(u => ({
    ...u,
    activeBookings: bs.filter(b => b.userId === u.id && b.status === 'confermata').length
  })));
});

// ── Start ──────────────────────────────────────────
seedTemplate();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`▶  http://localhost:${PORT}`));
