const express = require('express'), cookie = require('cookie-parser'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), Database = require('better-sqlite3'), path = require('path');
const Anthropic = require('@anthropic-ai/sdk');

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (PROD ? (() => { throw new Error('Set JWT_SECRET'); })() : 'dev-secret');
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const ai = process.env.ANTHROPIC_API_KEY ? new Anthropic() : null; // SDK reads ANTHROPIC_API_KEY

const db = new Database(process.env.DB_PATH || 'plantcare.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, created INTEGER);
CREATE TABLE IF NOT EXISTS gardens(user_id INTEGER PRIMARY KEY REFERENCES users(id), data TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), plant_type TEXT, result TEXT, created INTEGER);
`);

const app = express();
app.set('trust proxy', 1);
const ORIGINS = (process.env.ALLOWED_ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean); // e.g. https://yourname.github.io
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ORIGINS.includes(o)) res.set({ 'Access-Control-Allow-Origin': o, Vary: 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '8mb' }), cookie());

const hits = new Map();
const limit = (key, max, ms) => { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length <= max; };
const setCookie = (res, id) => { const t = jwt.sign({ id }, SECRET, { expiresIn: '30d' }); res.cookie('t', t, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 30 * 864e5 }); return t; };
const auth = (req, res, next) => { try { req.uid = jwt.verify(req.cookies.t || (req.headers.authorization || '').replace(/^Bearer /, ''), SECRET).id; next(); } catch { res.status(401).json({ error: 'unauthorized' }); } };

// ---------- auth ----------
app.post('/api/register', (req, res) => {
  const e = String(req.body.email || '').trim().toLowerCase(), p = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) || p.length < 8) return res.status(400).json({ error: 'Enter a valid email and a password of 8+ characters' });
  try {
    const r = db.prepare('INSERT INTO users(email,hash,created) VALUES(?,?,?)').run(e, bcrypt.hashSync(p, 10), Date.now());
    res.json({ email: e, ai: !!ai, token: setCookie(res, r.lastInsertRowid) });
  } catch { res.status(409).json({ error: 'Email already registered' }); }
});
app.post('/api/login', (req, res) => {
  if (!limit('l' + req.ip, 10, 15 * 60e3)) return res.status(429).json({ error: 'Too many attempts, try again later' });
  const e = String(req.body.email || '').trim().toLowerCase(), u = db.prepare('SELECT * FROM users WHERE email=?').get(e);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ email: u.email, ai: !!ai, token: setCookie(res, u.id) });
});
app.post('/api/logout', (req, res) => res.clearCookie('t').json({ ok: true }));
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT email FROM users WHERE id=?').get(req.uid);
  u ? res.json({ email: u.email, ai: !!ai }) : res.status(401).json({ error: 'unauthorized' });
});

// ---------- garden (plants, health history, weather settings, location consent) ----------
app.get('/api/garden', auth, (req, res) => {
  const g = db.prepare('SELECT data,ts FROM gardens WHERE user_id=?').get(req.uid);
  res.json(g ? { data: JSON.parse(g.data), ts: g.ts } : { data: null, ts: 0 });
});
app.put('/api/garden', auth, (req, res) => {
  const d = req.body.data;
  if (!d || !Array.isArray(d.plants) || d.plants.length > 200) return res.status(400).json({ error: 'bad data' });
  const ts = Date.now();
  db.prepare('INSERT INTO gardens(user_id,data,ts) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, ts=excluded.ts').run(req.uid, JSON.stringify(d), ts);
  res.json({ ts });
});

// ---------- AI image diagnosis ----------
const PROMPT = t => `You are an expert plant pathologist. Examine the attached photo of a plant leaf (the user says it is a ${t} plant) and diagnose it carefully from visible symptoms only.
Return ONLY JSON: {"is_plant":boolean,"plant":string,"disease":string ("Healthy" if no disease; use the common name e.g. Early Blight, Late Blight, Septoria Leaf Spot, Powdery Mildew, Leaf Curl, Bacterial Spot, Mosaic Virus, Rust, Nutrient Deficiency, Pest Damage),"conf":integer 0-100 honest confidence,"sev":"none"|"mild"|"moderate"|"severe","sym":[2-4 short visible symptoms you actually see],"act":[4-5 short practical treatment steps for a home urban gardener, organic first],"prev":string one-line prevention tip,"water":string one short watering note for this condition}.
If the image is not a plant leaf or is too blurry, set is_plant false, conf under 40, and explain in "disease". Do not invent a disease when the leaf looks healthy. If the photo is unclear or you are unsure, set conf below 60.`;
const text = m => m.content.filter(b => b.type === 'text').map(b => b.text).join('');

app.post('/api/analyze', auth, async (req, res) => {
  if (!ai) return res.status(503).json({ error: 'unavailable' });
  if (!limit('a' + req.uid, 40, 36e5)) return res.status(429).json({ error: 'rate_limited' });
  const { image, plantType } = req.body;
  if (typeof image !== 'string' || image.length > 7e6) return res.status(400).json({ error: 'bad_image' });
  const type = String(plantType || 'unknown').slice(0, 40);
  try {
    const m = await ai.messages.create({
      model: MODEL, max_tokens: 1000,
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: image } },
        { type: 'text', text: PROMPT(type) }] }]
    });
    const t = text(m), r = JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1));
    r.conf = Math.max(0, Math.min(100, Math.round(+r.conf || 0)));
    if (!['none', 'mild', 'moderate', 'severe'].includes(r.sev)) r.sev = 'none';
    r.sym = (r.sym || []).slice(0, 4).map(String); r.act = (r.act || []).slice(0, 6).map(String);
    db.prepare('INSERT INTO scans(user_id,plant_type,result,created) VALUES(?,?,?,?)').run(req.uid, type, JSON.stringify(r), Date.now());
    res.json(r);
  } catch (e) { console.error('analyze:', e.message); res.status(502).json({ error: 'ai_error' }); }
});
app.get('/api/scans', auth, (req, res) => res.json(db.prepare('SELECT id,plant_type,result,created FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.uid).map(s => ({ ...s, result: JSON.parse(s.result) }))));

// ---------- AI plant assistant ----------
app.post('/api/chat', auth, async (req, res) => {
  if (!ai) return res.status(503).json({ error: 'unavailable' });
  if (!limit('c' + req.uid, 120, 36e5)) return res.status(429).json({ error: 'rate_limited' });
  const msgs = (Array.isArray(req.body.messages) ? req.body.messages : []).slice(-8)
    .filter(m => ['user', 'assistant'].includes(m.role) && typeof m.content === 'string' && m.content).map(m => ({ role: m.role, content: m.content.slice(0, 4000) }));
  if (!msgs.length || msgs[0].role !== 'user' || msgs[msgs.length - 1].role !== 'user') return res.status(400).json({ error: 'bad_messages' });
  try {
    const m = await ai.messages.create({ model: MODEL, max_tokens: 600, messages: msgs,
      system: 'You are the PlantCare AI assistant for urban gardeners. Answer using the garden data in the first message. Be concise, practical and organic-first. Say when you are unsure and advise consulting a local agricultural expert for severe or unclear problems.' });
    res.json({ text: text(m) });
  } catch (e) { console.error('chat:', e.message); res.status(502).json({ error: 'ai_error' }); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('PlantCare AI running on port ' + (process.env.PORT || 3000) + (ai ? '' : ' (no ANTHROPIC_API_KEY: AI disabled)')));
