const express = require('express'), cookie = require('cookie-parser'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), Database = require('better-sqlite3'), path = require('path');

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (PROD ? (() => { throw new Error('Set JWT_SECRET'); })() : 'dev-secret');

const MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash-lite';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || null;

const db = new Database(process.env.DB_PATH || 'plantcare.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, created INTEGER);
CREATE TABLE IF NOT EXISTS gardens(user_id INTEGER PRIMARY KEY REFERENCES users(id), data TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), plant_type TEXT, result TEXT, created INTEGER);
`);

const app = express();
app.set('trust proxy', 1);

const ORIGINS = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const o = req.headers.origin;

  if (o && ORIGINS.includes(o)) {
    res.set({
      'Access-Control-Allow-Origin': o,
      'Vary': 'Origin',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS'
    });
  }

  if (req.method === 'OPTIONS') return res.sendStatus(204);

  next();
});

app.use(express.json({ limit: '8mb' }), cookie());

const hits = new Map();

const limit = (key, max, ms) => {
  const n = Date.now();
  const a = (hits.get(key) || []).filter(t => n - t < ms);

  a.push(n);
  hits.set(key, a);

  return a.length <= max;
};

const setCookie = (res, id) => {
  const t = jwt.sign({ id }, SECRET, { expiresIn: '30d' });

  res.cookie('t', t, {
    httpOnly: true,
    sameSite: 'lax',
    secure: PROD,
    maxAge: 30 * 864e5
  });

  return t;
};

const auth = (req, res, next) => {
  try {
    req.uid = jwt.verify(
      req.cookies.t ||
      (req.headers.authorization || '').replace(/^Bearer /, ''),
      SECRET
    ).id;

    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
};

// ---------- Gemini AI helper ----------

async function geminiGenerate(contents, config = {}) {
  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is not configured');
  }

  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      contents,
      generationConfig: config
    })
  });

  const data = await response.json();

  if (!response.ok) {
    console.error('Gemini API error:', JSON.stringify(data));
    throw new Error(data?.error?.message || 'Gemini API request failed');
  }

  return data?.candidates?.[0]?.content?.parts
    ?.map(p => p.text || '')
    .join('') || '';
}

// ---------- auth ----------

app.post('/api/register', (req, res) => {
  const e = String(req.body.email || '').trim().toLowerCase();
  const p = String(req.body.password || '');

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) || p.length < 8) {
    return res.status(400).json({
      error: 'Enter a valid email and a password of 8+ characters'
    });
  }

  try {
    const r = db
      .prepare('INSERT INTO users(email,hash,created) VALUES(?,?,?)')
      .run(e, bcrypt.hashSync(p, 10), Date.now());

    res.json({
      email: e,
      ai: !!GEMINI_API_KEY,
      token: setCookie(res, r.lastInsertRowid)
    });
  } catch {
    res.status(409).json({
      error: 'Email already registered'
    });
  }
});

app.post('/api/login', (req, res) => {
  if (!limit('l' + req.ip, 10, 15 * 60e3)) {
    return res.status(429).json({
      error: 'Too many attempts, try again later'
    });
  }

  const e = String(req.body.email || '').trim().toLowerCase();

  const u = db
    .prepare('SELECT * FROM users WHERE email=?')
    .get(e);

  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) {
    return res.status(401).json({
      error: 'Wrong email or password'
    });
  }

  res.json({
    email: u.email,
    ai: !!GEMINI_API_KEY,
    token: setCookie(res, u.id)
  });
});

app.post('/api/logout', (req, res) =>
  res.clearCookie('t').json({ ok: true })
);

app.get('/api/me', auth, (req, res) => {
  const u = db
    .prepare('SELECT email FROM users WHERE id=?')
    .get(req.uid);

  u
    ? res.json({
        email: u.email,
        ai: !!GEMINI_API_KEY
      })
    : res.status(401).json({
        error: 'unauthorized'
      });
});

// ---------- garden ----------

app.get('/api/garden', auth, (req, res) => {
  const g = db
    .prepare('SELECT data,ts FROM gardens WHERE user_id=?')
    .get(req.uid);

  res.json(
    g
      ? {
          data: JSON.parse(g.data),
          ts: g.ts
        }
      : {
          data: null,
          ts: 0
        }
  );
});

app.put('/api/garden', auth, (req, res) => {
  const d = req.body.data;

  if (!d || !Array.isArray(d.plants) || d.plants.length > 200) {
    return res.status(400).json({
      error: 'bad data'
    });
  }

  const ts = Date.now();

  db.prepare(`
    INSERT INTO gardens(user_id,data,ts)
    VALUES(?,?,?)
    ON CONFLICT(user_id)
    DO UPDATE SET data=excluded.data, ts=excluded.ts
  `).run(
    req.uid,
    JSON.stringify(d),
    ts
  );

  res.json({ ts });
});

// ---------- AI image diagnosis ----------

const PROMPT = t => `You are an expert plant pathologist.

Examine the attached photo of a plant leaf. The user says it is a ${t} plant.

Diagnose it carefully from visible symptoms only.

Return ONLY valid JSON in exactly this structure:

{
  "is_plant": true,
  "plant": "plant name",
  "disease": "disease name",
  "conf": 0,
  "sev": "none",
  "sym": ["symptom 1", "symptom 2"],
  "act": ["treatment step 1", "treatment step 2"],
  "prev": "one-line prevention tip",
  "water": "one short watering note"
}

Rules:

- "is_plant" must be false if the image is not a plant leaf.
- If the image is too blurry or unclear, set confidence below 40.
- Do not invent a disease.
- Use "Healthy" when there is no visible disease.
- Use common disease names such as Early Blight, Late Blight, Septoria Leaf Spot, Powdery Mildew, Leaf Curl, Bacterial Spot, Mosaic Virus, Rust, Nutrient Deficiency, or Pest Damage when appropriate.
- "conf" must be an honest integer from 0 to 100.
- "sev" must be exactly one of: none, mild, moderate, severe.
- "sym" must contain 2 to 4 short visible symptoms.
- "act" must contain 4 to 5 practical treatment steps for a home urban gardener.
- Prefer organic treatment first.
- "prev" must be one short prevention tip.
- "water" must be one short watering note.
- If unsure, keep confidence below 60.`;

// Convert the AI response into clean JSON
function extractJson(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');

  if (start === -1 || end === -1) {
    throw new Error('Gemini did not return JSON');
  }

  return JSON.parse(text.slice(start, end + 1));
}

app.post('/api/analyze', auth, async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(503).json({
      error: 'unavailable'
    });
  }

  if (!limit('a' + req.uid, 40, 36e5)) {
    return res.status(429).json({
      error: 'rate_limited'
    });
  }

  const { image, plantType } = req.body;

  if (typeof image !== 'string' || image.length > 7e6) {
    return res.status(400).json({
      error: 'bad_image'
    });
  }

  const type = String(plantType || 'unknown').slice(0, 40);

  try {
    const prompt = PROMPT(type);

    const text = await geminiGenerate([
      {
        role: 'user',
        parts: [
          {
            inlineData: {
              mimeType: 'image/jpeg',
              data: image
            }
          },
          {
            text: prompt
          }
        ]
      }
    ], {
      temperature: 0.2,
      maxOutputTokens: 1000,
      responseMimeType: 'application/json'
    });

    const r = extractJson(text);

    r.conf = Math.max(
      0,
      Math.min(
        100,
        Math.round(Number(r.conf) || 0)
      )
    );

    if (!['none', 'mild', 'moderate', 'severe'].includes(r.sev)) {
      r.sev = 'none';
    }

    r.sym = (r.sym || [])
      .slice(0, 4)
      .map(String);

    r.act = (r.act || [])
      .slice(0, 6)
      .map(String);

    db.prepare(`
      INSERT INTO scans(user_id,plant_type,result,created)
      VALUES(?,?,?,?)
    `).run(
      req.uid,
      type,
      JSON.stringify(r),
      Date.now()
    );

    res.json(r);

  } catch (e) {
    console.error('analyze:', e.message);

    res.status(502).json({
      error: 'ai_error'
    });
  }
});

app.get('/api/scans', auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT id,plant_type,result,created
      FROM scans
      WHERE user_id=?
      ORDER BY id DESC
      LIMIT 50
    `)
    .all(req.uid)
    .map(s => ({
      ...s,
      result: JSON.parse(s.result)
    }))
  );
});

// ---------- AI plant assistant ----------

app.post('/api/chat', auth, async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(503).json({
      error: 'unavailable'
    });
  }

  if (!limit('c' + req.uid, 120, 36e5)) {
    return res.status(429).json({
      error: 'rate_limited'
    });
  }

  const msgs = (
    Array.isArray(req.body.messages)
      ? req.body.messages
      : []
  )
    .slice(-8)
    .filter(
      m =>
        ['user', 'assistant'].includes(m.role) &&
        typeof m.content === 'string' &&
        m.content
    )
    .map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [
        {
          text: m.content.slice(0, 4000)
        }
      ]
    }));

  if (
    !msgs.length ||
    msgs[0].role !== 'user' ||
    msgs[msgs.length - 1].role !== 'user'
  ) {
    return res.status(400).json({
      error: 'bad_messages'
    });
  }

  try {
    const text = await geminiGenerate(msgs, {
      temperature: 0.4,
      maxOutputTokens: 600,
      systemInstruction: {
        parts: [
          {
            text: 'You are the PlantCare AI assistant for urban gardeners. Answer using the garden data in the conversation. Be concise, practical and organic-first. Say when you are unsure and advise consulting a local agricultural expert for severe or unclear problems.'
          }
        ]
      }
    });

    res.json({
      text
    });

  } catch (e) {
    console.error('chat:', e.message);

    res.status(502).json({
      error: 'ai_error'
    });
  }
});

// ---------- frontend ----------

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    'PlantCare AI running on port ' +
    PORT +
    (GEMINI_API_KEY
      ? ' (Gemini AI enabled)'
      : ' (no GEMINI_API_KEY: AI disabled)')
  );
});
