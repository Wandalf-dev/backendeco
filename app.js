// app.js — API QCM/AgenceEco (Render-ready, articles CRUD)

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // ✅ pour chemin absolu swagger

const app = express();

/* =========================
   CORS (liste, sans slash)
   ========================= */
const allowedRaw = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const allowed = allowedRaw.map(u => u.replace(/\/$/, ''));

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // OK pour serveur à serveur
    const o = origin.replace(/\/$/, '');
    if (allowed.includes('*') || allowed.includes(o)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  }
}));
app.use(bodyParser.json());

// Render est derrière un proxy
app.set('trust proxy', 1);

/* =========================
   Config / Secrets
   ========================= */
const SECRET_KEY = process.env.SECRET_KEY || 'dev_only_change_me';
if (!process.env.SECRET_KEY) {
  console.warn('⚠️  SECRET_KEY non défini (OK en local), mets-le dans Render > Environment');
}

/* =========================
   Données démo (in-memory)
   ========================= */
const users = [
  { id: 1, email: 'john@example.com', password: bcrypt.hashSync('password123', 10), name: 'John Doe' },
  { id: 2, email: 'jane@example.com', password: bcrypt.hashSync('mypassword', 10), name: 'Jane Smith' }
];

let articles = [
  { id: 1, title: "Les bases de Node.js", description: "Intro Node.js", content: "Node.js est un environnement...", publicationDate: "2023-01-01" },
  { id: 2, title: "REST API avec Express", description: "Créer une API", content: "Express est un framework...", publicationDate: "2023-02-15" },
  { id: 3, title: "L’éco-conception web", description: "Impact environnemental", content: "L’éco-conception consiste à...", publicationDate: "2023-03-20" },
  { id: 4, title: "Bonnes pratiques HTML", description: "Accessibilité", content: "Utiliser les bonnes balises...", publicationDate: "2023-04-05" }
];

/* =========================
   Auth (JWT Bearer)
   ========================= */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = users.find(x => x.email === email);
  if (!u || !bcrypt.compareSync(password, u.password)) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  const token = jwt.sign({ id: u.id, email: u.email, name: u.name }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ token, user: { id: u.id, email: u.email, name: u.name } });
});

/* =========================
   Helpers Articles
   ========================= */
const getArticleDate = (a) => a?.publicationDate || a?.date || null;
const normalizeToISO = (v) => {
  if (!v) return new Date().toISOString();
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return new Date(v + 'T00:00:00Z').toISOString();
  return new Date(v).toISOString();
};

/* =========================
   Articles (CRUD)
   ========================= */
app.get('/articles', (_req, res) => {
  const sorted = [...articles].sort((a, b) => new Date(getArticleDate(b)) - new Date(getArticleDate(a)));
  res.json(sorted);
});

app.get('/articles/:id', (req, res) => {
  const id = Number(req.params.id);
  const a = articles.find(x => x.id === id);
  if (!a) return res.status(404).json({ error: 'Article introuvable' });
  res.json(a);
});

app.post('/articles', auth, (req, res) => {
  const { title, description, content, publicationDate, date } = req.body || {};
  const errors = {};
  if (!title || String(title).trim().length < 3) errors.title = 'Le titre doit contenir au moins 3 caractères';
  if (!content || String(content).trim().length < 10) errors.content = 'Le contenu doit contenir au moins 10 caractères';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const id = Math.max(0, ...articles.map(a => a.id)) + 1;
  const pubISO = normalizeToISO(publicationDate || date || new Date().toISOString());

  const item = { id, title, description: description ?? '', content, publicationDate: pubISO };
  articles.push(item);
  res.status(201).json(item);
});

app.put('/articles/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const idx = articles.findIndex(a => a.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Article introuvable' });

  const { title, description, content, publicationDate, date } = req.body || {};
  const errors = {};
  if (title !== undefined && String(title).trim().length < 3) errors.title = 'Le titre doit contenir au moins 3 caractères';
  if (content !== undefined && String(content).trim().length < 10) errors.content = 'Le contenu doit contenir au moins 10 caractères';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const current = articles[idx];
  const pubISO = normalizeToISO(publicationDate ?? date ?? current.publicationDate ?? current.date ?? new Date().toISOString());

  articles[idx] = { ...current, title: title ?? current.title, description: description ?? current.description, content: content ?? current.content, publicationDate: pubISO };
  res.json(articles[idx]);
});

app.delete('/articles/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const idx = articles.findIndex(x => x.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Article introuvable' });
  const removed = articles.splice(idx, 1)[0];
  res.json({ ok: true, removed });
});

/* =========================
   Aliases optionnels (/api/*, /news/*)
   ========================= */
app.get(['/api/articles', '/news', '/api/news'], (_req, res) => res.json(articles));
app.get(['/api/articles/:id', '/news/:id', '/api/news/:id'], (req, res) => {
  const id = Number(req.params.id);
  const a = articles.find(x => x.id === id);
  if (!a) return res.status(404).json({ error: 'Article introuvable' });
  res.json(a);
});
app.put(['/api/articles/:id', '/news/:id', '/api/news/:id'], auth, (req, res) => {
  req.url = `/articles/${req.params.id}`;
  app._router.handle(req, res);
});

/* =========================
   Health + Root
   ========================= */
app.get('/health', (_req, res) => res.send('ok'));
app.get('/', (_req, res) => res.send('API QCM/AgenceEco OK'));

/* =========================
   Swagger (corrigé)
   ========================= */
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: { title: 'QCM / AgenceEco API', version: '1.0.0' },
    servers: process.env.SWAGGER_PUBLIC_URL ? [{ url: process.env.SWAGGER_PUBLIC_URL }] : [],
    components: {
      securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
    }
  },
  apis: [path.join(__dirname, 'app.js')], // ✅ corrige apis: [] → scan app.js
});
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));

/* =========================
   Boot
   ========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on :${PORT}`));
