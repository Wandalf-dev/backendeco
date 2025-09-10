// app.js — API QCM prête pour Render

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// --------- CORS (domaines séparés par virgules dans CORS_ORIGIN) ----------
const allowed = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (allowed.includes('*') || !origin || allowed.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  }
}));
app.use(bodyParser.json());

// Render est derrière un proxy
app.set('trust proxy', 1);

// --------- Config / Secrets ----------
const SECRET_KEY = process.env.SECRET_KEY || 'dev_only_change_me';
if (!process.env.SECRET_KEY) {
  console.warn('⚠️  SECRET_KEY non défini (OK en local), mets-le dans Render > Environment');
}

// --------- Données démo (remplace par ta vraie persistance) ----------
const users = [
  { id: 1, email: 'john@example.com', password: bcrypt.hashSync('password123', 10), name: 'John Doe' },
  { id: 2, email: 'jane@example.com', password: bcrypt.hashSync('mypassword', 10), name: 'Jane Smith' }
];

let articles = [
  { id: 1, title: 'Les bases de Node.js', description: 'Intro Node', content: '...', date: '2025-09-01T09:00:00Z' },
  { id: 2, title: 'Express avancé', description: 'Middleware & co', content: '...', date: '2025-09-05T12:00:00Z' }
];

// --------- Auth (JWT Bearer) ----------
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

// --------- Articles (exemples) ----------
app.get('/articles', (_req, res) => {
  const sorted = [...articles].sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(sorted);
});

app.get('/articles/:id', (req, res) => {
  const id = Number(req.params.id);
  const a = articles.find(x => x.id === id);
  if (!a) return res.status(404).json({ error: 'Article introuvable' });
  res.json(a);
});

app.post('/articles', auth, (req, res) => {
  const { title, description, content, date } = req.body || {};
  const id = Math.max(0, ...articles.map(a => a.id)) + 1;
  const item = { id, title, description, content, date: date || new Date().toISOString() };
  articles.push(item);
  res.status(201).json(item);
});

app.delete('/articles/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const idx = articles.findIndex(x => x.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Article introuvable' });
  const removed = articles.splice(idx, 1)[0];
  res.json({ ok: true, removed });
});

// --------- Health + Root ----------
app.get('/health', (_req, res) => res.send('ok'));
app.get('/', (_req, res) => res.send('API QCM/AgenceEco OK'));

// --------- Swagger ----------
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: { title: 'QCM / AgenceEco API', version: '1.0.0' },
    servers: process.env.SWAGGER_PUBLIC_URL ? [{ url: process.env.SWAGGER_PUBLIC_URL }] : [],
    components: {
      securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
    }
  },
  apis: [] // Ajoute des fichiers avec JSDoc @openapi si tu veux documenter tes routes.
});
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));

// --------- Lancement (Render fournit PORT) ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on :${PORT}`));
