// ============================================================
//  SECURITY LAB — app.js
//  ✅  SECURED VERSION — all vulnerabilities fixed
//  ✅  WEEK 4 — CORS, global rate limiting, API key auth added
// ============================================================

// Load environment variables from .env file
// Create a .env file in the root with: JWT_SECRET=your-long-random-secret
require('dotenv').config();

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const validator  = require('validator');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const cors       = require('cors');
const winston    = require('winston');

// ── Logger Setup ──────────────────────────────────────────
// Logs to both the console and a persistent security.log file.
// Levels: info (normal events), warn (suspicious), error (failures)
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) =>
      `[${timestamp}] ${level.toUpperCase()}: ${message}`
    )
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

const app = express();

// ── Security Middleware ───────────────────────────────────
// helmet() sets all critical security headers automatically:
//   X-Frame-Options: SAMEORIGIN        → prevents clickjacking
//   X-Content-Type-Options: nosniff    → prevents MIME sniffing
//   Content-Security-Policy            → mitigates XSS attacks
//   Strict-Transport-Security          → enforces HTTPS
app.use(helmet());

// ── CORS Configuration ────────────────────────────────────
// Restricts which domains can make requests to this API.
// Only requests from the listed origins will be accepted.
// Change 'http://localhost:3000' to your actual frontend URL in production.
app.use(cors({
  origin: ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true
}));

// ── Global Rate Limiter ───────────────────────────────────
// Applies to ALL routes — limits each IP to 100 requests per 15 minutes.
// authLimiter below adds a stricter limit (10 requests) on /login & /register.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' },
  handler: (req, res, next, options) => {
    const ip = req.ip || req.connection.remoteAddress;
    logger.warn(`GLOBAL RATE LIMIT exceeded — IP: ${ip} on ${req.method} ${req.path}`);
    res.status(options.statusCode).json(options.message);
  }
});
app.use(globalLimiter);

// ── Request Logger ────────────────────────────────────────
// Logs every incoming request: method, path, and IP address.
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  logger.info(`${req.method} ${req.path} — IP: ${ip}`);
  next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Rate Limiter ──────────────────────────────────────────
// Prevents brute-force attacks on auth endpoints.
// Limits each IP to 10 requests per 15 minutes on /login and /register.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts from this IP, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    const ip = req.ip || req.connection.remoteAddress;
    logger.warn(`RATE LIMIT exceeded — IP: ${ip} on ${req.method} ${req.path}`);
    res.status(options.statusCode).json(options.message);
  }
});

// ── Auth Middleware ───────────────────────────────────────
// Verifies the JWT token sent in the Authorization header.
// Usage: Authorization: Bearer <token>
// Attaches the decoded payload to req.user for downstream routes.
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn(`Unauthorized access attempt — no token — IP: ${req.ip} on ${req.path}`);
    return res.status(401).json({ error: 'No token provided. Please log in.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, iat, exp }
    next();
  } catch (err) {
    logger.warn(`Invalid token attempt — IP: ${req.ip} on ${req.path} — ${err.message}`);
    return res.status(401).json({ error: 'Invalid or expired token. Please log in again.' });
  }
}

// ── API Key Middleware ────────────────────────────────────
// Alternative auth method using a static API key in the request header.
// Usage: x-api-key: your-secret-key (set API_KEY in your .env file)
// Apply to any route with: app.use('/api/', apiKeyAuth)
function apiKeyAuth(req, res, next) {
  const clientKey = req.headers['x-api-key'];

  if (!clientKey) {
    logger.warn(`API key missing — IP: ${req.ip} on ${req.path}`);
    return res.status(401).json({ error: 'API key missing. Include x-api-key header.' });
  }

  if (clientKey !== process.env.API_KEY) {
    logger.warn(`Invalid API key attempt — IP: ${req.ip} on ${req.path}`);
    return res.status(403).json({ error: 'Invalid API key.' });
  }

  next();
}

// ── Mock "Database" (in-memory array) ────────────────────
// NOTE: Seed passwords below are placeholders only.
// In a real app, these would already be bcrypt hashes stored in a database.
// On app start, we hash them so the in-memory store never holds plain text.
const rawUsers = [
  { id: 1, email: 'alice@example.com', password: 'password123', name: 'Alice' },
  { id: 2, email: 'bob@example.com',   password: 'hunter2',     name: 'Bob'   },
];

// Hash all seed passwords on startup so plain-text never sits in memory
let users = [];
let nextId = 3;

(async () => {
  users = await Promise.all(
    rawUsers.map(async (u) => ({
      ...u,
      password: await bcrypt.hash(u.password, 10),
    }))
  );
  logger.info('Seed user passwords hashed successfully on startup');
})();

// ── Routes ────────────────────────────────────────────────

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── POST /register ────────────────────────────────────────
// Validates input, hashes the password, and stores the new user.
app.post('/register', authLimiter, async (req, res) => {
  const { email, password, name } = req.body;

  // Validate email format
  if (!email || !validator.isEmail(email)) {
    logger.warn(`Register failed — invalid email format: "${email}" — IP: ${req.ip}`);
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  // Enforce minimum password length
  if (!password || password.length < 6) {
    logger.warn(`Register failed — password too short — IP: ${req.ip}`);
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  // Ensure name is not blank or whitespace-only
  if (!name || validator.isEmpty(name.trim())) {
    logger.warn(`Register failed — missing name — IP: ${req.ip}`);
    return res.status(400).json({ error: 'Name is required.' });
  }

  // Prevent duplicate registrations
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    logger.warn(`Register failed — duplicate email: ${email} — IP: ${req.ip}`);
    return res.status(409).json({ error: 'Email already registered.' });
  }

  // Hash the password before storing — never store plain text
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: nextId++,
    email,
    password: hashedPassword, // only the hash is stored
    name: name.trim(),
  };

  users.push(newUser);

  logger.info(`New user registered — email: ${email} — ID: ${newUser.id} — IP: ${req.ip}`);

  // Return user info without the password hash
  res.status(201).json({
    message: `User "${newUser.name}" registered successfully.`,
    user: { id: newUser.id, email: newUser.email, name: newUser.name },
  });
});

// ── POST /login ───────────────────────────────────────────
// Validates credentials using bcrypt, then issues a signed JWT.
app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Validate email format
  if (!email || !validator.isEmail(email)) {
    logger.warn(`Login failed — invalid email format: "${email}" — IP: ${req.ip}`);
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  // Ensure password field is present
  if (!password) {
    logger.warn(`Login failed — missing password — IP: ${req.ip}`);
    return res.status(400).json({ error: 'Password is required.' });
  }

  const user = users.find(u => u.email === email);

  // Use bcrypt.compare for timing-safe password comparison.
  // Returning the same generic error for both "user not found"
  // and "wrong password" prevents user enumeration attacks.
  if (!user || !(await bcrypt.compare(password, user.password))) {
    logger.warn(`Login failed — invalid credentials for email: ${email} — IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  logger.info(`Login successful — email: ${email} — ID: ${user.id} — IP: ${req.ip}`);

  // Sign a JWT with the user's ID.
  // Secret is loaded from environment — never hardcoded.
  // Token expires in 1 hour to limit the window of misuse if stolen.
  const token = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    message: `Welcome back, ${user.name}!`,
    token,
  });
});

// ── GET /profile ──────────────────────────────────────────
// Returns the authenticated user's own profile.
// requireAuth verifies the JWT and attaches req.user.
// The user ID comes from the verified token — not from a query param —
// so users cannot access each other's profiles (prevents IDOR).
app.get('/profile', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);

  if (!user) {
    logger.error(`Profile fetch failed — user ID ${req.user.id} not found — IP: ${req.ip}`);
    return res.status(404).json({ error: 'User not found.' });
  }

  logger.info(`Profile accessed — user ID: ${req.user.id} — IP: ${req.ip}`);
  // Never include the password hash in any response
  res.json({ id: user.id, email: user.email, name: user.name });
});

// ── GET /users ────────────────────────────────────────────
// Returns all users for authenticated users only (e.g. admin tooling).
// Password hashes are stripped before sending.
app.get('/users', requireAuth, (req, res) => {
  logger.info(`User list accessed — requested by ID: ${req.user.id} — IP: ${req.ip}`);
  const safeUsers = users.map(({ password, ...rest }) => rest);
  res.json(safeUsers);
});

// ── Start server ──────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Security Lab started — http://localhost:${PORT}`);
});