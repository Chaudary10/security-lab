# Security Lab — Secured Node.js/Express App

> **For educational use only. This version has all vulnerabilities patched.**

A User Management System built with Node.js and Express, progressively secured over multiple weeks. All classic web vulnerabilities have been fixed, and Week 4 adds advanced threat detection, API hardening, and security headers.

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Create a `.env` file in the project root
```
JWT_SECRET=replace-this-with-a-long-random-string-min-32-chars
API_KEY=your-api-key-here
PORT=3000
```

### 3. Start the server
```bash
npm start
# → http://localhost:3000
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `express` | Web framework |
| `bcrypt` | Password hashing |
| `jsonwebtoken` | JWT auth tokens |
| `validator` | Input validation |
| `helmet` | Security headers (CSP, HSTS, XSS protection) |
| `express-rate-limit` | Brute-force & rate limiting protection |
| `cors` | Cross-Origin Resource Sharing control |
| `winston` | Logging to console and file |
| `dotenv` | Environment variable loading |
| `body-parser` | Request body parsing |

Install all at once:
```bash
npm install express bcrypt jsonwebtoken validator helmet express-rate-limit cors winston dotenv body-parser
```

---

## Project Structure

```
security-lab/
├── app.js          # Main server — all security middleware
├── security.log    # Auto-generated log file (git ignored)
├── .env            # Environment secrets (git ignored)
├── .gitignore      # Excludes .env, node_modules, security.log
├── package.json
└── public/
    └── index.html  # Frontend
```

---

## Previous Weeks — Vulnerabilities Fixed

### ❶ Input Validation — `POST /register`, `POST /login`

**Problem:** Any value was accepted for email and password — blank passwords, invalid emails, etc.

**Fix:** All inputs are validated before processing using the `validator` package.

```js
if (!email || !validator.isEmail(email))
  return res.status(400).json({ error: 'Invalid email format.' });

if (!password || password.length < 6)
  return res.status(400).json({ error: 'Password must be at least 6 characters.' });

if (!name || validator.isEmpty(name.trim()))
  return res.status(400).json({ error: 'Name is required.' });
```

---

### ❷ Plain-text Passwords — `POST /register`, `POST /login`

**Problem:** Passwords were stored and compared as plain text.

**Fix:** Passwords are hashed with `bcrypt` before storage and compared with `bcrypt.compare` on login. Seed passwords are also hashed at startup.

```js
const hashedPassword = await bcrypt.hash(password, 10);

if (!user || !(await bcrypt.compare(password, user.password))) {
  return res.status(401).json({ error: 'Invalid email or password.' });
}
```

---

### ❸ No Auth / IDOR — `GET /profile`, `GET /users`

**Problem:** `/profile?id=1` was publicly accessible. Any user could read any other user's data by changing the `id` param.

**Fix:** Both routes are protected by `requireAuth` middleware that verifies a JWT. The user ID is read from the verified token — never from user-supplied input.

```js
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}
```

---

### ❹ Hardcoded JWT Secret

**Problem:** The JWT secret was hardcoded in source code, visible to anyone with repo access.

**Fix:** Secret is loaded exclusively from the `.env` file.

```js
jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
```

---

## Week 4 — Advanced Threat Detection & Web Security

### Task 1 — Intrusion Detection & Monitoring

- **Fail2Ban** set up on the Linux server to monitor SSH login attempts in real time
- Bans any IP after **5 failed attempts** within 10 minutes for 1 hour
- **Winston logger** integrated in `app.js` — logs every request, warning, and error to both console and `security.log`
- Every failed login, rate limit breach, and unauthorized access attempt is logged with timestamp and IP address

```js
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
```

---

### Task 2 — API Security Hardening

#### Rate Limiting (`express-rate-limit`)

Two layers of protection:

| Limiter | Routes | Max Requests | Window |
|--------|--------|-------------|--------|
| Global Limiter | All routes | 100 requests | 15 minutes |
| Auth Limiter | `/login`, `/register` | 10 requests | 15 minutes |

```js
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(globalLimiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post('/login', authLimiter, ...);
app.post('/register', authLimiter, ...);
```

#### CORS Configuration

Only requests from whitelisted origins are accepted. All others are blocked.

```js
app.use(cors({
  origin: ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true
}));
```

#### API Key Authentication

Every request must include a valid API key in the `x-api-key` header.

```js
function apiKeyAuth(req, res, next) {
  const clientKey = req.headers['x-api-key'];
  if (!clientKey) return res.status(401).json({ error: 'API key missing.' });
  if (clientKey !== process.env.API_KEY) return res.status(403).json({ error: 'Invalid API key.' });
  next();
}
```

---

### Task 3 — Security Headers & CSP Implementation

All headers applied via **Helmet.js**:

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Blocks XSS / script injection by whitelisting trusted sources |
| `Strict-Transport-Security` | Forces HTTPS (maxAge: 1 year, includeSubDomains, preload) |
| `X-Frame-Options` | Prevents clickjacking via iframe embedding |
| `X-Content-Type-Options` | Prevents MIME type sniffing |
| `X-XSS-Protection` | Enables browser built-in XSS filter |

**CSP Directives:**
```js
helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],
    styleSrc:   ["'self'", "'unsafe-inline'"],
    imgSrc:     ["'self'", "data:"],
    objectSrc:  ["'none'"],
    frameSrc:   ["'none'"],
  }
});
```

**HSTS Configuration:**
```js
helmet.hsts({
  maxAge: 31536000,       // 1 year
  includeSubDomains: true,
  preload: true
});
```

---

## API Reference

| Method | Route | Auth Required | Description |
|--------|-------|--------------|-------------|
| `GET` | `/` | No | Serves frontend |
| `POST` | `/register` | No | Register a new user |
| `POST` | `/login` | No | Login and receive JWT |
| `GET` | `/profile` | JWT token | Get your own profile |
| `GET` | `/users` | JWT token | Get all users (no passwords) |

### Example Requests

**Register:**
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test User"}'
```

**Login:**
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}'
```

**Access protected route:**
```bash
curl http://localhost:3000/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Access with API key:**
```bash
curl http://localhost:3000/profile \
  -H "x-api-key: your-api-key-here"
```

---

## Complete Security Checklist

| # | Feature | Status |
|---|---------|--------|
| 1 | Input validation on all fields | ✅ Done |
| 2 | Passwords hashed with bcrypt | ✅ Done |
| 3 | JWT auth + IDOR prevention | ✅ Done |
| 4 | JWT secret in environment only | ✅ Done |
| 5 | Rate limiting on auth routes | ✅ Done |
| 6 | Global rate limiting on all routes | ✅ Done |
| 7 | CORS — restrict unauthorized origins | ✅ Done |
| 8 | API key authentication middleware | ✅ Done |
| 9 | Content Security Policy (CSP) | ✅ Done |
| 10 | HSTS — enforce HTTPS | ✅ Done |
| 11 | Security headers via Helmet | ✅ Done |
| 12 | Real-time logging with Winston | ✅ Done |
| 13 | Fail2Ban intrusion detection | ✅ Done |