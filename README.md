# ✅ Security Lab — Secured Node.js/Express App

> **For educational use only. This version has all vulnerabilities patched.**

A User Management System originally built with four classic web security vulnerabilities — now fully secured. Use this as a reference for how each vulnerability should be fixed in a real application.

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Create a `.env` file in the project root
```
JWT_SECRET=replace-this-with-a-long-random-string-min-32-chars
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
| `helmet` | Security headers |
| `express-rate-limit` | Brute-force protection |
| `dotenv` | Environment variable loading |

Install all at once:
```bash
npm install express bcrypt jsonwebtoken validator helmet express-rate-limit dotenv
```

---

## What Was Fixed

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

### ❷ Plain-text Passwords — `POST /register`, `POST /login`, seed data

**Problem:** Passwords were stored and compared as plain text. Anyone with database access could read every password.

**Fix:** Passwords are hashed with `bcrypt` before storage and compared with `bcrypt.compare` on login. Seed passwords are also hashed at startup so plain text never sits in memory.

```js
// On register — hash before storing:
const hashedPassword = await bcrypt.hash(password, 10);

// On login — timing-safe comparison:
if (!user || !(await bcrypt.compare(password, user.password))) {
  return res.status(401).json({ error: 'Invalid email or password.' });
}

// Seed data — hashed at startup:
users = await Promise.all(
  rawUsers.map(async (u) => ({ ...u, password: await bcrypt.hash(u.password, 10) }))
);
```

---

### ❸ No Auth / IDOR — `GET /profile`, `GET /users`

**Problem:** `/profile?id=1` was publicly accessible with no login required. Any user could read any other user's data (including passwords) just by changing the `id` param.

**Fix:** Both routes are protected by `requireAuth` middleware that verifies a JWT from the `Authorization` header. The user ID is read from the verified token — never from user-supplied input — eliminating the IDOR.

```js
// Auth middleware — verifies JWT, attaches req.user:
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// Profile route — ID from token, not query param:
app.get('/profile', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  res.json({ id: user.id, email: user.email, name: user.name }); // no password
});
```

To access protected routes, include the token from `/login`:
```
Authorization: Bearer <token>
```

---

### ❹ Missing Security Headers — entire app

**Problem:** No security headers were set, leaving the app open to clickjacking, MIME sniffing, XSS, and protocol downgrade attacks.

**Fix:** `helmet()` is applied as the first middleware, automatically setting ~15 security headers.

```js
const helmet = require('helmet');
app.use(helmet());
// Sets: X-Frame-Options, X-Content-Type-Options,
//       Content-Security-Policy, Strict-Transport-Security, and more.
```

---

### ❺ Hardcoded JWT Secret — `POST /login`

**Problem:** The JWT secret was hardcoded as a string literal in source code, making it visible to anyone with repo access.

**Fix:** Secret is loaded exclusively from the environment. The app will crash on startup if `JWT_SECRET` is missing — intentionally, to prevent running with no secret.

```js
// In .env:
JWT_SECRET=replace-this-with-a-long-random-string-min-32-chars

// In app.js:
jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
```

---

### ❻ No Rate Limiting — `POST /login`, `POST /register`

**Problem:** No limit on login attempts allowed unlimited brute-force password guessing.

**Fix:** `express-rate-limit` restricts each IP to 10 requests per 15 minutes on auth routes.

```js
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, please try again after 15 minutes.' }
});

app.post('/login', authLimiter, async (req, res) => { ... });
app.post('/register', authLimiter, async (req, res) => { ... });
```

---

## API Reference

| Method | Route | Auth Required | Description |
|--------|-------|---------------|-------------|
| `GET` | `/` | No | Serves frontend |
| `POST` | `/register` | No | Register a new user |
| `POST` | `/login` | No | Login and receive JWT |
| `GET` | `/profile` | ✅ Yes | Get your own profile |
| `GET` | `/users` | ✅ Yes | Get all users (no passwords) |

---

## Security Checklist

| # | Issue | Status |
|---|-------|--------|
| 1 | Input validation on all fields | ✅ Fixed |
| 2 | Passwords hashed with bcrypt | ✅ Fixed |
| 3 | JWT auth + IDOR prevention | ✅ Fixed |
| 4 | Security headers via Helmet | ✅ Fixed |
| 5 | JWT secret in environment only | ✅ Fixed |
| 6 | Rate limiting on auth routes | ✅ Fixed |