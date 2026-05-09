<<<<<<< HEAD
# ⚠️ Security Lab — Vulnerable Node.js/Express App

> **For educational use only. Never deploy this publicly.**

A purposefully broken User Management System designed so you can find, exploit, and fix four classic web security vulnerabilities.

---

## Quick Start

```bash
npm install
npm start
# → http://localhost:3000
```

---

## The Four Vulnerabilities

| # | Vulnerability | Location in `app.js` |
|---|---------------|----------------------|
| 1 | **No Input Validation** | `POST /register`, `POST /login` |
| 2 | **Plain-text Passwords** | `users` array + `/register` route |
| 3 | **No Auth / IDOR** | `GET /profile?id=N`, `GET /users` |
| 4 | **Missing Security Headers** | Entire app (no Helmet) |

---

## How to Exploit Each One

### ❶ No Input Validation
Register with `email: "notanemail"` or a blank password — the server happily accepts it.

### ❷ Plain-text Passwords
After registering, call `GET /users` — every password is visible in the response JSON.

### ❸ IDOR (Insecure Direct Object Reference)
Without logging in, visit `/profile?id=1`, `/profile?id=2` — you get each user's full record including their password.

### ❹ Missing Security Headers
Open DevTools → Network → click any response. Notice the absence of:
`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, etc.

---

## How to Fix Each One

### Fix ❶ — Add Input Validation
```bash
npm install express-validator
```
```js
const { body, validationResult } = require('express-validator');

app.post('/register',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    // ... rest of handler
  }
);
```

### Fix ❷ — Hash Passwords with bcrypt
```bash
npm install bcrypt
```
```js
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// On register:
const hash = await bcrypt.hash(password, SALT_ROUNDS);
users.push({ ...newUser, password: hash });

// On login:
const match = await bcrypt.compare(password, user.password);
if (!match) return res.status(401).json({ error: 'Invalid credentials.' });
```

### Fix ❸ — Protect Routes with JWT
```bash
npm install jsonwebtoken
```
```js
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';

// Issue token on login:
const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '1h' });
res.json({ token });

// Auth middleware:
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token.' });
  try {
    req.user = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token.' });
  }
}

// Protect the route:
app.get('/profile', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id); // use token, not query param
  res.json({ id: user.id, email: user.email, name: user.name }); // never return password
});
```

### Fix ❹ — Add Security Headers with Helmet
```bash
npm install helmet
```
```js
const helmet = require('helmet');
app.use(helmet()); // adds ~15 security headers automatically
```

---

## Dependency Cheatsheet

| Purpose | Package |
|---------|---------|
| Input validation | `express-validator` |
| Password hashing | `bcrypt` |
| Auth tokens | `jsonwebtoken` |
| Security headers | `helmet` |
=======
# Initial-vulnerable-lab
>>>>>>> 29e7db39597ea559523b5ff580a2dfbdb04341ba
