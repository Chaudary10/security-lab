// ============================================================
//  Security Lab — main.js  (Secured Version)
//  Frontend fetch logic for Register, Login, and Auth panel
// ============================================================

// In-memory token store — persists for the session only.
// Never written to localStorage or sessionStorage.
let authToken = null;

// ── Utility ───────────────────────────────────────────────
// Renders a JSON response into the target element.
// isOk drives the green/red border colour via CSS classes.
function showResp(id, data, isOk) {
  const el = document.getElementById(id);
  el.textContent = JSON.stringify(data, null, 2);
  el.className = 'response ' + (isOk ? 'ok' : 'error');
}

// Shows the JWT bar beneath the header after a successful login.
function showTokenBar(token) {
  const bar = document.getElementById('token-bar');
  document.getElementById('token-display').textContent = token.slice(0, 40) + '…';
  bar.classList.add('visible');
}

// ── Register ──────────────────────────────────────────────
// POST /register — server validates email format, password
// length, and name before hashing and storing the new user.
async function register() {
  const body = {
    name:     document.getElementById('reg-name').value,
    email:    document.getElementById('reg-email').value,
    password: document.getElementById('reg-password').value,
  };
  try {
    const res  = await fetch('/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    showResp('reg-resp', data, res.ok);
  } catch (e) {
    showResp('reg-resp', { error: e.message }, false);
  }
}

// ── Login ─────────────────────────────────────────────────
// POST /login — server validates credentials with bcrypt,
// then returns a signed JWT valid for 1 hour.
// The token is stored in the module-level variable above.
async function login() {
  const body = {
    email:    document.getElementById('log-email').value,
    password: document.getElementById('log-password').value,
  };
  try {
    const res  = await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();

    if (res.ok && data.token) {
      authToken = data.token;   // store token in memory
      showTokenBar(authToken);  // display truncated token in the UI bar
    }

    showResp('log-resp', data, res.ok);
  } catch (e) {
    showResp('log-resp', { error: e.message }, false);
  }
}

// ── Fetch Profile ─────────────────────────────────────────
// GET /profile — protected route.
// ID comes from the verified JWT server-side (req.user.id),
// not from a query param, so IDOR is not possible.
// Requires a valid Bearer token in the Authorization header.
async function fetchProfile() {
  if (!authToken) {
    showResp('auth-resp', { error: 'Not logged in. Please login first to get a token.' }, false);
    return;
  }
  try {
    const res  = await fetch('/profile', {
      headers: { 'Authorization': 'Bearer ' + authToken },
    });
    const data = await res.json();
    showResp('auth-resp', data, res.ok);
  } catch (e) {
    showResp('auth-resp', { error: e.message }, false);
  }
}

// ── Fetch All Users ───────────────────────────────────────
// GET /users — protected route.
// Returns all users with password hashes stripped server-side.
// Requires a valid Bearer token in the Authorization header.
async function fetchUsers() {
  if (!authToken) {
    showResp('auth-resp', { error: 'Not logged in. Please login first to get a token.' }, false);
    return;
  }
  try {
    const res  = await fetch('/users', {
      headers: { 'Authorization': 'Bearer ' + authToken },
    });
    const data = await res.json();
    showResp('auth-resp', data, res.ok);
  } catch (e) {
    showResp('auth-resp', { error: e.message }, false);
  }
}