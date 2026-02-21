'use strict';
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const SQLiteStore  = require('connect-sqlite3')(session);
const bcrypt       = require('bcrypt');
const helmet       = require('helmet');
const { spawn }    = require('child_process');
const { randomUUID } = require('crypto');   // cryptographically secure IDs
const fs           = require('fs');
const path         = require('path');
const os           = require('os');
const { authDb, dataDb } = require('./db');
const {
  authLimiter, registerLimiter, runLimiter, apiLimiter,
  validateString, validateId, errorHandler, LIMITS,
} = require('./security');

const app     = express();
app.set('trust proxy', 1);
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Session secret: hard-fail in production without it ───────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET && IS_PROD) {
  console.error('\nFATAL: SESSION_SECRET environment variable must be set in production.');
  console.error('  Generate: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
  process.exit(1);
}

// ── Security headers via helmet ───────────────────────────────────────────────
// Sets X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security,
// X-XSS-Protection, Referrer-Policy, and more automatically.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Monaco editor requires inline scripts and styles
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
      baseUri:    ["'self'"],
      formAction:  ["'self'"],
      upgradeInsecureRequests: null,   // MUST be null on plain HTTP — otherwise browser upgrades all page navigations to HTTPS
    },
  },
  // Must be off — Monaco loads workers as blob: URLs
  strictTransportSecurity: IS_PROD ? { maxAge: 31536000 } : false,
  crossOriginEmbedderPolicy: false,
}));

// ── Core middleware ───────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));  // Tightened from original 4 MB
app.use(express.static(path.join(__dirname, 'public')));

// ── Session ───────────────────────────────────────────────────────────────────
app.use(session({
  name:  'cls.sid',   // Non-default name prevents server fingerprinting
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   1000 * 60 * 60 * 8,  // 8 hours
    httpOnly: true,
    sameSite: 'lax',
    secure:   true,             // HTTPS-only cookies in production
  },
}));

// ── Rate limiting on all API / auth / run routes ──────────────────────────────
app.use('/api',  apiLimiter);
app.use('/auth', apiLimiter);
app.use('/run',  apiLimiter);

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function requireTeacher(req, res, next) {
  if (!req.session.userId)            return res.status(401).json({ error: 'Not logged in' });
  if (req.session.role !== 'teacher') return res.status(403).json({ error: 'Teacher access only' });
  next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────

app.get('/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({
    loggedIn:    true,
    userId:      req.session.userId,
    username:    req.session.username,
    role:        req.session.role,
    first_name:  req.session.first_name  || '',
    last_name:   req.session.last_name   || '',
    class_color: req.session.class_color || 'blue',
  });
});

app.post('/auth/login', authLimiter, async (req, res, next) => {
  try {
    const username = validateString(req.body.username, 'username', { maxLen: LIMITS.username });
    const password = validateString(req.body.password, 'password', { maxLen: LIMITS.password });

    const user = authDb.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());

    // Always run bcrypt even when user is not found.
    // Without this, a timing difference between "no user" (instant) and
    // "wrong password" (~100 ms bcrypt) lets attackers enumerate valid emails.
    const hashToCheck = user?.password_hash ?? '$2b$10$invalidhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const match = await bcrypt.compare(password, hashToCheck);

    if (!user || !match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Regenerate session ID on login to prevent session fixation attacks.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId      = user.id;
      req.session.username    = user.username;
      req.session.role        = user.role;
      req.session.first_name  = user.first_name  || '';
      req.session.last_name   = user.last_name   || '';
      req.session.class_color = user.class_color || 'blue';
      res.json({ success: true, username: user.username, role: user.role });
    });
  } catch (err) { next(err); }
});

app.post('/auth/register', registerLimiter, async (req, res, next) => {
  try {
    // Optional registration-code gate.
    // Set REGISTRATION_CODE in .env to restrict who can sign up.
    // If enabled, add a "class_code" input to the Login.html register form.
    const REG_CODE = process.env.REGISTRATION_CODE;
    if (REG_CODE) {
      const provided = validateString(req.body.class_code || '', 'class_code', { required: false, maxLen: LIMITS.class_code });
      if (provided !== REG_CODE) {
        return res.status(403).json({ error: 'Invalid class registration code' });
      }
    }

    const username   = validateString(req.body.username,   'Email',      { maxLen: LIMITS.username });
    const password   = validateString(req.body.password,   'Password',   { maxLen: LIMITS.password });
    const first_name = validateString(req.body.first_name, 'First name', { maxLen: LIMITS.first_name });
    const last_name  = validateString(req.body.last_name,  'Last name',  { maxLen: LIMITS.last_name });

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const clean = username.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    // Only letters, spaces, hyphens, and apostrophes allowed in names
    if (!/^[a-zA-Z\s'\-]{1,64}$/.test(first_name)) {
      return res.status(400).json({ error: 'First name contains invalid characters' });
    }
    if (!/^[a-zA-Z\s'\-]{1,64}$/.test(last_name)) {
      return res.status(400).json({ error: 'Last name contains invalid characters' });
    }

    const exists = authDb.prepare('SELECT id FROM users WHERE username = ?').get(clean);
    if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

    const hash = await bcrypt.hash(password, 10);
    const validColors = ['red', 'green', 'blue', 'yellow', 'purple'];
    const color = validColors.includes(req.body.class_color) ? req.body.class_color : 'blue';

    const result = authDb.prepare(
      'INSERT INTO users (username, password_hash, role, first_name, last_name, class_color) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(clean, hash, 'student', first_name, last_name, color);

    // Regenerate session on register too
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId      = result.lastInsertRowid;
      req.session.username    = clean;
      req.session.role        = 'student';
      req.session.first_name  = first_name;
      req.session.last_name   = last_name;
      req.session.class_color = color;
      res.json({ success: true, username: clean, role: 'student' });
    });
  } catch (err) { next(err); }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.post('/auth/change-password', requireAuth, authLimiter, async (req, res, next) => {
  try {
    const currentPassword = validateString(req.body.currentPassword, 'Current password', { maxLen: LIMITS.password });
    const newPassword     = validateString(req.body.newPassword,     'New password',     { maxLen: LIMITS.password });
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    const user  = authDb.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    authDb.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ── File routes ───────────────────────────────────────────────────────────────

app.get('/api/files', requireAuth, (req, res) => {
  const files = dataDb.prepare(
    'SELECT id, filename, language, updated_at FROM files WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.session.userId);
  res.json(files);
});

app.get('/api/files/:id', requireAuth, (req, res, next) => {
  try {
    const id   = validateId(req.params.id);
    const file = dataDb.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?')
      .get(id, req.session.userId);
    if (!file) return res.status(404).json({ error: 'File not found' });
    res.json(file);
  } catch (err) { next(err); }
});

app.post('/api/files', requireAuth, (req, res, next) => {
  try {
    const rawName  = validateString(req.body.filename,            'filename', { maxLen: LIMITS.filename });
    const language = validateString(req.body.language || 'python','language', { maxLen: LIMITS.language });
    const content  = validateString(req.body.content  || '',      'content',  { required: false, maxLen: LIMITS.content });

    // Strip characters usable for path traversal
    const clean = rawName.replace(/[^a-zA-Z0-9_\-. ]/g, '').trim();
    if (!clean)             return res.status(400).json({ error: 'Invalid filename' });
    if (clean.includes('..') || clean.startsWith('/') || clean.startsWith('\\'))
      return res.status(400).json({ error: 'Invalid filename' });

    const validLangs = ['python', 'html', 'javascript', 'css', 'text'];
    const lang = validLangs.includes(language) ? language : 'python';

    const existing = dataDb.prepare('SELECT id FROM files WHERE user_id = ? AND filename = ?')
      .get(req.session.userId, clean);

    if (existing) {
      dataDb.prepare('UPDATE files SET content=?, language=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
        .run(content, lang, existing.id);
      return res.json({ success: true, id: existing.id, filename: clean, action: 'updated' });
    }

    // Per-user file cap to prevent storage abuse
    const { c: fileCount } = dataDb.prepare('SELECT COUNT(*) AS c FROM files WHERE user_id=?')
      .get(req.session.userId);
    if (fileCount >= 50) {
      return res.status(400).json({ error: 'File limit reached (50 files per student)' });
    }

    const result = dataDb.prepare('INSERT INTO files (user_id, filename, language, content) VALUES (?, ?, ?, ?)')
      .run(req.session.userId, clean, lang, content);
    res.json({ success: true, id: result.lastInsertRowid, filename: clean, action: 'created' });
  } catch (err) { next(err); }
});

app.delete('/api/files/:id', requireAuth, (req, res, next) => {
  try {
    const id     = validateId(req.params.id);
    const result = dataDb.prepare('DELETE FROM files WHERE id = ? AND user_id = ?')
      .run(id, req.session.userId);
    if (result.changes === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ── Assignment routes ─────────────────────────────────────────────────────────

app.get('/api/assignments', requireAuth, (req, res) => {
  const isTeacher   = req.session.role === 'teacher';
  const assignments = isTeacher
    ? dataDb.prepare('SELECT * FROM assignments ORDER BY created_at DESC').all()
    : dataDb.prepare('SELECT * FROM assignments WHERE visible=1 ORDER BY created_at DESC').all();
  res.json(assignments);
});

app.get('/api/assignments/:id', requireAuth, (req, res, next) => {
  try {
    const id = validateId(req.params.id);
    const a  = dataDb.prepare('SELECT * FROM assignments WHERE id = ?').get(id);
    if (!a) return res.status(404).json({ error: 'Assignment not found' });
    if (a.visible === 0 && req.session.role !== 'teacher')
      return res.status(403).json({ error: 'Not available' });
    res.json(a);
  } catch (err) { next(err); }
});

app.post('/api/assignments', requireTeacher, (req, res, next) => {
  try {
    const title          = validateString(req.body.title,              'title',        { maxLen: LIMITS.title });
    const description    = validateString(req.body.description  || '', 'description',  { required: false, maxLen: LIMITS.description });
    const language       = validateString(req.body.language || 'python','language',    { maxLen: LIMITS.language });
    const starter_code   = validateString(req.body.starter_code || '', 'starter_code', { required: false, maxLen: LIMITS.starter_code });
    const visible        = req.body.visible !== false ? 1 : 0;
    const allow_resubmit = req.body.allow_resubmit ? 1 : 0;
    const validLangs     = ['python', 'html', 'javascript', 'css', 'text'];
    const lang           = validLangs.includes(language) ? language : 'python';

    const result = dataDb.prepare(
      'INSERT INTO assignments (title, description, language, starter_code, visible, allow_resubmit) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(title, description, lang, starter_code, visible, allow_resubmit);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) { next(err); }
});

app.put('/api/assignments/:id', requireTeacher, (req, res, next) => {
  try {
    const id             = validateId(req.params.id);
    const title          = validateString(req.body.title,              'title',        { maxLen: LIMITS.title });
    const description    = validateString(req.body.description  || '', 'description',  { required: false, maxLen: LIMITS.description });
    const language       = validateString(req.body.language || 'python','language',    { maxLen: LIMITS.language });
    const starter_code   = validateString(req.body.starter_code || '', 'starter_code', { required: false, maxLen: LIMITS.starter_code });
    const visible        = req.body.visible ? 1 : 0;
    const allow_resubmit = req.body.allow_resubmit ? 1 : 0;
    const validLangs     = ['python', 'html', 'javascript', 'css', 'text'];
    const lang           = validLangs.includes(language) ? language : 'python';
    const a              = dataDb.prepare('SELECT id FROM assignments WHERE id = ?').get(id);
    if (!a) return res.status(404).json({ error: 'Assignment not found' });
    dataDb.prepare('UPDATE assignments SET title=?, description=?, language=?, starter_code=?, visible=?, allow_resubmit=? WHERE id=?')
      .run(title, description, lang, starter_code, visible, allow_resubmit, id);
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.delete('/api/assignments/:id', requireTeacher, (req, res, next) => {
  try {
    const id     = validateId(req.params.id);
    const result = dataDb.prepare('DELETE FROM assignments WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/assignments/:id/toggle', requireTeacher, (req, res, next) => {
  try {
    const id = validateId(req.params.id);
    const a  = dataDb.prepare('SELECT id, visible FROM assignments WHERE id = ?').get(id);
    if (!a) return res.status(404).json({ error: 'Not found' });
    const newVis = a.visible ? 0 : 1;
    dataDb.prepare('UPDATE assignments SET visible=? WHERE id=?').run(newVis, id);
    res.json({ success: true, visible: newVis === 1 });
  } catch (err) { next(err); }
});

// ── Submission routes ─────────────────────────────────────────────────────────

app.post('/api/submissions', requireAuth, (req, res, next) => {
  try {
    const assignment_id = validateId(req.body.assignment_id, 'assignment_id');
    const code     = validateString(req.body.code     || '', 'code',     { required: false, maxLen: LIMITS.code });
    const language = validateString(req.body.language || 'python', 'language', { maxLen: LIMITS.language });
    const note     = validateString(req.body.note     || '', 'note',     { required: false, maxLen: LIMITS.note });

    const assignment = dataDb.prepare('SELECT id, allow_resubmit FROM assignments WHERE id = ?').get(assignment_id);
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    // If resubmissions are not allowed, block students who already submitted
    if (!assignment.allow_resubmit) {
      const existing = dataDb.prepare(
        'SELECT id FROM submissions WHERE user_id = ? AND assignment_id = ?'
      ).get(req.session.userId, assignment_id);
      if (existing) {
        return res.status(409).json({ error: 'You have already submitted this assignment and resubmissions are not allowed.' });
      }
    }

    const result = dataDb.prepare(
      'INSERT INTO submissions (user_id, assignment_id, code, language, note) VALUES (?, ?, ?, ?, ?)'
    ).run(req.session.userId, assignment_id, code, language, note);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) { next(err); }
});

app.get('/api/submissions/mine/:assignment_id', requireAuth, (req, res, next) => {
  try {
    const aid  = validateId(req.params.assignment_id, 'assignment_id');
    const subs = dataDb.prepare(
      'SELECT id, assignment_id, language, note, submitted_at FROM submissions WHERE user_id=? AND assignment_id=? ORDER BY submitted_at DESC'
    ).all(req.session.userId, aid);
    res.json(subs);
  } catch (err) { next(err); }
});

app.get('/api/submissions/assignment/:assignment_id', requireTeacher, (req, res, next) => {
  try {
    const aid  = validateId(req.params.assignment_id, 'assignment_id');
    const subs = dataDb.prepare(
      'SELECT id, user_id, assignment_id, code, language, note, submitted_at FROM submissions WHERE assignment_id=? ORDER BY submitted_at DESC'
    ).all(aid);
    const withNames = subs.map(s => {
      const u = authDb.prepare('SELECT username, first_name, last_name FROM users WHERE id=?').get(s.user_id);
      return { ...s, username: u?.username || `student_${s.user_id}`, first_name: u?.first_name || '', last_name: u?.last_name || '' };
    });
    res.json(withNames);
  } catch (err) { next(err); }
});

app.get('/api/submissions/all', requireTeacher, (req, res) => {
  const subs = dataDb.prepare(
    `SELECT s.id, s.user_id, s.assignment_id, s.code, s.language, s.note, s.submitted_at,
            a.title AS assignment_title
     FROM submissions s JOIN assignments a ON a.id = s.assignment_id
     ORDER BY s.submitted_at DESC LIMIT 300`
  ).all();
  const withNames = subs.map(s => {
    const u = authDb.prepare('SELECT username, first_name, last_name FROM users WHERE id=?').get(s.user_id);
    return { ...s, username: u?.username || `student_${s.user_id}`, first_name: u?.first_name || '', last_name: u?.last_name || '' };
  });
  res.json(withNames);
});

app.get('/api/submissions/:id', requireTeacher, (req, res, next) => {
  try {
    const id  = validateId(req.params.id);
    const sub = dataDb.prepare('SELECT * FROM submissions WHERE id=?').get(id);
    if (!sub) return res.status(404).json({ error: 'Not found' });
    const u = authDb.prepare('SELECT username, first_name, last_name FROM users WHERE id=?').get(sub.user_id);
    res.json({ ...sub, username: u?.username || `student_${sub.user_id}`, first_name: u?.first_name || '', last_name: u?.last_name || '' });
  } catch (err) { next(err); }
});

// ── User management (teacher) ─────────────────────────────────────────────────

app.get('/api/users', requireTeacher, (req, res) => {
  const users = authDb.prepare(
    "SELECT id, username, role, first_name, last_name, class_color, created_at FROM users WHERE role='student' ORDER BY last_name, first_name"
  ).all();
  const enriched = users.map(u => {
    const fc = dataDb.prepare('SELECT COUNT(*) AS c FROM files WHERE user_id=?').get(u.id);
    const sc = dataDb.prepare('SELECT COUNT(*) AS c FROM submissions WHERE user_id=?').get(u.id);
    return { ...u, file_count: fc.c, submission_count: sc.c };
  });
  res.json(enriched);
});

app.delete('/api/users/:id', requireTeacher, (req, res, next) => {
  try {
    const id = validateId(req.params.id);
    if (id === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
    authDb.prepare('DELETE FROM users WHERE id=? AND role=?').run(id, 'student');
    dataDb.prepare('DELETE FROM files WHERE user_id=?').run(id);
    dataDb.prepare('DELETE FROM submissions WHERE user_id=?').run(id);
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/users/:id/reset-password', requireTeacher, async (req, res, next) => {
  try {
    const id          = validateId(req.params.id);
    const newPassword = validateString(req.body.newPassword, 'New password', { maxLen: LIMITS.password });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const hash = await bcrypt.hash(newPassword, 10);
    authDb.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, id);
    res.json({ success: true });
  } catch (err) { next(err); }
});

app.post('/api/users/:id/class-color', requireTeacher, (req, res, next) => {
  try {
    const id          = validateId(req.params.id);
    const validColors = ['red', 'green', 'blue', 'yellow', 'purple'];
    const class_color = req.body.class_color;
    if (!validColors.includes(class_color)) return res.status(400).json({ error: 'Invalid color' });
    authDb.prepare('UPDATE users SET class_color=? WHERE id=?').run(class_color, id);
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ── Assignment progress ───────────────────────────────────────────────────────

app.get('/api/progress/:assignment_id', requireAuth, (req, res, next) => {
  try {
    const aid = validateId(req.params.assignment_id, 'assignment_id');
    const row = dataDb.prepare('SELECT code FROM assignment_progress WHERE user_id=? AND assignment_id=?')
      .get(req.session.userId, aid);
    res.json({ code: row ? row.code : null });
  } catch (err) { next(err); }
});

app.post('/api/progress/:assignment_id', requireAuth, (req, res, next) => {
  try {
    const aid  = validateId(req.params.assignment_id, 'assignment_id');
    const code = validateString(req.body.code || '', 'code', { required: false, maxLen: LIMITS.code });
    dataDb.prepare(`
      INSERT INTO assignment_progress (user_id, assignment_id, code, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id, assignment_id) DO UPDATE
        SET code=excluded.code, updated_at=CURRENT_TIMESTAMP
    `).run(req.session.userId, aid, code);
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ── Root redirect ─────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/Login.html');
  res.redirect(req.session.role === 'teacher' ? '/teacher.html' : '/Ide.html');
});

// ── Python execution (sandboxed) ──────────────────────────────────────────────

const SANDBOX_RUNNER   = path.join(__dirname, 'sandbox_runner.py');
const MAX_OUTPUT_BYTES = 200 * 1024;  // 200 KB total buffered output per run
const MAX_PROCS_PER_USER = 2;         // Max concurrent processes per student

const activeProcs = new Map();   // pid     -> entry
const userProcs   = new Map();   // userId  -> Set<pid>

// POST /run/start — write code to temp file and spawn Python
app.post('/run/start', requireAuth, runLimiter, (req, res, next) => {
  try {
    const code = validateString(req.body.code || '', 'code', { required: false, maxLen: LIMITS.code });
    if (!code.trim()) return res.json({ pid: null, error: 'No code to run' });

    // Enforce per-user concurrent process limit
    const uid     = req.session.userId;
    const myPids  = userProcs.get(uid) || new Set();
    const running = [...myPids].filter(p => activeProcs.has(p));
    if (running.length >= MAX_PROCS_PER_USER) {
      return res.status(429).json({
        error: `You already have ${MAX_PROCS_PER_USER} program(s) running. Stop one first.`,
      });
    }

    // Cryptographically random UUID — never Math.random()
    const pid     = randomUUID();
    const tmpFile = path.join(os.tmpdir(), `ide_${pid}.py`);
    fs.writeFileSync(tmpFile, code, 'utf8');

    const pyCmd = process.platform === 'win32' ? 'python' : 'python3';

    // ── Minimal clean environment ─────────────────────────────────────────────
    // Never pass process.env to student code — it contains SESSION_SECRET and
    // database paths. Only provide what Python needs to run.
    const cleanEnv = {
      PATH:                    process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
      PYTHONIOENCODING:        'utf-8',
      PYTHONUTF8:              '1',
      PYTHONDONTWRITEBYTECODE: '1',
      HOME:                    os.tmpdir(),  // Prevent access to real home directory
      TMPDIR:                  os.tmpdir(),
    };

    // Run through sandbox_runner.py if it exists; bare execution as fallback.
    const useSandbox = fs.existsSync(SANDBOX_RUNNER);
    const args = useSandbox ? ['-u', SANDBOX_RUNNER, tmpFile] : ['-u', tmpFile];

    const proc = spawn(pyCmd, args, {
      env: cleanEnv,
      cwd: os.tmpdir(),   // Restrict working directory to /tmp
    });

    const entry = {
      proc, tmpFile,
      clients:    new Set(),
      done:       false,
      buffer:     [],
      totalBytes: 0,
      _capped:    false,
    };

    function broadcast(type, text) {
      // Cap total buffered output to prevent server memory exhaustion
      entry.totalBytes += Buffer.byteLength(text, 'utf8');
      if (entry.totalBytes > MAX_OUTPUT_BYTES) {
        if (!entry._capped) {
          entry._capped = true;
          const capMsg  = `data: ${JSON.stringify({ type: 'stderr', text: '\n[Output limit reached: 200 KB max]\n' })}\n\n`;
          const doneMsg = `data: ${JSON.stringify({ type: 'done',   text: '1' })}\n\n`;
          entry.buffer.push(capMsg, doneMsg);
          entry.clients.forEach(c => { try { c.write(capMsg); c.write(doneMsg); c.end(); } catch {} });
          entry.done = true;
          try { proc.kill('SIGKILL'); } catch {}
        }
        return;
      }
      const msg = `data: ${JSON.stringify({ type, text })}\n\n`;
      entry.buffer.push(msg);
      entry.clients.forEach(c => { try { c.write(msg); } catch {} });
    }

    const killer = setTimeout(() => {
      broadcast('stderr', '\n[Killed: 30 second time limit]\n');
      broadcast('done', '');
      entry.done = true;
      try { proc.kill('SIGKILL'); } catch {}
      try { fs.unlinkSync(tmpFile); } catch {}
    }, 30000);

    proc.stdout.on('data', d => broadcast('stdout', d.toString('utf8')));
    proc.stderr.on('data', d => broadcast('stderr', d.toString('utf8')));

    proc.on('close', (exitCode) => {
      clearTimeout(killer);
      broadcast('done', String(exitCode ?? 0));
      entry.done = true;
      const s = userProcs.get(uid); if (s) s.delete(pid);
      try { fs.unlinkSync(tmpFile); } catch {}
      setTimeout(() => activeProcs.delete(pid), 10_000);
    });

    proc.on('error', () => {
      clearTimeout(killer);
      // Never expose internal error details to the client in production
      broadcast('stderr', IS_PROD
        ? 'Could not start Python. Please contact your instructor.\n'
        : 'Could not start Python. Make sure Python 3 is installed.\n');
      broadcast('done', '1');
      entry.done = true;
      const s = userProcs.get(uid); if (s) s.delete(pid);
      try { fs.unlinkSync(tmpFile); } catch {}
    });

    activeProcs.set(pid, entry);
    if (!userProcs.has(uid)) userProcs.set(uid, new Set());
    userProcs.get(uid).add(pid);

    res.json({ pid });
  } catch (err) { next(err); }
});

// GET /run/stream/:pid — SSE stream of output
app.get('/run/stream/:pid', requireAuth, (req, res) => {
  // Strict UUID format check before using as a Map key
  const pid = req.params.pid;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pid)) {
    return res.status(400).end();
  }

  const entry = activeProcs.get(pid);
  if (!entry) {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
    res.write(`data: ${JSON.stringify({ type: 'stderr', text: 'Process not found.\n' })}\n\n`);
    res.write(`data: ${JSON.stringify({ type: 'done',   text: '1' })}\n\n`);
    return res.end();
  }

  res.writeHead(200, {
    'Content-Type':      'text/event-stream',
    'Cache-Control':     'no-cache',
    'Connection':        'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  entry.buffer.forEach(msg => res.write(msg));
  if (entry.done) return res.end();

  entry.clients.add(res);
  req.on('close', () => entry.clients.delete(res));
});

// POST /run/stdin/:pid — send a line of input to the running process
app.post('/run/stdin/:pid', requireAuth, (req, res, next) => {
  try {
    const pid = req.params.pid;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pid)) {
      return res.status(400).end();
    }
    const entry = activeProcs.get(pid);
    if (!entry || !entry.proc || !entry.proc.stdin.writable) {
      return res.status(404).json({ error: 'No active process' });
    }
    // Cap stdin line length to prevent memory issues
    const line = String(req.body.line ?? '').slice(0, 10_000);
    entry.proc.stdin.write(line + '\n', 'utf8');
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST /run/kill/:pid — kill the running process
app.post('/run/kill/:pid', requireAuth, (req, res) => {
  const pid = req.params.pid;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pid)) {
    return res.status(400).end();
  }
  const entry = activeProcs.get(pid);
  if (entry && entry.proc) {
    try { entry.proc.kill('SIGKILL'); } catch {}
    entry.done = true;
    entry.clients.forEach(c => {
      try {
        c.write(`data: ${JSON.stringify({ type: 'stderr', text: '\n[Stopped by user]\n' })}\n\n`);
        c.write(`data: ${JSON.stringify({ type: 'done',   text: '1' })}\n\n`);
        c.end();
      } catch {}
    });
  }
  res.json({ ok: true });
});

// ── Global error handler (must be the very last app.use) ──────────────────────
app.use(errorHandler);

// ── Start ──────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Classroom IDE running at http://localhost:${PORT}`);
  console.log(`  Share with students:   http://<your-ip>:${PORT}\n`);
  if (!SESSION_SECRET) {
    console.warn('  ⚠  SESSION_SECRET not set — insecure default in use. Set it in .env before going live!\n');
  }
});
