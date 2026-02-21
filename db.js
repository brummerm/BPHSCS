const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

// ── Two separate databases ──────────────────────────────────────────────────
// auth.db  → user accounts only (credentials, roles)
// data.db  → files, assignments, submissions (all class data)
//
// DB_DIR is set to /data on Render (persistent disk) via environment variable.
// Falls back to '.' for local development.

const DB_DIR = process.env.DB_DIR || '.';

const authDb = new Database(path.join(DB_DIR, 'auth.db'));
const dataDb = new Database(path.join(DB_DIR, 'data.db'));

authDb.pragma('journal_mode = WAL');
dataDb.pragma('journal_mode = WAL');
dataDb.pragma('foreign_keys = ON');

// ── Auth Schema ─────────────────────────────────────────────────────────────

authDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'student',
    first_name    TEXT    DEFAULT '',
    last_name     TEXT    DEFAULT '',
    class_color   TEXT    DEFAULT 'blue',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Class Data Schema ───────────────────────────────────────────────────────

dataDb.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    filename   TEXT    NOT NULL,
    language   TEXT    NOT NULL DEFAULT 'python',
    content    TEXT    DEFAULT '',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, filename)
  );

  CREATE TABLE IF NOT EXISTS assignments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    language        TEXT    NOT NULL DEFAULT 'python',
    starter_code    TEXT    DEFAULT '',
    visible         INTEGER DEFAULT 1,
    allow_resubmit  INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    assignment_id INTEGER NOT NULL,
    code          TEXT    DEFAULT '',
    language      TEXT    NOT NULL DEFAULT 'python',
    note          TEXT    DEFAULT '',
    submitted_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS assignment_progress (
    user_id       INTEGER NOT NULL,
    assignment_id INTEGER NOT NULL,
    code          TEXT    DEFAULT '',
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, assignment_id),
    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
  );
`);

// ── Migrate existing DBs: add new columns if missing ───────────────────────
const userCols = authDb.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userCols.includes('first_name'))  authDb.exec("ALTER TABLE users ADD COLUMN first_name TEXT DEFAULT ''");
if (!userCols.includes('last_name'))   authDb.exec("ALTER TABLE users ADD COLUMN last_name  TEXT DEFAULT ''");
if (!userCols.includes('class_color')) authDb.exec("ALTER TABLE users ADD COLUMN class_color TEXT DEFAULT 'blue'");

const assignCols = dataDb.prepare("PRAGMA table_info(assignments)").all().map(c => c.name);
if (!assignCols.includes('allow_resubmit')) dataDb.exec("ALTER TABLE assignments ADD COLUMN allow_resubmit INTEGER DEFAULT 0");

// ── Seed default teacher account ────────────────────────────────────────────

const teacherExists = authDb.prepare('SELECT id FROM users WHERE username = ?').get('teacher');
if (!teacherExists) {
  const hash = bcrypt.hashSync('classroom123', 10);
  authDb.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    .run('teacher', hash, 'teacher');
  console.log('─────────────────────────────────────────');
  console.log('  Teacher account created.');
  console.log('  Username : teacher');
  console.log('  Password : classroom123');
  console.log('  Change this password after first login!');
  console.log('─────────────────────────────────────────');
}

module.exports = { authDb, dataDb };
