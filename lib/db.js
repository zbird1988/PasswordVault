'use strict';

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const DB_PATH = path.join(__dirname, '..', 'data', 'vault.db');

let SQL = null;
let db = null;
let dirty = false;
let lastId = null;

function persist() {
  if (!db || !dirty) return;
  const data = db.export();
  // export() 会重置 last_insert_rowid，故在导出前已缓存 lastId
  const buffer = Buffer.from(data);
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, buffer);
  dirty = false;
}

function readLastInsertId() {
  const res = db.exec('SELECT last_insert_rowid() AS id');
  if (res && res[0] && res[0].values && res[0].values[0]) {
    return res[0].values[0][0];
  }
  return null;
}

async function init() {
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      kdf_salt TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS vault_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      username TEXT,
      url TEXT,
      notes TEXT,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      entry_id INTEGER NOT NULL,
      channel TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  dirty = true;
  persist();
  setInterval(persist, 5000);
  process.on('exit', persist);
  return db;
}

function run(sql, params) {
  if (params && params.length) {
    db.run(sql, params);
  } else {
    db.run(sql);
  }
  // 必须在 export/persist 之前读取 rowid
  lastId = readLastInsertId();
  dirty = true;
  persist();
}

function get(sql, params) {
  const stmt = db.prepare(sql);
  try {
    if (params && params.length) {
      stmt.bind(params);
    }
    if (stmt.step()) {
      return stmt.getAsObject();
    }
    return undefined;
  } finally {
    stmt.free();
  }
}

function all(sql, params) {
  const stmt = db.prepare(sql);
  const rows = [];
  try {
    if (params && params.length) {
      stmt.bind(params);
    }
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    return rows;
  } finally {
    stmt.free();
  }
}

function lastInsertId() {
  return lastId;
}

module.exports = {
  init,
  persist,
  run,
  get,
  all,
  lastInsertId,
  DB_PATH,
};
