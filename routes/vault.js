'use strict';

const express = require('express');
const db = require('../lib/db');
const cryptoUtil = require('../lib/crypto');
const { requireAuth } = require('./auth');

const router = express.Router();

function getDek(req) {
  return cryptoUtil.keyFromSession(req.session.dek);
}

/** 列表：不返回明文密码，仅元数据 */
router.get('/', requireAuth, (req, res) => {
  const rows = db.all(
    `SELECT id, title, username, url, notes, created_at, updated_at
     FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC`,
    [req.session.userId]
  );
  res.json({ ok: true, entries: rows });
});

/** 单条解密查看（登录会话内） */
router.get('/:id', requireAuth, (req, res) => {
  const row = db.get(
    'SELECT * FROM vault_entries WHERE id = ? AND user_id = ?',
    [Number(req.params.id), req.session.userId]
  );
  if (!row) {
    return res.status(404).json({ ok: false, error: '条目不存在' });
  }
  try {
    const password = cryptoUtil.decrypt(row.ciphertext, row.iv, row.auth_tag, getDek(req));
    res.json({
      ok: true,
      entry: {
        id: row.id,
        title: row.title,
        username: row.username,
        url: row.url,
        notes: row.notes,
        password,
        created_at: row.created_at,
        updated_at: row.updated_at,
      },
    });
  } catch (e) {
    console.error('decrypt error', e);
    res.status(500).json({ ok: false, error: '解密失败，请重新登录' });
  }
});

router.post('/', requireAuth, (req, res) => {
  const { title, password, username, url, notes } = req.body || {};
  if (!title || !String(title).trim()) {
    return res.status(400).json({ ok: false, error: '标题不能为空' });
  }
  if (password === undefined || password === null || String(password) === '') {
    return res.status(400).json({ ok: false, error: '密码不能为空' });
  }

  try {
    const enc = cryptoUtil.encrypt(String(password), getDek(req));
    db.run(
      `INSERT INTO vault_entries
       (user_id, title, username, url, notes, ciphertext, iv, auth_tag)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.session.userId,
        String(title).trim(),
        username ? String(username).trim() : null,
        url ? String(url).trim() : null,
        notes ? String(notes).trim() : null,
        enc.ciphertext,
        enc.iv,
        enc.authTag,
      ]
    );
    const id = db.lastInsertId();
    res.json({
      ok: true,
      entry: {
        id,
        title: String(title).trim(),
        username: username ? String(username).trim() : null,
        url: url ? String(url).trim() : null,
        notes: notes ? String(notes).trim() : null,
      },
    });
  } catch (e) {
    console.error('create entry error', e);
    res.status(500).json({ ok: false, error: '创建失败' });
  }
});

router.put('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.get(
    'SELECT * FROM vault_entries WHERE id = ? AND user_id = ?',
    [id, req.session.userId]
  );
  if (!existing) {
    return res.status(404).json({ ok: false, error: '条目不存在' });
  }

  const { title, password, username, url, notes } = req.body || {};
  if (!title || !String(title).trim()) {
    return res.status(400).json({ ok: false, error: '标题不能为空' });
  }

  try {
    let ciphertext = existing.ciphertext;
    let iv = existing.iv;
    let authTag = existing.auth_tag;

    if (password !== undefined && password !== null && String(password) !== '') {
      const enc = cryptoUtil.encrypt(String(password), getDek(req));
      ciphertext = enc.ciphertext;
      iv = enc.iv;
      authTag = enc.authTag;
    }

    db.run(
      `UPDATE vault_entries SET
         title = ?, username = ?, url = ?, notes = ?,
         ciphertext = ?, iv = ?, auth_tag = ?,
         updated_at = datetime('now')
       WHERE id = ? AND user_id = ?`,
      [
        String(title).trim(),
        username ? String(username).trim() : null,
        url ? String(url).trim() : null,
        notes ? String(notes).trim() : null,
        ciphertext,
        iv,
        authTag,
        id,
        req.session.userId,
      ]
    );

    res.json({
      ok: true,
      entry: {
        id,
        title: String(title).trim(),
        username: username ? String(username).trim() : null,
        url: url ? String(url).trim() : null,
        notes: notes ? String(notes).trim() : null,
      },
    });
  } catch (e) {
    console.error('update entry error', e);
    res.status(500).json({ ok: false, error: '更新失败' });
  }
});

router.delete('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.get(
    'SELECT id FROM vault_entries WHERE id = ? AND user_id = ?',
    [id, req.session.userId]
  );
  if (!existing) {
    return res.status(404).json({ ok: false, error: '条目不存在' });
  }
  db.run('DELETE FROM vault_entries WHERE id = ? AND user_id = ?', [id, req.session.userId]);
  res.json({ ok: true });
});

module.exports = router;
