'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../lib/db');
const cryptoUtil = require('../lib/crypto');

const router = express.Router();
const BCRYPT_ROUNDS = 12;

function requireAuth(req, res, next) {
  if (!req.session || req.session.userId == null || !req.session.dek) {
    return res.status(401).json({ ok: false, error: '请先登录' });
  }
  next();
}

router.post('/register', async (req, res) => {
  try {
    const { username, masterPassword, email, phone } = req.body || {};

    if (!username || typeof username !== 'string' || username.trim().length < 3) {
      return res.status(400).json({ ok: false, error: '用户名至少 3 个字符' });
    }
    if (!masterPassword || typeof masterPassword !== 'string' || masterPassword.length < 8) {
      return res.status(400).json({ ok: false, error: '主密码至少 8 个字符' });
    }
    const emailTrim = email ? String(email).trim() : '';
    const phoneTrim = phone ? String(phone).trim() : '';
    if (!emailTrim && !phoneTrim) {
      return res.status(400).json({ ok: false, error: '邮箱和手机号至少填写一项' });
    }
    if (emailTrim && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailTrim)) {
      return res.status(400).json({ ok: false, error: '邮箱格式不正确' });
    }
    if (phoneTrim && !/^1\d{10}$|^[\d+\-\s]{6,20}$/.test(phoneTrim)) {
      return res.status(400).json({ ok: false, error: '手机号格式不正确' });
    }

    const existing = db.get('SELECT id FROM users WHERE username = ?', [username.trim()]);
    if (existing) {
      return res.status(409).json({ ok: false, error: '用户名已被占用' });
    }

    const passwordHash = await bcrypt.hash(masterPassword, BCRYPT_ROUNDS);
    const kdfSalt = cryptoUtil.generateSalt();

    db.run(
      `INSERT INTO users (username, password_hash, email, phone, kdf_salt)
       VALUES (?, ?, ?, ?, ?)`,
      [username.trim(), passwordHash, emailTrim || null, phoneTrim || null, kdfSalt]
    );

    const userId = db.lastInsertId();
    const dek = cryptoUtil.deriveKey(masterPassword, kdfSalt);

    req.session.userId = userId;
    req.session.username = username.trim();
    req.session.dek = cryptoUtil.keyToSession(dek);
    req.session.email = emailTrim || null;
    req.session.phone = phoneTrim || null;

    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ ok: false, error: '会话创建失败' });
      }
      res.json({
        ok: true,
        user: {
          id: userId,
          username: username.trim(),
          email: emailTrim || null,
          phone: phoneTrim || null,
        },
      });
    });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ ok: false, error: '注册失败' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, masterPassword } = req.body || {};
    if (!username || !masterPassword) {
      return res.status(400).json({ ok: false, error: '请输入用户名和主密码' });
    }

    const user = db.get('SELECT * FROM users WHERE username = ?', [String(username).trim()]);
    if (!user) {
      return res.status(401).json({ ok: false, error: '用户名或主密码错误' });
    }

    const match = await bcrypt.compare(masterPassword, user.password_hash);
    if (!match) {
      return res.status(401).json({ ok: false, error: '用户名或主密码错误' });
    }

    const dek = cryptoUtil.deriveKey(masterPassword, user.kdf_salt);

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.dek = cryptoUtil.keyToSession(dek);
    req.session.email = user.email || null;
    req.session.phone = user.phone || null;

    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ ok: false, error: '会话创建失败' });
      }
      res.json({
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email || null,
          phone: user.phone || null,
        },
      });
    });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ ok: false, error: '登录失败' });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

router.get('/me', (req, res) => {
  if (!req.session || req.session.userId == null || !req.session.dek) {
    return res.json({ ok: false, authenticated: false });
  }
  res.json({
    ok: true,
    authenticated: true,
    user: {
      id: req.session.userId,
      username: req.session.username,
      email: req.session.email || null,
      phone: req.session.phone || null,
    },
  });
});

module.exports = { router, requireAuth };
