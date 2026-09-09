'use strict';

const express = require('express');
const db = require('../lib/db');
const cryptoUtil = require('../lib/crypto');
const otpUtil = require('../lib/otp');
const { requireAuth } = require('./auth');

const router = express.Router();

/**
 * 按标题请求 OTP 恢复
 * body: { title, channel: 'email'|'phone' }
 * 需要登录：用会话中的 DEK 解密；OTP 验证身份后揭示密码
 *
 * 也支持未登录场景：提供 username + masterPassword 临时派生密钥
 * 为简化原型，要求已登录（会话内有 DEK），OTP 用于二次验证后揭示
 */
router.post('/request', requireAuth, (req, res) => {
  try {
    const { title, channel } = req.body || {};
    if (!title || !String(title).trim()) {
      return res.status(400).json({ ok: false, error: '请输入条目标题' });
    }
    if (channel !== 'email' && channel !== 'phone') {
      return res.status(400).json({ ok: false, error: '请选择邮箱或手机号通道' });
    }

    const user = db.get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      return res.status(401).json({ ok: false, error: '用户不存在' });
    }

    const dest = channel === 'email' ? user.email : user.phone;
    if (!dest) {
      return res.status(400).json({
        ok: false,
        error: channel === 'email' ? '账号未绑定邮箱' : '账号未绑定手机号',
      });
    }

    const confirmContact = req.body && req.body.confirmContact != null
      ? String(req.body.confirmContact).trim()
      : '';
    if (confirmContact && confirmContact !== String(dest).trim()) {
      return res.status(400).json({
        ok: false,
        error: channel === 'email' ? '确认邮箱与绑定邮箱不一致' : '确认手机号与绑定手机号不一致',
      });
    }

    const titleTrim = String(title).trim();
    const entry = db.get(
      `SELECT id, title FROM vault_entries
       WHERE user_id = ? AND LOWER(title) = LOWER(?)`,
      [req.session.userId, titleTrim]
    );
    if (!entry) {
      const titles = db
        .all('SELECT title FROM vault_entries WHERE user_id = ? ORDER BY title', [req.session.userId])
        .map((r) => r.title);
      return res.status(404).json({
        ok: false,
        error: `未找到标题为「${titleTrim}」的条目，请从下拉列表选择已有标题`,
        availableTitles: titles,
      });
    }

    const code = otpUtil.generateOtp();
    const expiresAt = otpUtil.expiryTimestamp();

    db.run(
      `INSERT INTO otp_codes (user_id, entry_id, channel, code, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [req.session.userId, entry.id, channel, code, expiresAt]
    );

    const otpId = db.lastInsertId();

    console.log(`[演示模式 OTP] 用户=${user.username} 通道=${channel} 目标=${dest} 标题=${entry.title} OTP=${code}`);

    res.json({
      ok: true,
      otpId,
      channel,
      maskedDest: maskDest(dest, channel),
      entryId: entry.id,
      title: entry.title,
      expiresInSec: Math.floor(otpUtil.OTP_TTL_MS / 1000),
      demoOtp: code, // 演示模式：直接返回 OTP
      message: '验证码已发送（演示模式：请查看 demoOtp 或演示面板）',
    });
  } catch (e) {
    console.error('recovery request error', e);
    res.status(500).json({ ok: false, error: '请求失败' });
  }
});

/**
 * 未登录恢复：用户名 + 主密码 + 标题 + 通道
 * 验证主密码后发 OTP，verify 时再解密
 */
router.post('/request-guest', async (req, res) => {
  try {
    const bcrypt = require('bcryptjs');
    const { username, masterPassword, title, channel } = req.body || {};

    if (!username || !masterPassword || !title) {
      return res.status(400).json({ ok: false, error: '请填写用户名、主密码和标题' });
    }
    if (channel !== 'email' && channel !== 'phone') {
      return res.status(400).json({ ok: false, error: '请选择邮箱或手机号通道' });
    }

    const user = db.get('SELECT * FROM users WHERE username = ?', [String(username).trim()]);
    if (!user) {
      return res.status(401).json({ ok: false, error: '用户名或主密码错误' });
    }

    const match = await bcrypt.compare(masterPassword, user.password_hash);
    if (!match) {
      return res.status(401).json({ ok: false, error: '用户名或主密码错误' });
    }

    const dest = channel === 'email' ? user.email : user.phone;
    if (!dest) {
      return res.status(400).json({
        ok: false,
        error: channel === 'email' ? '账号未绑定邮箱' : '账号未绑定手机号',
      });
    }

    const titleTrim = String(title).trim();
    const entry = db.get(
      `SELECT id, title FROM vault_entries
       WHERE user_id = ? AND LOWER(title) = LOWER(?)`,
      [user.id, titleTrim]
    );
    if (!entry) {
      const titles = db
        .all('SELECT title FROM vault_entries WHERE user_id = ? ORDER BY title', [user.id])
        .map((r) => r.title);
      return res.status(404).json({
        ok: false,
        error: `未找到标题为「${titleTrim}」的条目，请核对标题后重试`,
        availableTitles: titles,
      });
    }

    const code = otpUtil.generateOtp();
    const expiresAt = otpUtil.expiryTimestamp();

    db.run(
      `INSERT INTO otp_codes (user_id, entry_id, channel, code, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [user.id, entry.id, channel, code, expiresAt]
    );

    const otpId = db.lastInsertId();

    // 临时将会话密钥信息放在 OTP 记录旁的内存 map（或 session）
    // 使用一次性 token 存在 session 中
    if (!req.session.pendingRecovery) req.session.pendingRecovery = {};
    const dek = cryptoUtil.deriveKey(masterPassword, user.kdf_salt);
    req.session.pendingRecovery[String(otpId)] = {
      userId: user.id,
      entryId: entry.id,
      dek: cryptoUtil.keyToSession(dek),
    };

    console.log(`[演示模式 OTP] 用户=${user.username} 通道=${channel} 目标=${dest} 标题=${entry.title} OTP=${code}`);

    req.session.save(() => {
      res.json({
        ok: true,
        otpId,
        channel,
        maskedDest: maskDest(dest, channel),
        entryId: entry.id,
        title: entry.title,
        expiresInSec: Math.floor(otpUtil.OTP_TTL_MS / 1000),
        demoOtp: code,
        message: '验证码已发送（演示模式：请查看 demoOtp 或演示面板）',
      });
    });
  } catch (e) {
    console.error('guest recovery error', e);
    res.status(500).json({ ok: false, error: '请求失败' });
  }
});

router.post('/verify', (req, res) => {
  try {
    const { otpId, code } = req.body || {};
    if (!otpId || !code) {
      return res.status(400).json({ ok: false, error: '请提供验证码' });
    }

    const otp = db.get('SELECT * FROM otp_codes WHERE id = ?', [Number(otpId)]);
    if (!otp) {
      return res.status(404).json({ ok: false, error: '验证码不存在' });
    }
    if (otp.used) {
      return res.status(400).json({ ok: false, error: '验证码已使用' });
    }
    if (otpUtil.isExpired(otp.expires_at)) {
      return res.status(400).json({ ok: false, error: '验证码已过期' });
    }
    if (String(code).trim() !== otp.code) {
      return res.status(400).json({ ok: false, error: '验证码错误' });
    }

    // 获取 DEK：优先登录会话，其次 pendingRecovery
    let dekBuf = null;
    if (req.session.userId && req.session.dek && req.session.userId === otp.user_id) {
      dekBuf = cryptoUtil.keyFromSession(req.session.dek);
    } else if (
      req.session.pendingRecovery &&
      req.session.pendingRecovery[String(otpId)]
    ) {
      const pending = req.session.pendingRecovery[String(otpId)];
      dekBuf = cryptoUtil.keyFromSession(pending.dek);
      delete req.session.pendingRecovery[String(otpId)];
    } else {
      return res.status(401).json({
        ok: false,
        error: '会话已失效，请重新登录或重新发起找回',
      });
    }

    const entry = db.get(
      'SELECT * FROM vault_entries WHERE id = ? AND user_id = ?',
      [otp.entry_id, otp.user_id]
    );
    if (!entry) {
      return res.status(404).json({ ok: false, error: '条目不存在' });
    }

    const password = cryptoUtil.decrypt(entry.ciphertext, entry.iv, entry.auth_tag, dekBuf);

    db.run('UPDATE otp_codes SET used = 1 WHERE id = ?', [otp.id]);

    res.json({
      ok: true,
      revealed: {
        title: entry.title,
        username: entry.username,
        url: entry.url,
        password,
        notes: entry.notes,
      },
      message: '验证成功，密码已揭示（仅此一次展示）',
    });
  } catch (e) {
    console.error('verify error', e);
    res.status(500).json({ ok: false, error: '验证失败' });
  }
});

function maskDest(dest, channel) {
  if (channel === 'email') {
    const [name, domain] = String(dest).split('@');
    if (!domain) return '***';
    const n = name.length <= 2 ? name[0] + '*' : name.slice(0, 2) + '***';
    return `${n}@${domain}`;
  }
  const s = String(dest);
  if (s.length < 7) return '***';
  return s.slice(0, 3) + '****' + s.slice(-4);
}

module.exports = router;
