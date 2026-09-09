'use strict';

const crypto = require('crypto');

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32; // AES-256
const IV_LEN = 12;  // GCM recommended
const SALT_LEN = 16;
const PBKDF2_ITERS = 120000; // fallback if scrypt unavailable in some envs

/**
 * 生成随机盐（hex）
 */
function generateSalt() {
  return crypto.randomBytes(SALT_LEN).toString('hex');
}

/**
 * 从主密码 + 盐派生 DEK（Data Encryption Key）
 * 优先使用 scrypt，失败则回退 PBKDF2（≥100k 迭代）
 * @returns {Buffer} 32 字节密钥
 */
function deriveKey(masterPassword, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  try {
    return crypto.scryptSync(masterPassword, salt, KEY_LEN, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: 64 * 1024 * 1024,
    });
  } catch (e) {
    return crypto.pbkdf2Sync(masterPassword, salt, PBKDF2_ITERS, KEY_LEN, 'sha256');
  }
}

/**
 * AES-256-GCM 加密
 * @returns {{ ciphertext: string, iv: string, authTag: string }} hex 编码
 */
function encrypt(plaintext, keyBuffer) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  const enc = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: enc.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

/**
 * AES-256-GCM 解密
 */
function decrypt(ciphertextHex, ivHex, authTagHex, keyBuffer) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    keyBuffer,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  const dec = Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, 'hex')),
    decipher.final(),
  ]);
  return dec.toString('utf8');
}

/**
 * 将 DEK Buffer 转为可放入 session 的 base64 字符串
 */
function keyToSession(keyBuffer) {
  return keyBuffer.toString('base64');
}

function keyFromSession(b64) {
  return Buffer.from(b64, 'base64');
}

module.exports = {
  generateSalt,
  deriveKey,
  encrypt,
  decrypt,
  keyToSession,
  keyFromSession,
  SCRYPT_N,
  PBKDF2_ITERS,
};
