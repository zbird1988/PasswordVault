'use strict';

const crypto = require('crypto');

const OTP_TTL_MS = 5 * 60 * 1000; // 5 分钟

function generateOtp() {
  // 6 位数字，密码学安全随机
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, '0');
}

function expiryTimestamp() {
  return Date.now() + OTP_TTL_MS;
}

function isExpired(expiresAt) {
  return Date.now() > Number(expiresAt);
}

module.exports = {
  generateOtp,
  expiryTimestamp,
  isExpired,
  OTP_TTL_MS,
};
