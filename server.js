'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const db = require('./lib/db');
const { router: authRouter } = require('./routes/auth');
const vaultRouter = require('./routes/vault');
const recoveryRouter = require('./routes/recovery');

const PORT = Number(process.env.PORT) || 3847;
const HOST = '0.0.0.0';

async function main() {
  await db.init();
  console.log(`[db] SQLite (sql.js) ready → ${db.DB_PATH}`);

  const app = express();
  app.set('trust proxy', 1);

  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  app.use(
    session({
      name: 'pm.sid',
      secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production' || !!process.env.RENDER,
        maxAge: 8 * 60 * 60 * 1000,
      },
    })
  );

  const recentOtps = [];

  const origLog = console.log;
  console.log = function (...args) {
    origLog.apply(console, args);
    const line = args.map(String).join(' ');
    if (line.includes('[演示模式 OTP]')) {
      const m = line.match(/OTP=(\d{6})/);
      recentOtps.unshift({
        time: new Date().toISOString(),
        message: line,
        otp: m ? m[1] : null,
      });
      if (recentOtps.length > 20) recentOtps.pop();
    }
  };

  app.get('/api/demo/otps', (req, res) => {
    res.json({ ok: true, demo: true, otps: recentOtps.slice(0, 10) });
  });

  app.use('/api/auth', authRouter);
  app.use('/api/vault', vaultRouter);
  app.use('/api/recovery', recoveryRouter);

  app.use(express.static(path.join(__dirname, 'public')));

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ ok: false, error: '接口不存在' });
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return res.status(404).json({ ok: false, error: '未找到' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  app.listen(PORT, HOST, () => {
    console.log(`[server] 密码管理器已启动 http://${HOST}:${PORT}`);
    console.log(`[server] 本机访问 http://127.0.0.1:${PORT}`);
    console.log(
      '[crypto] AES-256-GCM + scrypt(N=16384) DEK 派生；主密码仅 bcrypt 哈希入库，DEK 仅存会话内存'
    );
  });
}

main().catch((err) => {
  console.error('启动失败', err);
  process.exit(1);
});
