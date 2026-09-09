# 密盾 · 在线密码管理器

基于 Node.js + Express 的演示级密码管理器，界面为简体中文。密码条目使用 **AES-256-GCM** 加密后入库，服务端**永不存储**明文保险库密码。

## 快速启动

```bash
cd /workspace/password-manager
npm install
npm start
```

浏览器访问：<http://127.0.0.1:3847>

服务监听 `0.0.0.0:3847`。

## 功能概览

1. **注册 / 登录**：用户名、主密码、邮箱与手机（至少填一项）。主密码用 bcrypt 哈希存储。
2. **保险库 CRUD**：标题 + 密码（可选用户名 / 网址 / 备注）；列表、查看、编辑、删除（带确认）。
3. **强加密**：见下文「加密说明」。
4. **按标题找回**：选择邮箱或手机发送 6 位 OTP（5 分钟有效）。**演示模式**下 OTP 出现在左下角「演示模式」面板，并在 API 字段 `demoOtp` 与服务器控制台中输出。
5. **现代中文 UI**：卡片布局、阴影、Toast、空状态、响应式。

## 加密说明（重要）

### 认证

- 主密码 → **bcrypt**（cost 12）→ 仅存 `password_hash`。
- 会话：`express-session`，**httpOnly** Cookie（`pm.sid`），SameSite=Lax。

### 数据加密密钥（DEK）

- 每个用户注册时生成随机 **kdf_salt**（16 字节，hex 存储）。
- 登录成功后，服务端用主密码派生 DEK：
  - 优先 **scrypt**（N=16384, r=8, p=1, keyLen=32）
  - 失败则回退 **PBKDF2-SHA256**（120,000 次迭代）
- DEK **只保存在会话内存**（`req.session.dek`，base64），**不写数据库**。
- 主密码本身不存明文，也不再会话中保留明文；登出后 DEK 随会话销毁。

### 条目密文

- 算法：**AES-256-GCM**
- 每条记录存储：`ciphertext` + `iv`（12 字节）+ `auth_tag`
- 列表接口不返回明文；查看 / 找回时才用会话 DEK 解密。

### 找回流程

1. 用户提供条目标题 + 通道（email/phone）。
2. 服务端生成 6 位 OTP，5 分钟过期；演示模式返回 `demoOtp`。
3. OTP 校验通过后，用会话中的 DEK（或找回时临时派生的 DEK）解密并**一次性**返回明文。

> 本项目为本地演示原型，未接真实短信/邮件网关。生产环境请使用 TLS、固定 `SESSION_SECRET`、真实 OTP 通道，并考虑客户端加密等强化方案。

## 技术栈

| 组件 | 选型 |
|------|------|
| 运行时 | Node.js |
| Web | Express |
| 会话 | express-session（httpOnly cookie） |
| 数据库 | sql.js（纯 JS SQLite，免原生编译） |
| 密码哈希 | bcryptjs |
| 加密 | Node.js `crypto`（AES-256-GCM / scrypt） |
| 前端 | 静态 HTML + CSS + Vanilla JS（简体中文） |

数据文件：`data/vault.db`（sql.js 导出的 SQLite 二进制）。

## API 摘要

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/register` | 注册 |
| POST | `/api/auth/login` | 登录 |
| POST | `/api/auth/logout` | 退出 |
| GET | `/api/auth/me` | 当前用户 |
| GET/POST | `/api/vault` | 列表 / 新建 |
| GET/PUT/DELETE | `/api/vault/:id` | 查看(解密) / 更新 / 删除 |
| POST | `/api/recovery/request` | 登录态发 OTP |
| POST | `/api/recovery/request-guest` | 未登录发 OTP（需主密码） |
| POST | `/api/recovery/verify` | 校验 OTP 并揭示 |
| GET | `/api/demo/otps` | 演示模式最近 OTP |

## 环境变量（可选）

- `SESSION_SECRET`：会话签名密钥。未设置时每次启动随机生成（重启后旧会话失效）。

## 许可

演示用途，按需修改。
