'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

let currentUser = null;
let deleteTargetId = null;

async function api(path, options = {}) {
  const opts = {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  };
  if (opts.body && typeof opts.body === 'object') {
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, opts);
  let data;
  try {
    data = await res.json();
  } catch {
    data = { ok: false, error: '服务器响应异常' };
  }
  if (!res.ok && !data.error) {
    data.error = `请求失败 (${res.status})`;
  }
  return data;
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  $('#toast-container').appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.3s';
    setTimeout(() => el.remove(), 300);
  }, 3200);
}

function showView(name) {
  $('#view-auth').classList.toggle('hidden', name !== 'auth');
  $('#view-app').classList.toggle('hidden', name !== 'app');
}

/* —— Tabs —— */
$$('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    $$('.tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    const name = tab.dataset.tab;
    $('#form-login').classList.toggle('hidden', name !== 'login');
    $('#form-register').classList.toggle('hidden', name !== 'register');
    $('#form-recover').classList.toggle('hidden', name !== 'recover');
  });
});

/* —— Demo panel —— */
$('#demo-toggle').addEventListener('click', () => {
  const body = $('#demo-body');
  const btn = $('#demo-toggle');
  if (body.classList.contains('hidden')) {
    body.classList.remove('hidden');
    btn.textContent = '−';
  } else {
    body.classList.add('hidden');
    btn.textContent = '+';
  }
});

function renderDemoOtps(otps) {
  const list = $('#demo-otp-list');
  if (!otps || !otps.length) {
    list.innerHTML = '<div class="empty-mini">暂无验证码</div>';
    return;
  }
  list.innerHTML = otps
    .map(
      (o) => `<div class="demo-otp-item">
      <span>${escapeHtml(o.message || '')}</span>
      ${o.otp ? `<strong>${escapeHtml(o.otp)}</strong>` : ''}
    </div>`
    )
    .join('');
}

async function refreshDemoOtps() {
  try {
    const data = await api('/api/demo/otps');
    if (data.ok) renderDemoOtps(data.otps);
  } catch {
    /* ignore */
  }
}

setInterval(refreshDemoOtps, 3000);

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* —— Auth —— */
$('#form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = await api('/api/auth/login', {
    method: 'POST',
    body: {
      username: fd.get('username'),
      masterPassword: fd.get('masterPassword'),
    },
  });
  if (!data.ok) return toast(data.error || '登录失败', 'error');
  currentUser = data.user;
  toast('登录成功', 'success');
  enterApp();
});

$('#form-register').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = await api('/api/auth/register', {
    method: 'POST',
    body: {
      username: fd.get('username'),
      masterPassword: fd.get('masterPassword'),
      email: fd.get('email'),
      phone: fd.get('phone'),
    },
  });
  if (!data.ok) return toast(data.error || '注册失败', 'error');
  currentUser = data.user;
  toast('注册成功，已自动登录', 'success');
  enterApp();
});

/* 未登录找回 */
$('#form-recover').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = await api('/api/recovery/request-guest', {
    method: 'POST',
    body: {
      username: fd.get('username'),
      masterPassword: fd.get('masterPassword'),
      title: fd.get('title'),
      channel: fd.get('channel'),
    },
  });
  if (!data.ok) return toast(data.error || '发送失败', 'error');
  e.target.querySelector('[name=otpId]').value = data.otpId;
  $('#recover-otp-step').classList.remove('hidden');
  $('#recover-result').classList.add('hidden');
  toast(`验证码已发送至 ${data.maskedDest}`, 'success');
  if (data.demoOtp) {
    toast(`演示 OTP：${data.demoOtp}`, 'info');
    refreshDemoOtps();
  }
});

$('#btn-verify-guest').addEventListener('click', async () => {
  const form = $('#form-recover');
  const otpId = form.querySelector('[name=otpId]').value;
  const code = form.querySelector('[name=otpCode]').value;
  const data = await api('/api/recovery/verify', {
    method: 'POST',
    body: { otpId: Number(otpId), code },
  });
  if (!data.ok) return toast(data.error || '验证失败', 'error');
  const r = data.revealed;
  const box = $('#recover-result');
  box.classList.remove('hidden');
  box.innerHTML = `
    <div><strong>标题：</strong>${escapeHtml(r.title)}</div>
    ${r.username ? `<div><strong>用户名：</strong>${escapeHtml(r.username)}</div>` : ''}
    <div><strong>密码：</strong><code>${escapeHtml(r.password)}</code></div>
  `;
  toast('密码已揭示', 'success');
});

$('#btn-logout').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  currentUser = null;
  toast('已退出', 'info');
  showView('auth');
});

function enterApp() {
  showView('app');
  $('#user-label').textContent = `你好，${currentUser.username}`;
  loadEntries();
}

/* —— Vault —— */
async function loadEntries() {
  const data = await api('/api/vault');
  if (!data.ok) {
    if (data.error === '请先登录') {
      showView('auth');
      return;
    }
    return toast(data.error || '加载失败', 'error');
  }
  const list = $('#entry-list');
  const empty = $('#empty-state');
  if (!data.entries.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  list.innerHTML = data.entries
    .map(
      (e) => `
    <article class="entry-card" data-id="${e.id}">
      <h3>${escapeHtml(e.title)}</h3>
      <div class="entry-meta">
        ${e.username ? `<div>用户：${escapeHtml(e.username)}</div>` : ''}
        ${e.url ? `<div><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener">打开网址</a></div>` : ''}
        ${e.notes ? `<div>${escapeHtml(e.notes).slice(0, 80)}</div>` : ''}
      </div>
      <div class="entry-actions">
        <button type="button" class="btn btn-primary btn-sm" data-act="view">查看密码</button>
        <button type="button" class="btn btn-ghost btn-sm" data-act="edit">编辑</button>
        <button type="button" class="btn btn-ghost btn-sm" data-act="delete">删除</button>
      </div>
    </article>`
    )
    .join('');
}

$('#entry-list').addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-act]');
  if (!btn) return;
  const card = btn.closest('.entry-card');
  const id = Number(card.dataset.id);
  const act = btn.dataset.act;

  if (act === 'view') {
    const data = await api(`/api/vault/${id}`);
    if (!data.ok) return toast(data.error || '解密失败', 'error');
    const e = data.entry;
    $('#view-title').textContent = e.title;
    $('#view-username').textContent = e.username || '—';
    $('#view-url').innerHTML = e.url
      ? `<a href="${escapeHtml(e.url)}" target="_blank" rel="noopener">${escapeHtml(e.url)}</a>`
      : '—';
    $('#view-password').textContent = e.password;
    $('#view-notes').textContent = e.notes || '—';
    $('#dialog-view').showModal();
  }

  if (act === 'edit') {
    const data = await api(`/api/vault/${id}`);
    if (!data.ok) return toast(data.error || '加载失败', 'error');
    openEntryDialog(data.entry);
  }

  if (act === 'delete') {
    deleteTargetId = id;
    $('#confirm-text').textContent = `确定删除「${card.querySelector('h3').textContent}」吗？此操作不可恢复。`;
    $('#dialog-confirm').showModal();
  }
});

$('#btn-copy-pw').addEventListener('click', async () => {
  const text = $('#view-password').textContent;
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制到剪贴板', 'success');
  } catch {
    toast('复制失败，请手动选择', 'error');
  }
});

$('#btn-close-view').addEventListener('click', () => $('#dialog-view').close());

$('#btn-confirm-cancel').addEventListener('click', () => {
  deleteTargetId = null;
  $('#dialog-confirm').close();
});

$('#btn-confirm-ok').addEventListener('click', async () => {
  if (!deleteTargetId) return;
  const data = await api(`/api/vault/${deleteTargetId}`, { method: 'DELETE' });
  $('#dialog-confirm').close();
  if (!data.ok) return toast(data.error || '删除失败', 'error');
  toast('已删除', 'success');
  deleteTargetId = null;
  loadEntries();
});

/* Entry dialog */
const entryDialog = $('#dialog-entry');
const formEntry = $('#form-entry');

$('#btn-new-entry').addEventListener('click', () => openEntryDialog(null));

$('#btn-cancel-entry').addEventListener('click', () => entryDialog.close());

$('#btn-toggle-pw').addEventListener('click', () => {
  const input = formEntry.querySelector('[name=password]');
  const btn = $('#btn-toggle-pw');
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '隐藏';
  } else {
    input.type = 'password';
    btn.textContent = '显示';
  }
});

function openEntryDialog(entry) {
  formEntry.reset();
  formEntry.querySelector('[name=password]').type = 'password';
  $('#btn-toggle-pw').textContent = '显示';
  if (entry) {
    $('#entry-dialog-title').textContent = '编辑条目';
    formEntry.querySelector('[name=id]').value = entry.id;
    formEntry.querySelector('[name=title]').value = entry.title || '';
    formEntry.querySelector('[name=password]').value = '';
    formEntry.querySelector('[name=username]').value = entry.username || '';
    formEntry.querySelector('[name=url]').value = entry.url || '';
    formEntry.querySelector('[name=notes]').value = entry.notes || '';
    $('#pw-hint').textContent = '编辑时留空表示不修改密码';
    formEntry.querySelector('[name=password]').required = false;
  } else {
    $('#entry-dialog-title').textContent = '新建条目';
    formEntry.querySelector('[name=id]').value = '';
    $('#pw-hint').textContent = '新建必填；密码将加密后入库';
    formEntry.querySelector('[name=password]').required = true;
  }
  entryDialog.showModal();
}

formEntry.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(formEntry);
  const id = fd.get('id');
  const payload = {
    title: fd.get('title'),
    username: fd.get('username') || null,
    url: fd.get('url') || null,
    notes: fd.get('notes') || null,
  };
  const pw = fd.get('password');
  if (pw) payload.password = pw;

  if (!id && !pw) {
    toast('请填写密码', 'error');
    return;
  }

  let data;
  if (id) {
    data = await api(`/api/vault/${id}`, { method: 'PUT', body: payload });
  } else {
    data = await api('/api/vault', { method: 'POST', body: payload });
  }

  if (!data.ok) return toast(data.error || '保存失败', 'error');
  entryDialog.close();
  toast('已保存', 'success');
  loadEntries();
});

/* In-app recovery */
function maskContact(dest, channel) {
  if (!dest) return '未绑定';
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

function showRecoveryError(msg) {
  const el = $('#in-recovery-error');
  if (!msg) {
    el.classList.add('hidden');
    el.textContent = '';
    return;
  }
  el.textContent = msg;
  el.classList.remove('hidden');
}

function resetRecoveryModalUi() {
  $('#in-otp-step').classList.add('hidden');
  $('#in-recover-result').classList.add('hidden');
  $('#in-demo-otp').classList.add('hidden');
  $('#in-demo-otp').textContent = '';
  $('#in-otp-dest').textContent = '';
  $('#btn-recovery-send').classList.remove('hidden');
  $('#btn-recovery-verify').classList.add('hidden');
  showRecoveryError('');
}

async function populateRecoveryModal() {
  resetRecoveryModalUi();
  const form = $('#form-recovery-in');
  form.reset();

  // Refresh user if needed
  if (!currentUser) {
    const me = await api('/api/auth/me');
    if (me.ok && me.authenticated) currentUser = me.user;
  }

  const email = currentUser && currentUser.email;
  const phone = currentUser && currentUser.phone;
  $('#recovery-masked-email').textContent = email ? maskContact(email, 'email') : '未绑定';
  $('#recovery-masked-phone').textContent = phone ? maskContact(phone, 'phone') : '未绑定';

  const channelSel = $('#recovery-channel');
  const emailOpt = channelSel.querySelector('option[value=email]');
  const phoneOpt = channelSel.querySelector('option[value=phone]');
  emailOpt.disabled = !email;
  phoneOpt.disabled = !phone;
  if (phone && !email) channelSel.value = 'phone';
  else if (email && !phone) channelSel.value = 'email';
  else if (email) channelSel.value = 'email';
  else channelSel.value = 'email';

  const titleSel = $('#recovery-title-select');
  titleSel.innerHTML = '<option value="">请选择条目</option>';
  const vault = await api('/api/vault');
  if (!vault.ok) {
    showRecoveryError(vault.error || '加载保险库失败');
    return;
  }
  if (!vault.entries.length) {
    showRecoveryError('保险库为空，请先添加条目');
    return;
  }
  for (const entry of vault.entries) {
    const opt = document.createElement('option');
    opt.value = entry.title;
    opt.textContent = entry.title;
    titleSel.appendChild(opt);
  }
}

$('#btn-recovery-modal').addEventListener('click', async () => {
  await populateRecoveryModal();
  $('#dialog-recovery').showModal();
});

$('#btn-recovery-close').addEventListener('click', () => $('#dialog-recovery').close());

$('#form-recovery-in').addEventListener('submit', async (e) => {
  e.preventDefault();
  showRecoveryError('');
  const fd = new FormData(e.target);
  const title = String(fd.get('title') || '').trim();
  const channel = fd.get('channel');
  const confirmContact = String(fd.get('confirmContact') || '').trim();

  if (!title) {
    showRecoveryError('请选择条目标题');
    return;
  }

  if (confirmContact && currentUser) {
    const bound = channel === 'email' ? currentUser.email : currentUser.phone;
    if (!bound || confirmContact !== String(bound).trim()) {
      showRecoveryError(
        channel === 'email' ? '确认邮箱与绑定邮箱不一致' : '确认手机号与绑定手机号不一致'
      );
      return;
    }
  }

  const data = await api('/api/recovery/request', {
    method: 'POST',
    body: {
      title,
      channel,
      confirmContact: confirmContact || undefined,
    },
  });
  if (!data.ok) {
    let msg = data.error || '发送失败';
    if (data.availableTitles && data.availableTitles.length) {
      msg += `（可选：${data.availableTitles.join('、')}）`;
    }
    showRecoveryError(msg);
    toast(msg, 'error');
    return;
  }

  e.target.querySelector('[name=otpId]').value = data.otpId;
  $('#in-otp-step').classList.remove('hidden');
  $('#in-recover-result').classList.add('hidden');
  $('#btn-recovery-verify').classList.remove('hidden');
  $('#btn-recovery-send').classList.add('hidden');
  $('#in-otp-dest').textContent = `验证码已发送至 ${data.maskedDest}`;

  const otpInput = e.target.querySelector('[name=otpCode]');
  otpInput.value = '';
  const demoBox = $('#in-demo-otp');
  if (data.demoOtp) {
    demoBox.textContent = `演示验证码：${data.demoOtp}`;
    demoBox.classList.remove('hidden');
    otpInput.value = data.demoOtp; // demo mode prefill
    refreshDemoOtps();
  } else {
    demoBox.classList.add('hidden');
    demoBox.textContent = '';
  }
  otpInput.focus();
  toast(`验证码已发送至 ${data.maskedDest}`, 'success');
});

$('#btn-recovery-verify').addEventListener('click', async () => {
  showRecoveryError('');
  const form = $('#form-recovery-in');
  const otpId = form.querySelector('[name=otpId]').value;
  const code = form.querySelector('[name=otpCode]').value;
  const data = await api('/api/recovery/verify', {
    method: 'POST',
    body: { otpId: Number(otpId), code },
  });
  if (!data.ok) {
    showRecoveryError(data.error || '验证失败');
    toast(data.error || '验证失败', 'error');
    return;
  }
  const r = data.revealed;
  const box = $('#in-recover-result');
  box.classList.remove('hidden');
  box.innerHTML = `
    <div><strong>标题：</strong>${escapeHtml(r.title)}</div>
    ${r.username ? `<div><strong>用户名：</strong>${escapeHtml(r.username)}</div>` : ''}
    <div><strong>密码：</strong><code>${escapeHtml(r.password)}</code></div>
  `;
  toast('密码已揭示', 'success');
});

/* Boot */
async function boot() {
  refreshDemoOtps();
  const data = await api('/api/auth/me');
  if (data.ok && data.authenticated) {
    currentUser = data.user;
    enterApp();
  } else {
    showView('auth');
  }
}

boot();
