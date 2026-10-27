'use strict';
// CBSD Web UI. No framework, no build step. All DOM is created with
// textContent (never innerHTML with data) so server data cannot inject markup.

const state = { user: null, role: null, csrf: null, version: '', terminal: false, timer: null, route: '', cleanup: null };
const ROLE_LEVEL = { viewer: 1, operator: 2, admin: 3 };
const can = (role) => (ROLE_LEVEL[state.role] || 0) >= ROLE_LEVEL[role];

// ---------- DOM helpers ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'style') el.style.cssText = v; // CSSOM: allowed by the strict CSP
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (sel, root = document) => root.querySelector(sel);
const clear = (el) => { while (el.firstChild) el.firstChild.remove(); return el; };
// fill replaces el's children; nested arrays and null/false entries are allowed.
function fill(el, ...kids) {
  clear(el);
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c);
  return el;
}

// ---------- formatting ----------
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n <= 0) return '—';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}
function fmtUptime(s) {
  if (!s) return '—';
  const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d ? d + ' д ' : '') + hh + ' ч ' + m + ' мин';
}
function fmtTime(t) {
  if (!t) return '—';
  const d = new Date(t);
  if (isNaN(d)) return String(t);
  return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' });
}
function fmtDur(a, b) {
  if (!a) return '';
  const ms = (b ? new Date(b) : new Date()) - new Date(a);
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? s + ' с' : Math.floor(s / 60) + ' мин ' + (s % 60) + ' с';
}
const EMU_TITLE = { jail: 'Клетка', bhyve: 'bhyve', xen: 'Xen', qemu: 'QEMU' };

function statusPill(env, busy) {
  if (busy) return h('span', { class: 'pill run' }, 'выполняется');
  if (env.maintenance) return h('span', { class: 'pill warn', title: env.maintenance }, 'обслуживание');
  switch (env.status) {
    case 1: return h('span', { class: 'pill on' }, 'запущен');
    case 2: return h('span', { class: 'pill warn' }, 'slave');
    case 3: return h('span', { class: 'pill warn' }, 'обслуживание');
    default: return h('span', { class: 'pill off' }, 'остановлен');
  }
}
function jobPill(st) {
  const map = { queued: ['off', 'в очереди'], running: ['run', 'выполняется'], done: ['on', 'готово'], failed: ['err', 'ошибка'], canceled: ['warn', 'отменено'] };
  const [c, t] = map[st] || ['off', st];
  return h('span', { class: 'pill ' + c }, t);
}

// ---------- API ----------
async function api(method, url, body) {
  const opt = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  if (method !== 'GET' && state.csrf) opt.headers['X-CSRF-Token'] = state.csrf;
  let r;
  try { r = await fetch(url, opt); } catch (e) { throw new Error('Сервер недоступен'); }
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401 && url !== '/api/login') { state.user = null; renderLogin(); throw Object.assign(new Error('Сессия истекла'), { silent: true }); }
  if (!r.ok) throw Object.assign(new Error(data.error || r.statusText), { field: data.field, status: r.status });
  return data;
}

function toast(msg, kind = 'info') {
  const t = h('div', { class: 'toast ' + kind, role: 'status' }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 7000 : 4000);
}
function fail(e) { if (!e.silent) toast(e.message, 'err'); }

// ---------- modal ----------
function modal(title, body, buttons = [], opts = {}) {
  const root = $('#modal-root');
  const close = () => { overlay.remove(); document.removeEventListener('keydown', onKey); if (opts.onClose) opts.onClose(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const foot = buttons.length ? h('div', { class: 'modal-foot' }, buttons.map((b) => {
    const btn = h('button', { class: b.class || '', type: 'button' }, b.text);
    btn.addEventListener('click', async () => {
      if (!b.onClick) return close();
      btn.disabled = true;
      try { if ((await b.onClick(btn)) !== false) close(); } catch (e) { fail(e); } finally { btn.disabled = false; }
    });
    return btn;
  })) : null;
  const overlay = h('div', { class: 'overlay', onmousedown: (e) => { if (e.target === overlay && !opts.sticky) close(); } },
    h('div', { class: 'modal' + (opts.wide ? ' wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' }, h('h2', null, title), h('button', { class: 'icon', type: 'button', 'aria-label': 'Закрыть', onclick: close }, '✕')),
      h('div', { class: 'modal-body' }, body), foot));
  document.addEventListener('keydown', onKey);
  root.append(overlay);
  const first = overlay.querySelector('input,select,textarea');
  if (first) first.focus();
  return { close };
}

function confirmDialog(title, text, { danger = false, confirmText = 'Подтвердить', typeName = null } = {}) {
  return new Promise((resolve) => {
    let input = null;
    const body = h('div', null, h('p', null, text));
    if (typeName) {
      input = h('input', { placeholder: typeName, autocomplete: 'off', spellcheck: 'false' });
      body.append(h('p', { class: 'muted small' }, 'Для подтверждения введите имя: ', h('b', null, typeName)), input);
    }
    let done = false;
    modal(title, body, [
      { text: 'Отмена' },
      { text: confirmText, class: danger ? 'danger' : 'primary', onClick: () => {
        if (input && input.value.trim() !== typeName) { toast('Имя не совпадает', 'err'); return false; }
        done = true; resolve(true);
      } },
    ], { onClose: () => { if (!done) resolve(false); } });
  });
}

// ---------- forms ----------
// Field spec: {name, label, type, value, options:[[v,label]], help, full, placeholder, min, max, show(values)}
function buildForm(fields) {
  const els = {};
  const form = h('div', { class: 'form' });
  for (const f of fields) {
    let input;
    const id = 'f_' + f.name;
    if (f.type === 'checkbox') {
      input = h('input', { type: 'checkbox', id, checked: !!f.value });
      els[f.name] = { f, input, wrap: h('div', { class: 'field check' + (f.full ? ' full' : '') }, input, h('label', { for: id }, f.label)) };
    } else {
      if (f.type === 'select') {
        input = h('select', { id }, (f.options || []).map(([v, l]) => h('option', { value: v }, l)));
        if (f.value != null) input.value = f.value;
      } else if (f.type === 'textarea') {
        input = h('textarea', { id, placeholder: f.placeholder || '', spellcheck: 'false' });
        input.value = f.value || '';
      } else {
        input = h('input', { id, type: f.type || 'text', placeholder: f.placeholder || '', min: f.min, max: f.max, autocomplete: f.autocomplete || 'off', spellcheck: 'false' });
        if (f.value != null) input.value = f.value;
      }
      els[f.name] = { f, input, wrap: h('div', { class: 'field' + (f.full ? ' full' : '') }, h('label', { for: id }, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null) };
    }
    form.append(els[f.name].wrap);
  }
  const values = () => {
    const out = {};
    for (const [k, { f, input }] of Object.entries(els)) {
      if (els[k].wrap.hidden) continue;
      if (f.type === 'checkbox') out[k] = input.checked;
      else if (f.type === 'number') out[k] = input.value === '' ? 0 : Number(input.value);
      else out[k] = input.value.trim();
    }
    return out;
  };
  const refresh = () => {
    const v = values();
    for (const { f, wrap } of Object.values(els)) if (f.show) wrap.hidden = !f.show(v);
  };
  form.addEventListener('input', refresh);
  form.addEventListener('change', refresh);
  const showError = (e) => {
    for (const { wrap } of Object.values(els)) { wrap.classList.remove('invalid'); wrap.querySelector('.err')?.remove(); }
    const target = e.field && els[e.field];
    if (target) {
      target.wrap.classList.add('invalid');
      target.wrap.append(h('div', { class: 'err' }, e.message));
      target.input.focus();
    } else toast(e.message, 'err');
  };
  setTimeout(refresh);
  return { form, els, values, showError, refresh };
}

// ---------- jobs ----------
function openJob(job) {
  const log = h('pre', { class: 'log' });
  const pill = h('span', null, jobPill(job.state));
  const meta = h('div', { class: 'muted small' }, (job.user || '') + ' · ' + fmtTime(job.created));
  let es = null;
  const cancelBtn = h('button', { class: 'danger sm', type: 'button', onclick: async () => {
    try { await api('POST', '/api/jobs/' + encodeURIComponent(job.id) + '/cancel'); } catch (e) { fail(e); }
  } }, 'Отменить');
  const body = h('div', null, h('div', { class: 'row', style: 'margin-bottom:10px' }, pill, meta, h('span', { style: 'flex:1' }), can('operator') ? cancelBtn : null), log);
  const setState = (st) => { clear(pill).append(jobPill(st)); cancelBtn.hidden = !(st === 'running' || st === 'queued'); };
  setState(job.state);
  modal(job.title, body, [], { wide: true, onClose: () => { if (es) es.close(); refreshCurrent(); } });
  const append = (txt) => {
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    log.append(document.createTextNode(txt));
    if (atBottom) log.scrollTop = log.scrollHeight;
  };
  es = new EventSource('/api/jobs/' + encodeURIComponent(job.id) + '/stream');
  es.addEventListener('out', (ev) => { const d = JSON.parse(ev.data); if (d.data) append(d.data); setState('running'); });
  es.addEventListener('end', (ev) => {
    const j = JSON.parse(ev.data);
    setState(j.state);
    if (j.error) append('\n[' + j.error + ']\n');
    es.close();
    toast(j.title + ': ' + (j.state === 'done' ? 'готово' : j.state === 'failed' ? 'ошибка' : 'отменено'), j.state === 'done' ? 'ok' : 'err');
  });
  es.onerror = () => { /* browser reconnects automatically; stream restarts from offset 0 */ es.close(); };
}

async function runAction(method, url, body) {
  const r = await api(method, url, body);
  if (r.job) openJob(r.job);
  return r;
}

// ---------- routing ----------
const routes = [
  [/^$/, pageDashboard, 'dash'],
  [/^jails$/, () => pageEnvs('jail'), 'jails'],
  [/^vms$/, () => pageEnvs('bhyve'), 'vms'],
  [/^xen$/, () => pageEnvs('xen'), 'xen'],
  [/^env\/([A-Za-z0-9_.-]+)(?:\/(config|limits))?$/, (m) => pageEnv(m[1], m[2] || ''), null],
  [/^env\/([A-Za-z0-9_.-]+)\/terminal$/, (m) => pageTerminal(m[1]), null],
  [/^env\/([A-Za-z0-9_.-]+)\/vnc$/, (m) => pageVNC(m[1]), null],
  [/^images$/, pageImages, 'images'],
  [/^bases$/, pageBases, 'bases'],
  [/^nodes$/, pageNodes, 'nodes'],
  [/^jobs$/, pageJobs, 'jobs'],
  [/^setup$/, pageSetup, 'setup'],
  [/^users$/, pageUsers, 'users'],
  [/^audit$/, pageAudit, 'audit'],
  [/^account$/, pageAccount, 'account'],
];
const navItems = [
  ['', 'dash', 'Обзор'],
  ['jails', 'jails', 'Клетки (jail)'],
  ['vms', 'vms', 'ВМ bhyve'],
  ['xen', 'xen', 'ВМ Xen'],
  null,
  ['bases', 'bases', 'Базы FreeBSD'],
  ['images', 'images', 'Образы и ISO'],
  ['nodes', 'nodes', 'Узлы'],
  ['jobs', 'jobs', 'Задачи'],
  null,
  ['setup', 'setup', 'Установка и настройка'],
  ['users', 'users', 'Пользователи', 'admin'],
  ['audit', 'audit', 'Журнал аудита', 'admin'],
];

function renderShell() {
  const app = $('#app');
  app.className = '';
  const nav = h('nav', { class: 'nav' });
  for (const it of navItems) {
    if (!it) { nav.append(h('div', { class: 'sep' })); continue; }
    const [path, key, title, role] = it;
    if (role && !can(role)) continue;
    nav.append(h('a', { href: '#/' + path, 'data-key': key }, title));
  }
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), 'CBSD Web'),
    nav,
    h('div', { class: 'side-foot' },
      h('div', null, h('a', { href: '#/account' }, state.user), ' · ', roleTitle(state.role)),
      h('div', { class: 'row' }, h('span', null, 'v' + state.version),
        h('button', { class: 'sm', type: 'button', onclick: logout }, 'Выйти'))));
  const main = h('main', { class: 'main', id: 'main' });
  clear(app).append(h('div', { class: 'layout' }, side, main));
  app.addEventListener('click', (e) => { if (e.target.closest('.nav a')) side.classList.remove('open'); });
}
function roleTitle(r) { return { admin: 'администратор', operator: 'оператор', viewer: 'наблюдатель' }[r] || r; }

function route() {
  if (!state.user) return;
  if (!$('#main')) renderShell();
  const path = location.hash.replace(/^#\/?/, '');
  state.route = path;
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  refreshFn = null;
  for (const a of document.querySelectorAll('.nav a')) a.classList.remove('active');
  for (const [re, fn, key] of routes) {
    const m = path.match(re);
    if (m) {
      if (key) document.querySelector(`.nav a[data-key="${key}"]`)?.classList.add('active');
      const main = clear($('#main'));
      main.append(h('div', { class: 'muted' }, 'Загрузка…'));
      Promise.resolve(fn(m)).catch(fail);
      return;
    }
  }
  location.hash = '#/';
}
let refreshFn = null;
function refreshCurrent() { if (refreshFn) refreshFn().catch(fail); }
// Poll the current page while the tab is visible; stops when hidden.
function autoRefresh(fn, ms = 5000) {
  refreshFn = fn;
  state.timer = setInterval(() => { if (document.visibilityState === 'visible' && !$('.overlay')) fn().catch(() => {}); }, ms);
}

function pageHead(title, ...right) {
  return h('div', { class: 'page-head' },
    h('button', { class: 'menu-btn icon', type: 'button', 'aria-label': 'Меню', onclick: () => $('.side').classList.toggle('open') }, '☰'),
    h('h1', null, title), h('div', { class: 'spacer' }), right);
}

// ---------- login ----------
function renderLogin(msg) {
  if (state.timer) clearInterval(state.timer);
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  const app = $('#app');
  app.className = '';
  const user = h('input', { name: 'username', autocomplete: 'username', placeholder: 'Пользователь', required: true });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', placeholder: 'Пароль', required: true });
  const err = h('div', { class: 'small', style: 'color:var(--err);min-height:18px' }, msg || '');
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Войти');
  const form = h('form', { onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true; err.textContent = '';
    try {
      const r = await api('POST', '/api/login', { user: user.value, password: pass.value });
      Object.assign(state, { user: r.user, role: r.role, csrf: r.csrf, version: r.version, terminal: !!r.terminal });
      clear(app); route();
    } catch (e2) { err.textContent = e2.message; pass.value = ''; pass.focus(); } finally { btn.disabled = false; }
  } }, user, pass, err, btn);
  clear(app).append(h('div', { class: 'login' }, h('div', { class: 'card' },
    h('h1', null, h('img', { src: '/favicon.svg', alt: '', width: 28, height: 28 }), 'CBSD Web'),
    h('div', { class: 'muted' }, 'Управление клетками и виртуальными машинами'), form)));
  user.focus();
}
async function logout() {
  try { await api('POST', '/api/logout'); } catch (_) { /* ignore */ }
  Object.assign(state, { user: null, role: null, csrf: null, terminal: false });
  renderLogin();
}

// ---------- dashboard ----------
async function pageDashboard() {
  const main = $('#main');
  const render = async () => {
    const d = await api('GET', '/api/overview');
    const host = d.host || {};
    const c = d.counts || {};
    const node = d.node || {};
    const content = [];
    if (!d.initialized) content.push(h('div', { class: 'banner warn' }, 'CBSD ещё не инициализирован в ', h('code', null, d.workdir), '. ', h('a', { href: '#/setup' }, 'Открыть мастер настройки →')));
    if (d.db_error) content.push(h('div', { class: 'banner err' }, d.db_error, ' ', h('a', { href: '#/setup' }, 'Диагностика →')));
    if (d.cbsd_error) content.push(h('div', { class: 'banner err' }, 'Не удаётся запустить cbsd: ', h('code', null, d.cbsd_error), ' ', h('a', { href: '#/setup' }, 'Диагностика →')));
    const stat = (label, val, sub, href) => h(href ? 'a' : 'div', { class: 'card stat', href }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, val), h('div', { class: 'sub' }, sub));
    const cnt = (k) => c[k] || { total: 0, running: 0 };
    content.push(h('div', { class: 'grid cols-4' },
      stat('Клетки', cnt('jail').running + ' / ' + cnt('jail').total, 'запущено / всего', '#/jails'),
      stat('ВМ bhyve', cnt('bhyve').running + ' / ' + cnt('bhyve').total, 'запущено / всего', '#/vms'),
      stat('ВМ Xen', cnt('xen').running + ' / ' + cnt('xen').total, 'запущено / всего', '#/xen'),
      stat('Задачи', Object.keys(d.busy || {}).length, 'выполняется сейчас', '#/jobs')));
    const memUsed = host.physmem && host.freemem ? host.physmem - host.freemem : 0;
    const diskUsed = host.disk_total ? host.disk_total - host.disk_free : 0;
    const meter = (used, total) => total ? h('div', { class: 'meter' }, h('i', { style: 'width:' + Math.min(100, Math.round(used / total * 100)) + '%' })) : null;
    content.push(h('div', { class: 'grid cols-2 mt' },
      h('div', { class: 'card' }, h('h2', null, 'Хост'), h('dl', { class: 'kv' },
        h('dt', null, 'Имя'), h('dd', null, host.hostname || '—'),
        h('dt', null, 'Система'), h('dd', null, (host.release || host.os || '') + ' · ' + (host.arch || '')),
        h('dt', null, 'CPU'), h('dd', null, String(host.cpus || '—')),
        h('dt', null, 'Нагрузка'), h('dd', null, (host.load || []).map((x) => x.toFixed(2)).join(' / ') || '—'),
        h('dt', null, 'Аптайм'), h('dd', null, fmtUptime(host.uptime)),
        h('dt', null, 'Память'), h('dd', null, host.physmem ? fmtBytes(memUsed) + ' из ' + fmtBytes(host.physmem) : '—', meter(memUsed, host.physmem)),
        h('dt', null, 'Диск workdir'), h('dd', null, host.disk_total ? fmtBytes(host.disk_free) + ' свободно из ' + fmtBytes(host.disk_total) : '—', meter(diskUsed, host.disk_total)),
        h('dt', null, 'bhyve (vmm)'), h('dd', null, host.vmm_loaded ? 'загружен' : 'не загружен'))),
      h('div', { class: 'card' }, h('h2', null, 'CBSD'), h('dl', { class: 'kv' },
        h('dt', null, 'Версия'), h('dd', null, d.cbsd_version || '—'),
        h('dt', null, 'Workdir'), h('dd', null, h('code', null, d.workdir)),
        h('dt', null, 'Узел'), h('dd', null, node.nodename || '—'),
        h('dt', null, 'IP узла'), h('dd', null, node.nodeip || '—'),
        h('dt', null, 'Пул IP'), h('dd', null, node.nodeippool || '—'),
        h('dt', null, 'NAT'), h('dd', null, node.nat_enable || '—'),
        h('dt', null, 'ZFS'), h('dd', null, node.zfsfeat === 1 || node.zfsfeat === '1' ? 'да' : 'нет'),
        h('dt', null, 'Веб-интерфейс'), h('dd', null, 'v' + d.web_version)))));
    content.push(h('div', { class: 'mt' }, h('h2', null, 'Последние задачи'), jobsTable(d.recent_jobs || [])));
    fill(main, pageHead('Обзор'), content);
  };
  await render();
  autoRefresh(render, 10000);
}

function jobsTable(list) {
  if (!list.length) return h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'Задач пока нет'));
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Задача', 'Статус', 'Пользователь', 'Начало', 'Длительность'].map((t) => h('th', null, t)))),
    h('tbody', null, list.map((j) => h('tr', null,
      h('td', null, h('a', { href: '#', onclick: (e) => { e.preventDefault(); openJob(j); } }, j.title)),
      h('td', null, jobPill(j.state), j.error ? h('span', { class: 'muted small', title: j.error }, ' ⚠') : null),
      h('td', null, j.user), h('td', null, fmtTime(j.started || j.created)),
      h('td', null, fmtDur(j.started, j.finished)))))));
}

// ---------- environments ----------
async function pageEnvs(emu) {
  const main = $('#main');
  const title = { jail: 'Клетки (jail)', bhyve: 'Виртуальные машины bhyve', xen: 'Виртуальные машины Xen' }[emu];
  let filter = '';
  const search = h('input', { class: 'search', type: 'search', placeholder: 'Поиск по имени или IP', oninput: () => { filter = search.value.toLowerCase(); draw(); } });
  const createBtn = can('operator') ? h('button', { class: 'primary', type: 'button', onclick: () => (emu === 'jail' ? createJail() : createVM(emu)) }, emu === 'jail' ? '+ Новая клетка' : '+ Новая ВМ') : null;
  const holder = h('div');
  fill(main, pageHead(title, search, createBtn), holder);
  let data = { envs: [], busy: {} };
  const draw = () => {
    const list = data.envs.filter((e) => !filter || e.jname.toLowerCase().includes(filter) || (e.ip4_addr || '').toLowerCase().includes(filter));
    clear(holder);
    if (data.initialized === false) { holder.append(h('div', { class: 'banner warn' }, 'CBSD не инициализирован. ', h('a', { href: '#/setup' }, 'Перейти к настройке →'))); return; }
    if (!list.length) { holder.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, data.envs.length ? 'Ничего не найдено' : 'Пока пусто. Создайте первое окружение.'))); return; }
    const cols = emu === 'jail' ? ['Статус', 'Имя', 'IP', 'Hostname', 'База', 'Автозапуск', ''] : ['Статус', 'Имя', 'IP', 'ОС / профиль', 'CPU', 'RAM', 'VNC', 'Автозапуск', ''];
    holder.append(h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, cols.map((c) => h('th', null, c)))),
      h('tbody', null, list.map((e) => envRow(e, emu, data.busy[e.jname]))))));
  };
  const render = async () => { data = await api('GET', '/api/envs?emulator=' + emu); draw(); };
  await render();
  autoRefresh(render);
}

function envRow(e, emu, busyJob) {
  const name = h('td', null, h('a', { href: '#/env/' + encodeURIComponent(e.jname) }, e.jname), e.protected ? h('span', { class: 'tag', title: 'Защищено от удаления' }, ' 🔒') : null);
  const cells = [h('td', null, statusPill(e, busyJob)), name, h('td', { class: 'mono' }, e.ip4_addr || '—')];
  if (emu === 'jail') {
    cells.push(h('td', null, e.host_hostname || '—'), h('td', null, e.ver || '—', e.baserw ? h('span', { class: 'tag' }, ' rw') : null));
  } else {
    cells.push(h('td', null, (e.vm_os_type || '') + (e.vm_os_profile ? ' · ' + e.vm_os_profile : '')), h('td', null, String(e.vm_cpus || '—')), h('td', null, fmtBytes(e.vm_ram)),
      h('td', { class: 'mono' }, e.vnc_port ? (e.vnc_bind || '127.0.0.1') + ':' + e.vnc_port : '—'));
  }
  cells.push(h('td', null, e.astart ? 'да' : 'нет'), h('td', { class: 'actions' }, envButtons(e, busyJob, true)));
  return h('tr', null, cells);
}

function envButtons(e, busyJob, compact) {
  if (!can('operator')) return null;
  const url = '/api/envs/' + encodeURIComponent(e.jname) + '/action';
  const act = (a) => async () => {
    try { await runAction('POST', url, { action: a }); } catch (err) { fail(err); }
  };
  const cls = compact ? 'sm' : '';
  const running = e.status === 1;
  const g = h('div', { class: 'btn-group' });
  if (busyJob) {
    g.append(h('button', { class: cls, type: 'button', onclick: async () => { try { const r = await api('GET', '/api/jobs/' + encodeURIComponent(busyJob)); openJob(r.job); } catch (err) { fail(err); } } }, 'Показать вывод'));
    return g;
  }
  if (!running) g.append(h('button', { class: cls + ' primary', type: 'button', onclick: act('start') }, '▶ Запустить'));
  if (running) {
    g.append(h('button', { class: cls, type: 'button', onclick: async () => {
      if (await confirmDialog('Остановить ' + e.jname + '?', 'Все процессы внутри будут завершены.', { confirmText: 'Остановить' })) act('stop')();
    } }, '■ Стоп'));
    if (e.emulator === 'jail' || e.emulator === 'bhyve') g.append(h('button', { class: cls, type: 'button', onclick: async () => {
      if (await confirmDialog('Перезапустить ' + e.jname + '?', 'Окружение будет остановлено и запущено снова.', { confirmText: 'Перезапустить' })) act('restart')();
    } }, '↻'));
    if (e.emulator === 'jail' && state.terminal) g.append(h('a', { class: 'btn ' + cls, href: '#/env/' + encodeURIComponent(e.jname) + '/terminal', title: 'Терминал в клетке' }, compact ? '>_' : '>_ Терминал'));
  }
  return g;
}

async function pageEnv(name, tab) {
  const main = $('#main');
  const enc = encodeURIComponent(name);
  const keep = {};
  const render = async () => {
    const { env: e, busy_job: busyJob } = await api('GET', '/api/envs/' + enc);
    const back = { jail: '#/jails', bhyve: '#/vms', xen: '#/xen' }[e.emulator] || '#/';
    const isJail = e.emulator === 'jail';
    if (!isJail) tab = '';
    const tools = [];
    if (can('operator')) {
      if (!isJail) tools.push(h('button', { type: 'button', onclick: () => editEnv(e) }, 'Настройки'));
      if (isJail || e.emulator === 'bhyve') tools.push(h('button', { type: 'button', onclick: () => cloneEnv(e) }, 'Клонировать'));
    }
    if (can('admin')) tools.push(h('button', { class: 'danger', type: 'button', disabled: e.protected || !!busyJob, title: e.protected ? 'Защищено (protected=1)' : '', onclick: async () => {
      if (!(await confirmDialog('Удалить ' + e.jname + '?', 'Окружение и все его данные будут удалены без возможности восстановления.', { danger: true, confirmText: 'Удалить навсегда', typeName: e.jname }))) return;
      try { await runAction('POST', '/api/envs/' + enc + '/action', { action: 'remove' }); location.hash = back; } catch (err) { fail(err); }
    } }, 'Удалить'));
    const head = [
      pageHead(e.jname, h('a', { class: 'btn', href: back }, '← К списку')),
      h('div', { class: 'row', style: 'margin-bottom:16px' }, statusPill(e, busyJob), envButtons(e, busyJob, false), h('span', { style: 'flex:1' }), tools),
      e.maintenance ? h('div', { class: 'banner warn' }, 'Режим обслуживания: ', e.maintenance) : null,
    ];
    if (isJail) {
      const t = (key, title) => h('a', { href: '#/env/' + enc + (key ? '/' + key : ''), class: tab === key ? 'active' : '' }, title);
      head.push(h('nav', { class: 'tabs' }, t('', 'Обзор'), t('config', 'Конфигурация'), t('limits', 'Лимиты ресурсов'),
        state.terminal ? h('a', { href: '#/env/' + enc + '/terminal' }, '>_ Терминал') : null));
    }
    if (tab === 'config') return fill(main, head, await jailConfigTab(e));
    if (tab === 'limits') return fill(main, head, await jailLimitsTab(e));
    fill(main, head, envOverview(e, keep));
  };
  await render();
  // Only the overview polls: the edit tabs must not reset what the user typed.
  if (!tab) autoRefresh(render, 6000);
  else refreshFn = render;
}

// Sticky bar with the change counter and save/reset buttons for an edit tab.
function saveBar(onSave, onReset, extra) {
  const count = h('span', { class: 'muted' });
  const save = h('button', { class: 'primary', type: 'button' }, 'Сохранить');
  const reset = h('button', { type: 'button', onclick: onReset }, 'Сбросить');
  save.addEventListener('click', async () => { save.disabled = true; try { await onSave(); } finally { save.disabled = false; } });
  const bar = h('div', { class: 'savebar', hidden: true }, count, extra, h('span', { style: 'flex:1' }), reset, save);
  return { bar, set(n) { bar.hidden = n === 0; count.textContent = 'Изменено: ' + n; } };
}

async function jailConfigTab(e) {
  const url = '/api/envs/' + encodeURIComponent(e.jname) + '/config';
  const r = await api('GET', url);
  const orig = r.values || {};
  // Only parameters this CBSD version has a column for.
  const params = r.params.filter((p) => p.name in orig);
  const ctrls = {};
  const norm = (p, v) => (p.kind === 'bool' ? (v === '1' || v === 'true' ? '1' : '0') : String(v ?? ''));
  const current = (c) => (c.p.kind === 'bool' ? (c.input.checked ? '1' : '0') : c.input.value.trim());
  const diff = () => {
    const out = {};
    for (const c of Object.values(ctrls)) { const v = current(c); if (v !== norm(c.p, orig[c.p.name])) out[c.p.name] = v; }
    return out;
  };
  const restartBox = h('input', { type: 'checkbox', id: 'cfg_restart' });
  const restartWrap = h('label', { class: 'row small', for: 'cfg_restart', hidden: true }, restartBox, 'Перезапустить клетку, чтобы применить');
  const update = () => {
    const d = diff();
    for (const c of Object.values(ctrls)) c.wrap.classList.toggle('changed', c.p.name in d);
    bar.set(Object.keys(d).length);
    restartWrap.hidden = !(r.running && Object.keys(d).some((k) => !ctrls[k].p.live));
  };
  const clearErrors = () => { restartWrap.classList.remove('attn'); for (const c of Object.values(ctrls)) { c.wrap.classList.remove('invalid'); c.wrap.querySelector('.err')?.remove(); } };
  const bar = saveBar(async () => {
    clearErrors();
    const values = diff();
    try { await runAction('PATCH', url, { values, restart: restartBox.checked }); } catch (err) {
      const c = ctrls[err.field];
      if (err.field === 'restart') { restartWrap.classList.add('attn'); restartBox.focus(); }
      if (c) { c.wrap.classList.add('invalid'); c.wrap.append(h('div', { class: 'err' }, err.message)); c.wrap.scrollIntoView({ block: 'center' }); c.input.focus(); } else fail(err);
    }
  }, () => {
    clearErrors();
    for (const c of Object.values(ctrls)) {
      const v = norm(c.p, orig[c.p.name]);
      if (c.p.kind === 'bool') c.input.checked = v === '1'; else c.input.value = v;
    }
    update();
  }, restartWrap);

  const field = (p) => {
    const id = 'cfg_' + p.name;
    const v = norm(p, orig[p.name]);
    const disabled = !can('operator') || (p.admin && !can('admin'));
    let input;
    if (p.kind === 'bool') input = h('input', { type: 'checkbox', id, checked: v === '1', disabled });
    else if (p.kind === 'enum') {
      const opts = p.options.includes(v) ? p.options : [v, ...p.options];
      input = h('select', { id, disabled }, opts.map((o) => h('option', { value: o }, o)));
      input.value = v;
    } else input = h('input', { id, type: p.kind === 'int' ? 'number' : 'text', min: p.kind === 'int' ? p.min : null, max: p.kind === 'int' ? p.max : null, value: v, disabled, autocomplete: 'off', spellcheck: 'false' });
    const marks = [p.live ? null : h('span', { class: 'mark', title: 'На запущенной клетке применяется перезапуском' }, '↻'),
      p.admin ? h('span', { class: 'mark', title: 'Меняет только администратор' }, '🔒') : null];
    const label = h('label', { for: id }, p.label, ' ', marks);
    const meta = h('div', { class: 'help' }, h('span', { class: 'mono' }, p.name), p.help ? ' · ' + p.help : '');
    const wrap = p.kind === 'bool'
      ? h('div', { class: 'pfield check' }, input, h('div', null, label, meta))
      : h('div', { class: 'pfield' }, label, input, meta);
    ctrls[p.name] = { p, input, wrap, text: (p.name + ' ' + p.label + ' ' + (p.help || '')).toLowerCase() };
    return wrap;
  };
  const cards = r.groups.map((g) => {
    const ps = params.filter((p) => p.group === g);
    if (!ps.length) return null;
    const card = h('section', { class: 'card pgroup' }, h('h2', null, g), h('div', { class: 'pgrid' }, ps.map(field)));
    card.dataset.group = g;
    return card;
  });
  const search = h('input', { class: 'search', type: 'search', placeholder: 'Поиск параметра…', oninput: () => {
    const q = search.value.trim().toLowerCase();
    for (const c of Object.values(ctrls)) c.wrap.hidden = !!q && !c.text.includes(q);
    for (const card of cards) if (card) card.hidden = ![...card.querySelectorAll('.pfield')].some((w) => !w.hidden);
  } });
  const box = h('div', { oninput: update, onchange: update },
    h('div', { class: 'row', style: 'margin-bottom:12px' }, search,
      h('span', { class: 'muted small' }, '↻ — на запущенной клетке нужен перезапуск, 🔒 — только администратор. Значения пишутся через cbsd jset.')),
    r.busy_job ? h('div', { class: 'banner warn' }, 'Сейчас над клеткой выполняется задача; изменения можно будет сохранить после неё.') : null,
    h('div', { class: 'pgroups' }, cards), bar.bar);
  return box;
}

async function jailLimitsTab(e) {
  const url = '/api/envs/' + encodeURIComponent(e.jname) + '/limits';
  const r = await api('GET', url);
  const orig = r.values || {};
  const usage = r.usage || {};
  const inputs = {};
  const origOf = (n) => (orig[n] && orig[n] !== '0' ? orig[n] : '');
  const diff = () => {
    const out = {};
    for (const [n, inp] of Object.entries(inputs)) { const v = inp.value.trim(); if (v !== origOf(n)) out[n] = v === '' ? '0' : v; }
    return out;
  };
  const update = () => {
    const d = diff();
    for (const [n, inp] of Object.entries(inputs)) inp.closest('tr').classList.toggle('changed', n in d);
    bar.set(Object.keys(d).length);
  };
  const bar = saveBar(async () => {
    for (const inp of Object.values(inputs)) inp.classList.remove('bad');
    try { await runAction('PUT', url, { values: diff() }); } catch (err) {
      if (inputs[err.field]) { inputs[err.field].classList.add('bad'); inputs[err.field].focus(); }
      fail(err);
    }
  }, () => { for (const [n, inp] of Object.entries(inputs)) inp.value = origOf(n); update(); });
  const rows = r.params.map((p) => {
    const inp = h('input', { value: origOf(p.name), placeholder: 'нет', disabled: !can('operator'), autocomplete: 'off', spellcheck: 'false', 'aria-label': p.label });
    inputs[p.name] = inp;
    return h('tr', null, h('td', null, h('div', null, p.label), h('div', { class: 'muted small mono' }, p.name)),
      h('td', { class: 'limit-in' }, inp), r.running ? h('td', { class: 'mono' }, usage[p.name] || '—') : null,
      h('td', { class: 'wrap muted small' }, p.help || (p.size ? 'Можно с суффиксом k, m, g, t.' : '')));
  });
  return h('div', { oninput: update },
    h('div', { class: 'banner info' }, 'Ограничения rctl применяются через cbsd jrctl. Пустое значение или 0 снимает лимит. ',
      'Нужен kern.racct.enable=1 в /boot/loader.conf (включается перезагрузкой хоста).'),
    r.values_error ? h('div', { class: 'banner warn' }, r.values_error, '. Можно задать новые значения: они перезапишут текущие.') : null,
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Ресурс'), h('th', null, 'Лимит'), r.running ? h('th', null, 'Сейчас') : null, h('th', null, ''))),
      h('tbody', null, rows))), bar.bar);
}

// ---------- VNC console ----------
async function pageVNC(name) {
  const main = $('#main');
  const enc = encodeURIComponent(name);
  const backBtn = h('a', { class: 'btn', href: '#/env/' + enc }, '← К машине');
  const info = await api('GET', '/api/envs/' + enc + '/vnc');
  if (!info.console || !info.port || !info.running) {
    const why = !info.console ? 'Консоль доступна администратору (параметр terminal_role в конфиге).'
      : !info.port ? 'VNC для этой машины не назначен.' : 'Машина не запущена.';
    return fill(main, pageHead('Консоль: ' + name, backBtn), h('div', { class: 'banner warn' }, why));
  }
  const { default: RFB } = await import('/vendor/novnc/core/rfb.js');
  const pill = h('span', { class: 'pill run' }, 'подключение…');
  const setPill = (cls, text) => { pill.className = 'pill ' + cls; pill.textContent = text; };
  const screen = h('div', { class: 'vnc-box' });
  let rfb = null;
  const btn = (text, title, fn) => h('button', { class: 'sm', type: 'button', title, onclick: fn }, text);
  const scaleBox = h('input', { type: 'checkbox', id: 'vnc_scale', checked: true, onchange: () => { if (rfb) rfb.scaleViewport = scaleBox.checked; } });
  const reconnect = btn('Переподключить', '', () => connect());
  reconnect.hidden = true;
  fill(main, pageHead('Консоль: ' + name, pill, backBtn),
    h('div', { class: 'row', style: 'margin-bottom:10px' },
      btn('Ctrl+Alt+Del', 'Отправить Ctrl+Alt+Del', () => rfb && rfb.sendCtrlAltDel()),
      btn('Во весь экран', '', () => screen.requestFullscreen && screen.requestFullscreen()),
      h('label', { class: 'row small', for: 'vnc_scale' }, scaleBox, 'Вписать в окно'),
      reconnect, h('span', { style: 'flex:1' }),
      h('span', { class: 'muted small mono' }, (info.bind || '127.0.0.1') + ':' + info.port + (info.resolution ? ' · ' + info.resolution : ''))),
    screen);
  const connect = () => {
    if (rfb) { const old = rfb; rfb = null; old.disconnect(); }
    fill(screen);
    setPill('run', 'подключение…');
    reconnect.hidden = true;
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/envs/' + enc + '/vnc/ws?' + new URLSearchParams({ csrf: state.csrf });
    const r = new RFB(screen, url, { wsProtocols: ['binary'], credentials: info.password ? { password: info.password } : undefined });
    rfb = r;
    r.scaleViewport = scaleBox.checked;
    r.background = '#0d1117';
    r.addEventListener('connect', () => { setPill('on', 'подключено'); r.focus(); });
    r.addEventListener('disconnect', (ev) => {
      if (rfb !== r) return;
      setPill('off', ev.detail.clean ? 'отключено' : 'соединение потеряно');
      reconnect.hidden = false;
    });
    r.addEventListener('securityfailure', (ev) => toast('VNC: ошибка аутентификации' + (ev.detail.reason ? ': ' + ev.detail.reason : ''), 'err'));
    r.addEventListener('credentialsrequired', () => {
      const inp = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Пароль VNC' });
      modal('Пароль VNC', h('div', null, inp), [{ text: 'Отмена' }, { text: 'Подключить', class: 'primary', onClick: () => r.sendCredentials({ password: inp.value }) }]);
    });
  };
  connect();
  state.cleanup = () => { const r = rfb; rfb = null; if (r) r.disconnect(); };
}

// ---------- terminal ----------
let xtermLoading = null;
function loadXterm() {
  if (window.Terminal && window.FitAddon) return Promise.resolve();
  if (!xtermLoading) {
    const add = (el) => new Promise((ok, bad) => { el.onload = ok; el.onerror = () => bad(new Error('не удалось загрузить ' + (el.src || el.href))); document.head.append(el); });
    xtermLoading = Promise.all([
      add(h('link', { rel: 'stylesheet', href: '/vendor/xterm.css' })),
      add(h('script', { src: '/vendor/xterm.js' })).then(() => add(h('script', { src: '/vendor/addon-fit.js' }))),
    ]).catch((e) => { xtermLoading = null; throw e; });
  }
  return xtermLoading;
}

async function pageTerminal(name) {
  const main = $('#main');
  const enc = encodeURIComponent(name);
  const { env: e } = await api('GET', '/api/envs/' + enc);
  const backBtn = h('a', { class: 'btn', href: '#/env/' + enc }, '← К клетке');
  if (!state.terminal || e.emulator !== 'jail' || e.status !== 1) {
    const why = !state.terminal ? 'Терминал доступен администратору (параметр terminal_role в конфиге).'
      : e.emulator !== 'jail' ? 'Терминал доступен только для клеток.' : 'Клетка не запущена.';
    return fill(main, pageHead('Терминал: ' + name, backBtn), h('div', { class: 'banner warn' }, why),
      e.emulator === 'jail' && e.status !== 1 && can('operator') ? envButtons(e, null, false) : null);
  }
  await loadXterm();
  const pill = h('span', { class: 'pill off' }, 'подключение…');
  const setPill = (cls, text) => { pill.className = 'pill ' + cls; pill.textContent = text; };
  const box = h('div', { class: 'term-box' });
  let ws = null;
  const reconnect = h('button', { type: 'button', hidden: true, onclick: () => connect() }, 'Переподключить');
  fill(main, pageHead('Терминал: ' + name, pill, reconnect, backBtn), box,
    h('div', { class: 'muted small mt' }, 'Вы входите как root через cbsd jlogin. Сеанс закрывается через ',
      'полчаса бездействия; если на хосте установлен tmux, CBSD сохраняет сеанс и при следующем входе подключится к нему.'));
  const term = new window.Terminal({ cursorBlink: true, fontSize: 14, scrollback: 5000, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    theme: { background: '#0d1117', foreground: '#d1d7e0' } });
  const fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(box);
  fit.fit();
  const encoder = new TextEncoder();
  const send = (data) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(data); };
  term.onData((d) => send(encoder.encode(d)));
  term.onBinary((d) => send(Uint8Array.from(d, (c) => c.charCodeAt(0))));
  term.onResize(({ cols, rows }) => send(JSON.stringify({ type: 'resize', cols, rows })));
  const connect = () => {
    if (ws) ws.close();
    setPill('run', 'подключение…');
    reconnect.hidden = true;
    const q = new URLSearchParams({ csrf: state.csrf, cols: term.cols, rows: term.rows });
    ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/envs/' + enc + '/terminal?' + q);
    ws.binaryType = 'arraybuffer';
    const me = ws;
    ws.onopen = () => { setPill('on', 'подключено'); term.focus(); };
    ws.onmessage = (ev) => term.write(typeof ev.data === 'string' ? ev.data : new Uint8Array(ev.data));
    ws.onclose = (ev) => {
      if (me !== ws) return;
      setPill('off', 'отключено');
      reconnect.hidden = false;
      term.write('\r\n\x1b[33m[соединение закрыто' + (ev.reason ? ': ' + ev.reason : ev.code === 1006 ? ': сервер отклонил подключение' : '') + ']\x1b[0m\r\n');
    };
  };
  const onResize = () => fit.fit();
  window.addEventListener('resize', onResize);
  connect();
  state.cleanup = () => { window.removeEventListener('resize', onResize); const w = ws; ws = null; if (w) w.close(); term.dispose(); };
}

function envOverview(e, keep) {
  const info = [
    ['Тип', EMU_TITLE[e.emulator] || e.emulator], ['IP', e.ip4_addr || '—'], ['Hostname', e.host_hostname || '—'],
    ['Путь', e.path || '—'], ['Интерфейс', e.interface || '—'], ['Автозапуск', e.astart ? 'да' : 'нет'],
    ['Защита от удаления', e.protected ? 'да' : 'нет'],
  ];
  if (e.emulator === 'jail') info.push(['JID', e.jid ? String(e.jid) : '—'], ['База', e.ver || '—'], ['Режим базы', e.baserw ? 'rw (своя копия)' : 'ro (общая)'], ['VNET', e.vnet ? 'да' : 'нет']);
  else info.push(['ОС', e.vm_os_type || '—'], ['Профиль', e.vm_os_profile || '—'], ['CPU', String(e.vm_cpus || '—')], ['RAM', fmtBytes(e.vm_ram)]);
  // Cards with their own state survive the periodic re-render of the page.
  if (!keep.stats) keep.stats = statsCard(e);
  keep.stats.update(e);
  if ((e.emulator === 'jail' || e.emulator === 'bhyve') && !keep.snaps) keep.snaps = snapshotCard(e);
  if (keep.snaps && keep.snaps.dirty) keep.snaps.load();
  const vnc = e.emulator === 'bhyve' || e.emulator === 'xen' ? vncCard(e, keep) : null;
  return [
    h('div', { class: 'grid cols-2' },
      h('div', { class: 'card' }, h('h2', null, 'Параметры'), h('dl', { class: 'kv' }, info.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))),
      vnc, keep.stats.el),
    keep.snaps ? keep.snaps.el : null,
  ];
}

function copyBtn(text) {
  return h('button', { class: 'sm icon', type: 'button', title: 'Скопировать', onclick: async () => {
    try { await navigator.clipboard.writeText(text); toast('Скопировано', 'ok'); } catch (_) { toast('Не удалось скопировать: выделите текст вручную', 'err'); }
  } }, '⧉');
}

function vncCard(e, keep) {
  const enc = encodeURIComponent(e.jname);
  if (!e.vnc_port) return h('div', { class: 'card' }, h('h2', null, 'Консоль VNC'), h('p', { class: 'muted' }, 'VNC для этой машины не назначен.'));
  const bind = e.vnc_bind || '127.0.0.1';
  const local = bind === '127.0.0.1' || bind === 'localhost' || bind === '::1';
  const addr = (bind === '0.0.0.0' || bind === '::' ? location.hostname : bind) + ':' + e.vnc_port;
  const pass = h('span', { class: 'mono' }, e.vnc_has_password ? '••••••••' : 'не задан');
  const reveal = (pw) => { keep.vncPass = pw; fill(pass, pw || 'не задан', ' ', pw ? copyBtn(pw) : null); };
  let showPass = null;
  if (keep.vncPass != null) reveal(keep.vncPass);
  else if (e.vnc_has_password && state.terminal) showPass = h('button', { class: 'sm', type: 'button', onclick: async () => {
    try { const r = await api('GET', '/api/envs/' + enc + '/vnc'); reveal(r.password || ''); showPass.remove(); } catch (err) { fail(err); }
  } }, 'Показать');
  const tunnel = 'ssh -L 5900:127.0.0.1:' + e.vnc_port + ' <пользователь>@' + location.hostname;
  return h('div', { class: 'card' }, h('h2', null, 'Консоль VNC'),
    h('dl', { class: 'kv' },
      h('dt', null, 'Адрес'), h('dd', null, h('span', { class: 'mono' }, local ? bind + ':' + e.vnc_port : addr), ' ', copyBtn(local ? bind + ':' + e.vnc_port : addr)),
      h('dt', null, 'Порт'), h('dd', { class: 'mono' }, String(e.vnc_port)),
      h('dt', null, 'Пароль'), h('dd', null, pass, ' ', showPass),
      e.vnc_resolution ? [h('dt', null, 'Разрешение'), h('dd', null, e.vnc_resolution)] : null),
    h('div', { class: 'row mt' },
      state.terminal ? h('a', { class: 'btn primary' + (e.status === 1 ? '' : ' disabled'), href: e.status === 1 ? '#/env/' + enc + '/vnc' : null, title: e.status === 1 ? '' : 'Машина не запущена' }, '🖥 Открыть в браузере') : null),
    local ? h('div', { class: 'mt' }, h('div', { class: 'muted small' }, 'VNC слушает только локальный адрес. Для внешнего клиента используйте SSH-туннель и подключайтесь к localhost:5900:'),
      h('div', { class: 'row' }, h('code', { class: 'mono' }, tunnel), copyBtn(tunnel))) : null);
}

function fmtRate(bps) {
  if (bps == null) return '';
  return bps < 1 ? '0 Б/с' : fmtBytes(bps) + '/с';
}

function statsCard(e) {
  const enc = encodeURIComponent(e.jname);
  const body = h('div', null, h('div', { class: 'muted' }, 'Загрузка…'));
  const el = h('div', { class: 'card' }, h('h2', null, 'Сеть и ресурсы'), body);
  let prev = null;
  let busy = false;
  const update = async (env) => {
    if (busy) return;
    busy = true;
    try {
      const s = await api('GET', '/api/envs/' + enc + '/stats');
      const dt = prev ? (s.at - prev.at) / 1000 : 0;
      const rate = (n, key) => {
        const p = prev && (prev.nics || []).find((x) => x.name === n.name);
        return p && dt > 0 && n[key] >= p[key] ? (n[key] - p[key]) / dt : null;
      };
      const nics = s.nics || [];
      const parts = [h('dl', { class: 'kv' },
        h('dt', null, 'IP-адреса'), h('dd', { class: 'mono' }, (s.ips || []).length ? s.ips.join(', ') : '—'),
        env.emulator === 'jail' ? [h('dt', null, 'Сетевой стек'), h('dd', null, s.vnet ? 'VNET (свой)' : 'общий с хостом, интерфейс ' + (s.interface || 'auto'))] : null)];
      if (nics.length) {
        parts.push(h('div', { class: 'table-wrap mt' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, h('th', null, 'Интерфейс на хосте'), h('th', null, 'Трафик: всего · сейчас'))),
          h('tbody', null, nics.map((n) => h('tr', null,
            h('td', null, h('div', { class: 'mono' }, n.name, n.up ? '' : ' (down)'), h('div', { class: 'muted small mono' }, n.mac), n.bridge ? h('div', { class: 'muted small' }, 'мост ' + n.bridge) : null),
            h('td', null,
              h('div', { title: 'Принято окружением' }, '↓ ', fmtBytes(n.rx_bytes), h('span', { class: 'muted small' }, ' · ' + (fmtRate(rate(n, 'rx_bytes')) || '…'))),
              h('div', { title: 'Отправлено окружением' }, '↑ ', fmtBytes(n.tx_bytes), h('span', { class: 'muted small' }, ' · ' + (fmtRate(rate(n, 'tx_bytes')) || '…'))),
              n.errs ? h('div', { class: 'small', style: 'color:var(--err)' }, 'ошибок: ' + n.errs) : null)))))));
      } else if (s.nics_error) {
        parts.push(h('p', { class: 'muted small' }, s.nics_error));
      } else if (env.emulator === 'jail' && !s.vnet) {
        parts.push(h('p', { class: 'muted small' }, 'Клетка без VNET работает на адресах интерфейса хоста, поэтому её трафик отдельно не учитывается. Включите VNET в конфигурации, чтобы видеть счётчики.'));
      } else if (env.status === 1) {
        parts.push(h('p', { class: 'muted small' }, 'Интерфейсы окружения на хосте не найдены.'));
      }
      const res = [];
      if (s.procs) res.push(['CPU', s.procs.cpu_pct.toFixed(1) + ' %'], ['Память (RSS)', fmtBytes(s.procs.rss)],
        ['Виртуальная память', fmtBytes(s.procs.vsz)], [env.emulator === 'jail' ? 'Процессов' : 'Процесс bhyve', String(s.procs.count)]);
      if (s.disk) {
        const total = s.disk.used + s.disk.avail;
        res.push(['Диск', h('div', null, fmtBytes(s.disk.used) + ' из ' + fmtBytes(total) + ' (свободно ' + fmtBytes(s.disk.avail) + ')',
          total ? h('div', { class: 'meter' }, h('i', { style: 'width:' + Math.min(100, Math.round(s.disk.used / total * 100)) + '%' })) : null,
          h('div', { class: 'muted small mono' }, s.disk.name))]);
      }
      if (res.length) parts.push(h('h3', { class: 'mt' }, 'Потребление'), h('dl', { class: 'kv' }, res.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])));
      else if (env.status !== 1) parts.push(h('p', { class: 'muted small mt' }, 'Окружение остановлено.'));
      parts.push(h('div', { class: 'muted small mt' }, 'Обновляется каждые 6 секунд; скорость считается между замерами.'));
      fill(body, parts);
      prev = s;
    } catch (err) {
      fill(body, h('div', { class: 'muted' }, err.message));
    } finally { busy = false; }
  };
  return { el, update };
}

function snapshotCard(e) {
  const enc = encodeURIComponent(e.jname);
  const url = '/api/envs/' + enc + '/snapshots';
  const body = h('div', null, h('div', { class: 'muted' }, 'Загрузка списка снимков…'));
  const count = h('span', { class: 'tag' }, '…');
  const card = { dirty: false };
  let view = 'graph';
  let order = []; // snapshot names, oldest first, from the last load
  const after = async (p) => { try { await p; card.dirty = true; } catch (err) { fail(err); } };
  const snapOp = (mode, snap) => {
    const titles = { create: 'Создать снимок', rollback: 'Откатить к снимку', destroy: 'Удалить снимок', destroyall: 'Удалить все снимки', try: 'Открыть снимок отдельной клеткой' };
    let nameIn = null, saveBox = null, saveName = null, newIn = null, keepBox = null, keepIn = null, startBox = null;
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-T:]/g, '');
    const parts = [];
    if (mode === 'create') {
      nameIn = h('input', { placeholder: 'необязательно: имя снимка (латиница, цифры, _.-)', autocomplete: 'off' });
      parts.push(h('p', { class: 'muted small' }, 'Снимок фиксирует текущее состояние данных. Пустое имя — по дате и времени.'), nameIn);
    } else if (mode === 'rollback') {
      const i = order.indexOf(snap);
      const newer = i >= 0 ? order.slice(i + 1) : [];
      parts.push(h('div', { class: 'banner warn' }, 'Данные вернутся к состоянию снимка ', h('b', null, snap), '. Изменения после него будут потеряны',
        newer.length ? [', а более новые снимки удалены: ', h('b', null, newer.join(', '))] : '', '. ',
        e.status === 1 ? 'Окружение запущено: на время отката оно будет остановлено и затем запущено снова.' : ''));
      if (e.emulator === 'jail') {
        saveName = h('input', { value: e.jname + '_' + new Date().toISOString().slice(0, 10).replace(/-/g, ''), autocomplete: 'off', spellcheck: 'false' });
        saveBox = h('input', { type: 'checkbox', id: 'save_branch' });
        parts.push(h('div', { class: 'field check' }, saveBox, h('label', { for: 'save_branch' }, 'Сохранить текущее состояние как ветку (новая клетка)')),
          h('div', { class: 'field' }, h('label', null, 'Имя клетки для ветки'), saveName,
            h('div', { class: 'help' }, 'Копия делается через rsync до отката, поэтому не зависит от удаляемых снимков. Появится на схеме как ветка.')));
        saveName.disabled = true;
        saveBox.addEventListener('change', () => { saveName.disabled = !saveBox.checked; });
        parts.push(h('p', { class: 'muted small' }, 'Хотите вернуться к снимку, не теряя текущее состояние? Закройте это окно и нажмите «Открыть отдельно»: снимок запустится рядом как клон ZFS, а эта клетка и все её снимки останутся как есть.'));
      }
    } else if (mode === 'try') {
      newIn = h('input', { value: e.jname + '_' + snap.replace(/[^A-Za-z0-9_]/g, '_'), autocomplete: 'off', spellcheck: 'false' });
      keepIn = h('input', { value: 'before_' + stamp, autocomplete: 'off', spellcheck: 'false' });
      keepBox = h('input', { type: 'checkbox', id: 'keep_snap', checked: true });
      startBox = h('input', { type: 'checkbox', id: 'try_start', checked: true });
      keepBox.addEventListener('change', () => { keepIn.disabled = !keepBox.checked; });
      parts.push(h('p', null, 'Состояние снимка ', h('b', null, snap), ' откроется как новая клетка. Это клон ZFS: создаётся мгновенно и почти не занимает места, пока в нём ничего не меняли.'),
        h('p', { class: 'muted small' }, e.jname + ' продолжит работать как сейчас, все её снимки сохранятся. Чтобы вернуться к текущему состоянию, просто удалите новую клетку. Пока она существует, откатить ' + e.jname + ' к снимку старше ' + snap + ' не получится: ZFS не удаляет снимок, от которого есть клон.'),
        h('div', { class: 'field' }, h('label', null, 'Имя новой клетки'), newIn),
        h('div', { class: 'field check' }, keepBox, h('label', { for: 'keep_snap' }, 'Сначала сделать снимок текущего состояния ' + e.jname)),
        h('div', { class: 'field' }, keepIn, h('div', { class: 'help' }, 'Отметка «до проверки» на схеме: к ней можно будет откатиться или открыть её так же.')),
        h('div', { class: 'field check' }, startBox, h('label', { for: 'try_start' }, 'Запустить новую клетку сразу')));
    } else if (mode === 'destroy') {
      parts.push(h('p', null, 'Снимок ', h('b', null, snap), ' будет удалён без возможности восстановления.'));
    } else {
      parts.push(h('div', { class: 'banner warn' }, 'Будут удалены все снимки ' + e.jname + '.'));
    }
    modal(titles[mode] + ' — ' + e.jname, h('div', null, parts), [
      { text: 'Отмена' },
      { text: mode === 'try' ? 'Открыть' : titles[mode], class: mode === 'create' || mode === 'try' ? 'primary' : 'danger', onClick: async () => {
        const req = { mode, snapname: mode === 'create' ? nameIn.value.trim() : snap || '' };
        if (saveBox && saveBox.checked) req.save_as = saveName.value.trim();
        if (mode === 'try') {
          req.new = newIn.value.trim();
          req.start = startBox.checked;
          if (keepBox.checked) req.keep = keepIn.value.trim();
        }
        try { await runAction('POST', url, req); card.dirty = true; } catch (err) {
          if (err.field === 'save_as' && saveName) { saveName.focus(); toast(err.message, 'err'); return false; }
          const inField = { new: newIn, keep: keepIn }[err.field];
          if (inField) { inField.focus(); toast(err.message, 'err'); return false; }
          fail(err);
        }
      } },
    ]);
  };
  const locationRow = (s, cols) => h('tr', { class: 'snap-loc', hidden: true }, h('td', { colspan: cols },
    h('dl', { class: 'kv' },
      h('dt', null, 'Снимок ZFS'), h('dd', null, h('code', { class: 'mono' }, s.dataset + '@' + s.name), ' ', copyBtn(s.dataset + '@' + s.name)),
      h('dt', null, 'Набор данных'), h('dd', { class: 'mono' }, s.dataset),
      s.path ? [h('dt', null, 'Файлы снимка'), h('dd', null, h('code', { class: 'mono' }, s.path), ' ', copyBtn(s.path))] : null),
    h('div', { class: 'muted small' }, s.path
      ? 'Каталог доступен только для чтения: из него можно скопировать отдельные файлы, не откатывая всю клетку (например, cp ' + s.path + '/etc/rc.conf /tmp/).'
      : 'Снимок диска ВМ; файлы внутри доступны после клонирования или отката.')));
  const actions = (name) => [
    can('admin') && e.emulator === 'jail' ? h('button', { class: 'sm', type: 'button', title: 'Запустить снимок рядом как новую клетку, не трогая текущую', onclick: () => snapOp('try', name) }, 'Открыть отдельно') : null,
    can('admin') ? h('button', { class: 'sm', type: 'button', onclick: () => snapOp('rollback', name) }, 'Откатить') : null,
    can('admin') ? h('button', { class: 'sm danger', type: 'button', onclick: () => snapOp('destroy', name) }, 'Удалить') : null];

  const loadTable = async () => {
    const r = await api('GET', url);
    const list = r.snapshots || [];
    order = list.map((s) => s.name);
    count.textContent = String(list.length);
    if (!list.length) {
      return [r.error ? h('div', { class: 'banner warn' }, r.error) : null,
        h('div', { class: 'empty' }, 'Снимков пока нет.', r.text ? h('pre', { class: 'mono small' }, r.text) : null)];
    }
    const rows = [];
    for (const s of list) {
      const loc = locationRow(s, 5);
      rows.push(h('tr', null,
        h('td', null, h('div', { class: 'mono' }, s.name)),
        h('td', null, s.created || '—'),
        h('td', null, s.refer || '—'),
        h('td', null, s.used ? fmtBytes(s.used) : '—'),
        h('td', { class: 'actions' }, h('div', { class: 'btn-group' },
          h('button', { class: 'sm', type: 'button', onclick: () => { loc.hidden = !loc.hidden; } }, 'Расположение'), actions(s.name)))), loc);
    }
    return [r.error ? h('div', { class: 'banner warn' }, r.error) : null,
      h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Имя'), h('th', null, 'Создан'), h('th', { title: 'Объём данных на момент снимка' }, 'Данные'),
          h('th', { title: 'Место, которое освободится при удалении снимка' }, 'Занимает'), h('th', null, ''))),
        h('tbody', null, rows)))];
  };

  const loadGraph = async () => {
    const g = await api('GET', url + '/graph');
    const snaps = g.snapshots || [];
    order = snaps.map((s) => s.name);
    count.textContent = String(snaps.length);
    if (g.error && !snaps.length) return h('div', { class: 'banner warn' }, g.error);
    const details = h('div', { class: 'snap-detail' }, h('div', { class: 'muted small' }, 'Нажмите на точку на схеме, чтобы увидеть подробности и действия.'));
    const select = (s) => {
      const loc = { name: s.name, dataset: g.dataset, path: null };
      fill(details, h('div', { class: 'row' }, h('b', { class: 'mono' }, s.name), s.cbsd ? null : h('span', { class: 'tag', title: 'Снимок сделан не через CBSD' }, 'ZFS'),
        h('span', { style: 'flex:1' }), s.cbsd ? actions(s.name) : null),
        h('dl', { class: 'kv mt' },
          h('dt', null, 'Создан'), h('dd', null, fmtTime(new Date(s.created * 1000).toISOString())),
          h('dt', null, 'Изменений с прошлого снимка'), h('dd', null, fmtBytes(s.written)),
          h('dt', null, 'Данные в снимке'), h('dd', null, fmtBytes(s.refer)),
          h('dt', null, 'Освободится при удалении'), h('dd', null, fmtBytes(s.used)),
          h('dt', null, 'Снимок ZFS'), h('dd', null, h('code', { class: 'mono' }, loc.dataset + '@' + s.name), ' ', copyBtn(loc.dataset + '@' + s.name))));
    };
    // Recorded rollbacks are only the web UI's notes: forgetting them changes nothing in ZFS.
    const removeEvents = async (ats) => {
      const q = ats.map((a) => 'at=' + encodeURIComponent(a)).join('&');
      await api('DELETE', url + '/history' + (q ? '?' + q : ''));
      load();
    };
    const when = (at) => new Date(at).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
    const forget = (ev) => modal('Убрать со схемы', h('p', null, 'Линия отката к ', h('b', null, ev.to), ' (' + when(ev.at) + ') и удалённые при нём снимки исчезнут со схемы. Сами снимки уже удалены, на данные это не влияет.'), [
      { text: 'Отмена' },
      { text: 'Убрать', class: 'danger', onClick: async () => { try { await removeEvents([ev.at]); } catch (err) { fail(err); } } },
    ]);
    const events = (g.history || []).slice().reverse(); // newest first
    const manage = () => {
      const boxes = [];
      const rows = events.map((ev) => {
        const box = h('input', { type: 'checkbox', 'aria-label': 'Выбрать' });
        box.value = ev.at;
        boxes.push(box);
        const lost = (ev.lost || []).map((l) => l.name);
        return h('tr', { onclick: (x) => { if (x.target !== box) box.checked = !box.checked; sync(); } },
          h('td', null, box),
          h('td', { class: 'nowrap' }, when(ev.at)),
          h('td', null, ev.type === 'try' ? 'открыт отдельно: ' : '↺ откат к ', h('b', { class: 'mono' }, ev.to)),
          h('td', { class: 'small' }, lost.length ? h('span', { class: 'mono' }, lost.join(', ')) : h('span', { class: 'muted' }, '—')),
          h('td', { class: 'small' }, ev.branch ? h('span', { class: 'mono' }, ev.branch) : h('span', { class: 'muted' }, '—')),
          h('td', { class: 'small' }, ev.user));
      });
      const all = h('input', { type: 'checkbox', 'aria-label': 'Выбрать все' });
      const counter = h('span', { class: 'muted small' }, '');
      const sync = () => {
        const n = boxes.filter((b) => b.checked).length;
        all.checked = n === boxes.length && n > 0;
        all.indeterminate = n > 0 && n < boxes.length;
        counter.textContent = n ? 'выбрано: ' + n : '';
      };
      all.addEventListener('change', () => { for (const b of boxes) b.checked = all.checked; sync(); });
      for (const b of boxes) b.addEventListener('change', sync);
      modal('Управление откатами — ' + e.jname, h('div', null,
        h('p', { class: 'muted small' }, 'Отметьте записи, которые не нужно показывать на схеме. Удаляется только запись в журнале веб-интерфейса: снимки и данные это не затрагивает.'),
        h('div', { class: 'table-wrap' }, h('table', { class: 'pick' },
          h('thead', null, h('tr', null, h('th', null, all), h('th', null, 'Когда'), h('th', null, 'Действие'), h('th', null, 'Удалённые снимки'), h('th', null, 'Сохранено как'), h('th', null, 'Кто'))),
          h('tbody', null, rows))),
        h('div', { class: 'mt' }, counter)), [
        { text: 'Закрыть' },
        { text: 'Удалить выбранные', class: 'danger', onClick: async () => {
          const ats = boxes.filter((b) => b.checked).map((b) => b.value);
          if (!ats.length) { toast('Ничего не выбрано', 'err'); return false; }
          try { await removeEvents(ats); toast('Убрано записей: ' + ats.length); } catch (err) { fail(err); return false; }
        } },
      ], { wide: true });
    };
    const svg = snapshotGraphSVG(g, select, can('operator') ? forget : null);
    return [g.error ? h('div', { class: 'banner warn' }, g.error) : null,
      h('div', { class: 'graph-wrap' }, svg),
      h('div', { class: 'row' }, graphLegend(), h('span', { style: 'flex:1' }),
        events.length && can('operator') ? h('button', { class: 'sm', type: 'button', title: 'Выбрать, какие прошлые откаты показывать на схеме', onclick: manage }, 'Управление откатами (' + events.length + ')') : null),
      details];
  };

  const load = async () => {
    card.dirty = false;
    fill(body, h('div', { class: 'muted' }, 'Загрузка…'));
    try { fill(body, view === 'graph' ? await loadGraph() : await loadTable()); } catch (err) { fill(body, h('div', { class: 'muted' }, err.message)); }
  };
  const viewBtn = (v, text) => h('button', { class: 'sm' + (view === v ? ' active' : ''), type: 'button', 'data-view': v, onclick: (ev) => {
    view = v;
    for (const b of ev.target.parentNode.children) b.classList.toggle('active', b.dataset.view === v);
    load();
  } }, text);
  card.el = h('section', { class: 'card mt' },
    h('div', { class: 'row', style: 'margin-bottom:12px' }, h('h2', { style: 'margin:0' }, 'Снимки ZFS'), count,
      h('div', { class: 'seg' }, viewBtn('graph', 'Схема'), viewBtn('table', 'Таблица')), h('span', { style: 'flex:1' }),
      h('button', { class: 'sm', type: 'button', onclick: load }, '↻ Обновить'),
      can('operator') ? h('button', { class: 'sm primary', type: 'button', onclick: () => snapOp('create') }, '+ Создать снимок') : null,
      can('admin') ? h('button', { class: 'sm danger', type: 'button', onclick: () => snapOp('destroyall') }, 'Удалить все') : null),
    body);
  card.load = load;
  load();
  return card;
}

function graphLegend() {
  const item = (cls, text) => h('span', { class: 'lg' }, h('i', { class: cls }), text);
  return h('div', { class: 'graph-legend small muted' },
    item('lg-main', 'снимки окружения'), item('lg-now', 'текущее состояние'), item('lg-zfs', 'снимок не из CBSD'),
    item('lg-branch', 'ветка: окружение, созданное из снимка'), item('lg-ghost', 'потеряно при откате'),
    h('span', null, 'Размер точки — объём изменений с предыдущего снимка.'));
}

// snapshotGraphSVG draws the snapshot history: the main line (oldest → now),
// clones branching off snapshots, and lines abandoned by rollbacks.
const graphHistoryShown = (ev) => ev.type === 'rollback' && (ev.lost && ev.lost.length || ev.branch);

function snapshotGraphSVG(g, onSelect, onForget) {
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs, ...kids) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) n.setAttribute(k, v);
    for (const c of kids) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  };
  const link = (href, ...kids) => el('a', { href }, ...kids);
  const snaps = g.snapshots || [];
  const STEP = 150, X0 = g.parent ? 210 : 70, Y0 = 92, LANE = 64;
  const radius = (bytes) => 6 + Math.min(12, Math.max(0, Math.log2((bytes || 0) / 1048576 + 1) * 1.6));
  const short = (s, n = 20) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
  const day = (t) => { const d = new Date(t * 1000); return d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit' }) + ' ' + d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }); };
  const pos = {};
  snaps.forEach((s, i) => { pos[s.name] = X0 + i * STEP; });
  const nowX = X0 + snaps.length * STEP;
  const lanes = []; // extra rows under the main line
  const branches = g.branches || [];
  const history = (g.history || []).filter(graphHistoryShown);
  let lane = 0;
  let maxX = nowX + 80;
  const layers = { lines: el('g'), nodes: el('g'), labels: el('g') };
  const curve = (x1, y1, x2, y2, cls) => layers.lines.append(el('path', { d: `M${x1},${y1} L${x1},${y2 - 22} Q${x1},${y2} ${x1 + 22},${y2} L${x2},${y2}`, class: cls }));
  const pill = (x, y, text, href, cls, title) => {
    const w = Math.max(70, text.length * 7.2 + 22);
    const g2 = el('g', { class: 'pill-node ' + (cls || '') }, el('title', null, title || text),
      el('rect', { x, y: y - 13, width: w, height: 26, rx: 13 }), el('text', { x: x + 11, y: y + 4 }, text));
    layers.nodes.append(href ? link(href, g2) : g2);
    maxX = Math.max(maxX, x + w + 20);
    return x + w;
  };

  // Parent: this environment was itself cloned from another snapshot.
  if (g.parent) {
    const p = g.parent;
    pill(14, Y0, '⎇ ' + short((p.env || p.dataset) + '@' + p.snap, 22), p.env ? '#/env/' + encodeURIComponent(p.env) : null, 'parent', 'Создано из снимка ' + p.dataset + '@' + p.snap);
    layers.lines.append(el('line', { x1: 170, y1: Y0, x2: X0, y2: Y0, class: 'g-main dashed' }));
  }
  // Main line.
  if (snaps.length) layers.lines.append(el('line', { x1: X0, y1: Y0, x2: nowX, y2: Y0, class: 'g-main' }));
  snaps.forEach((s) => {
    const x = pos[s.name];
    const c = el('circle', { cx: x, cy: Y0, r: radius(s.written), class: 'g-node' + (s.cbsd ? '' : ' zfs'), tabindex: 0 });
    c.append(el('title', null, s.name + '\n' + day(s.created) + '\nизменений: ' + fmtBytes(s.written)));
    const pick = () => { for (const n of layers.nodes.querySelectorAll('.sel')) n.classList.remove('sel'); c.classList.add('sel'); onSelect(s); };
    c.addEventListener('click', pick);
    c.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });
    layers.nodes.append(c);
    // Labels sit above the line so branch curves below never cross them.
    layers.labels.append(el('text', { x, y: Y0 - 54, class: 'g-name' }, short(s.name)),
      el('text', { x, y: Y0 - 39, class: 'g-sub' }, day(s.created)),
      el('text', { x, y: Y0 - 25, class: 'g-sub' }, '+' + fmtBytes(s.written)));
  });
  // Current state.
  const cur = g.current || {};
  layers.nodes.append(el('rect', { x: nowX - 9, y: Y0 - 9, width: 18, height: 18, rx: 4, class: 'g-now' }, el('title', null, 'Текущее состояние')));
  layers.labels.append(el('text', { x: nowX, y: Y0 - 54, class: 'g-name' }, 'сейчас'),
    el('text', { x: nowX, y: Y0 - 39, class: 'g-sub' }, snaps.length ? 'изменено после снимка' : 'снимков нет'),
    el('text', { x: nowX, y: Y0 - 25, class: 'g-sub' }, snaps.length ? '+' + fmtBytes(cur.written) : ''));

  // Branches: clones made from a snapshot (jclone, or zfs clone).
  for (const b of branches) {
    const x = pos[b.snap];
    if (x == null) continue;
    lane++;
    const y = Y0 + 10 + lane * LANE;
    curve(x, Y0, x + 60, y, 'g-branch');
    pill(x + 60, y, '⎇ ' + short(b.env || b.dataset, 24), b.env ? '#/env/' + encodeURIComponent(b.env) : null, 'branch',
      'Создано из ' + b.snap + (b.env ? ': окружение ' + b.env : ': набор ' + b.dataset));
  }
  // Rollbacks: the snapshots they destroyed stay visible as an abandoned line.
  for (const ev of history) {
    lane++;
    const y = Y0 + 10 + lane * LANE;
    const x = pos[ev.to] != null ? pos[ev.to] : X0;
    curve(x, Y0, x + 60, y, 'g-ghost');
    let cx = x + 60;
    for (const l of ev.lost || []) {
      cx += 70;
      layers.lines.append(el('line', { x1: cx - 70, y1: y, x2: cx, y2: y, class: 'g-ghost' }));
      layers.nodes.append(el('circle', { cx, cy: y, r: radius(l.written), class: 'g-node ghost' }, el('title', null, l.name + ' (удалён при откате)' + (l.created ? '\n' + l.created : ''))));
      layers.labels.append(el('text', { x: cx, y: y - 18, class: 'g-sub' }, short(l.name, 16)));
    }
    cx += 40;
    layers.lines.append(el('line', { x1: cx - 40, y1: y, x2: cx, y2: y, class: 'g-ghost' }));
    const when = new Date(ev.at).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const end = ev.branch
      ? pill(cx, y, '⎇ сохранено: ' + ev.branch, '#/env/' + encodeURIComponent(ev.branch), 'branch', 'Состояние до отката сохранено как клетка ' + ev.branch)
      : cx;
    const label = '↺ откат к ' + ev.to + ' · ' + when + ' · ' + ev.user;
    layers.labels.append(el('text', { x: end + 10, y: y + 4, class: 'g-sub left' }, label));
    maxX = Math.max(maxX, end + 20 + label.length * 6.5);
    if (onForget) {
      const bx = end + 24 + label.length * 6.5;
      const del = el('g', { class: 'g-del', tabindex: 0, role: 'button', 'aria-label': 'Убрать со схемы' },
        el('title', null, 'Убрать этот откат со схемы'), el('circle', { cx: bx, cy: y, r: 10 }), el('text', { x: bx, y: y + 4 }, '✕'));
      const go = () => onForget(ev);
      del.addEventListener('click', go);
      del.addEventListener('keydown', (k) => { if (k.key === 'Enter' || k.key === ' ') { k.preventDefault(); go(); } });
      layers.nodes.append(del);
      maxX = Math.max(maxX, bx + 20);
    }
  }
  const width = Math.ceil(maxX);
  const height = Y0 + 40 + lane * LANE;
  return el('svg', { class: 'snap-graph', width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Схема снимков' },
    layers.lines, layers.nodes, layers.labels);
}


function editEnv(e) {
  const fields = [{ name: 'astart', label: 'Автозапуск при загрузке хоста', type: 'checkbox', value: e.astart, full: true }];
  if (e.emulator === 'jail') {
    fields.push({ name: 'ip4_addr', label: 'IP-адреса', value: e.ip4_addr, help: 'DHCP или 10.0.0.5/24, через запятую' },
      { name: 'host_hostname', label: 'Hostname', value: e.host_hostname });
  } else {
    fields.push({ name: 'vm_cpus', label: 'vCPU', type: 'number', value: e.vm_cpus, min: 1, max: 256 },
      { name: 'vm_ram', label: 'RAM', value: Math.round((e.vm_ram || 0) / 1048576) + 'm', help: 'например 2g или 512m' });
  }
  const f = buildForm(fields);
  const note = e.status === 1 ? h('div', { class: 'banner info' }, 'Часть изменений применится после перезапуска.') : null;
  modal('Настройки — ' + e.jname, h('div', null, note, f.form), [
    { text: 'Отмена' },
    { text: 'Сохранить', class: 'primary', onClick: async () => {
      const v = f.values();
      const body = { astart: v.astart };
      if (e.emulator === 'jail') {
        if (v.ip4_addr !== (e.ip4_addr || '')) body.ip4_addr = v.ip4_addr;
        if (v.host_hostname !== (e.host_hostname || '')) body.host_hostname = v.host_hostname;
      } else {
        if (v.vm_cpus !== e.vm_cpus) body.vm_cpus = v.vm_cpus;
        if (v.vm_ram !== Math.round((e.vm_ram || 0) / 1048576) + 'm') body.vm_ram = v.vm_ram;
      }
      try { await runAction('PATCH', '/api/envs/' + encodeURIComponent(e.jname), body); } catch (err) { f.showError(err); return false; }
    } },
  ]);
}

function cloneEnv(e) {
  const fields = [{ name: 'new', label: 'Имя копии', value: e.jname + '_clone', full: true }];
  if (e.emulator === 'jail') fields.push({ name: 'host_hostname', label: 'Hostname копии', full: true, help: 'по умолчанию — имя копии' });
  const f = buildForm(fields);
  modal('Клонировать ' + e.jname, h('div', null, e.status === 1 ? h('div', { class: 'banner info' }, e.emulator === 'jail' ? 'Клетка запущена: на время копирования она будет остановлена и затем запущена снова.' : 'Рекомендуется остановить окружение перед клонированием.') : null, f.form), [
    { text: 'Отмена' },
    { text: 'Клонировать', class: 'primary', onClick: async () => {
      try { await runAction('POST', '/api/envs/' + encodeURIComponent(e.jname) + '/clone', f.values()); } catch (err) { f.showError(err); return false; }
    } },
  ]);
}

async function createJail() {
  let bases = [];
  try { bases = (await api('GET', '/api/bases')).bases || []; } catch (_) { /* optional */ }
  const vers = [['native', 'native — как у хоста']];
  for (const b of bases) if (b.ver && !vers.some(([v]) => v === String(b.ver))) vers.push([String(b.ver), String(b.ver) + (b.arch ? ' (' + b.arch + ')' : '')]);
  const f = buildForm([
    { name: 'jname', label: 'Имя клетки', placeholder: 'web1', help: 'латиница, цифры и _' },
    { name: 'host_hostname', label: 'Hostname', placeholder: 'web1.example.org', help: 'по умолчанию — имя клетки' },
    { name: 'ip4_addr', label: 'IP-адрес', value: 'DHCP', help: 'DHCP — взять свободный из пула CBSD, или 10.0.0.5/24' },
    { name: 'ver', label: 'База FreeBSD', type: 'select', options: vers, value: 'native', help: 'базы скачиваются в разделе «Базы FreeBSD»' },
    { name: 'pkglist', label: 'Пакеты для установки', placeholder: 'nginx git', full: true, help: 'через пробел; установятся при создании' },
    { name: 'pkg_bootstrap', label: 'Подготовить pkg', type: 'checkbox', value: true },
    { name: 'baserw', label: 'Своя копия базы (rw)', type: 'checkbox' },
    { name: 'vnet', label: 'VNET (свой сетевой стек)', type: 'checkbox' },
    { name: 'interface', label: 'Интерфейс', value: 'auto' },
    { name: 'astart', label: 'Автозапуск', type: 'checkbox', value: true },
    { name: 'runasap', label: 'Запустить сразу после создания', type: 'checkbox', value: true },
  ]);
  modal('Новая клетка', f.form, [
    { text: 'Отмена' },
    { text: 'Создать', class: 'primary', onClick: async () => {
      try { await runAction('POST', '/api/jails', f.values()); } catch (err) { f.showError(err); return false; }
    } },
  ], { wide: true, sticky: true });
}

async function createVM(emu) {
  const [{ profiles }, isoList] = await Promise.all([api('GET', '/api/profiles?emulator=' + emu), api('GET', '/api/isos').catch(() => ({ isos: [] }))]);
  const isoOptions = [['', 'из профиля (CBSD скачает сам)'], ...isoList.isos.filter((i) => i.usable).map((i) => [i.media, (i.file || i.media) + ' · ' + fmtBytes(i.size)])];
  if (!profiles.length) { toast('Профили ОС не найдены. Проверьте dist_dir и workdir в настройках.', 'err'); return; }
  const types = [...new Set(profiles.map((p) => p.vm_os_type))];
  const profOptions = (t) => profiles.filter((p) => p.vm_os_type === t).map((p) => [p.vm_profile, (p.long_description || p.vm_profile) + (p.cloud ? ' ☁' : '')]);
  const isCloud = (v) => profiles.some((p) => p.vm_profile === v.vm_os_profile && p.vm_os_type === v.vm_os_type && p.cloud);
  const defType = types.includes('freebsd') ? 'freebsd' : types[0];
  const fields = [
    { name: 'jname', label: 'Имя ВМ', placeholder: 'vm1', help: 'латиница, цифры и _' },
    { name: 'vm_os_type', label: 'Тип ОС', type: 'select', options: types.map((t) => [t, t]), value: defType },
    { name: 'vm_os_profile', label: 'Профиль (дистрибутив)', type: 'select', options: profOptions(defType), full: true, help: '☁ — облачный образ с cloud-init: готов к работе без установки' },
    { name: 'iso', label: 'Установочный ISO', type: 'select', options: isoOptions, full: true, show: (v) => !isCloud(v),
      help: 'свой образ из раздела «Образы и ISO»; профиль задаёт настройки ВМ для этой ОС' },
    { name: 'vm_cpus', label: 'vCPU', type: 'number', value: 1, min: 1, max: 256 },
    { name: 'vm_ram', label: 'RAM', value: '1g', help: 'например 1g, 512m' },
    { name: 'imgsize', label: 'Размер диска', value: '20g' },
    { name: 'ip4_addr', label: 'IP-адрес', value: 'DHCP' },
    { name: 'interface', label: 'Интерфейс / мост', value: 'auto' },
  ];
  if (emu === 'bhyve') fields.push(
    { name: 'bhyve_vnc_tcp_bind', label: 'VNC слушает', type: 'select', options: [['127.0.0.1', '127.0.0.1 (только через SSH-туннель)'], ['0.0.0.0', '0.0.0.0 (все интерфейсы)']], value: '127.0.0.1' },
    { name: 'vnc_password', label: 'Пароль VNC', type: 'password', autocomplete: 'new-password', help: 'обязательно при 0.0.0.0' });
  fields.push(
    { name: 'ci_ip4_addr', label: 'cloud-init: IP', placeholder: '10.0.0.50/24', show: isCloud },
    { name: 'ci_gw4', label: 'cloud-init: шлюз', placeholder: '10.0.0.1', show: isCloud },
    { name: 'ci_user_add', label: 'cloud-init: пользователь', placeholder: 'admin', show: isCloud },
    { name: 'ci_user_pubkey', label: 'cloud-init: SSH-ключ', type: 'textarea', full: true, placeholder: 'ssh-ed25519 AAAA… user@host', show: isCloud },
    { name: 'astart', label: 'Автозапуск', type: 'checkbox', value: false },
    { name: 'runasap', label: 'Запустить сразу после создания', type: 'checkbox', value: true });
  const f = buildForm(fields);
  f.els.vm_os_type.input.addEventListener('change', () => {
    const sel = f.els.vm_os_profile.input;
    clear(sel).append(...profOptions(f.els.vm_os_type.input.value).map(([v, l]) => h('option', { value: v }, l)));
    f.refresh();
  });
  modal(emu === 'xen' ? 'Новая ВМ Xen' : 'Новая ВМ bhyve', f.form, [
    { text: 'Отмена' },
    { text: 'Создать', class: 'primary', onClick: async () => {
      const v = f.values();
      if (v.bhyve_vnc_tcp_bind === '0.0.0.0' && !v.vnc_password) { f.showError({ field: 'vnc_password', message: 'Задайте пароль, если VNC доступен извне' }); return false; }
      for (const k of ['ci_ip4_addr', 'ci_gw4', 'ci_user_add', 'ci_user_pubkey', 'vnc_password', 'iso']) if (v[k] === '') delete v[k];
      try { await runAction('POST', '/api/vms/' + emu, v); } catch (err) { f.showError(err); return false; }
    } },
  ], { wide: true, sticky: true });
}

// ---------- images, bases, nodes ----------
function rowsTable(rows, cols, empty) {
  if (!rows.length) return h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, empty));
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, cols.map(([, t]) => h('th', null, t)))),
    h('tbody', null, rows.map((r) => h('tr', null, cols.map(([k, , fmt]) => h('td', { class: k === 'path' ? 'mono wrap' : '' }, fmt ? fmt(r[k]) : r[k] == null || r[k] === '0' ? '—' : String(r[k]))))))));
}

// The upload in progress survives page changes: it is an XHR owned by the tab.
let isoUpload = null; // { name, loaded, total, started, xhr, onChange }

// isoFileName turns a local file name into one the server accepts.
function isoFileName(n) {
  let base = String(n || '').replace(/\.iso$/i, '').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 59);
  return base ? base + '.iso' : '';
}

function uploadISO(file, name, sha256) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    isoUpload = { name, loaded: 0, total: file.size, started: Date.now(), xhr, onChange: null };
    const changed = () => { if (isoUpload && isoUpload.onChange) isoUpload.onChange(); };
    const done = (fn, v) => { isoUpload = null; window.removeEventListener('beforeunload', guard); fn(v); refreshCurrent(); };
    const guard = (e) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', guard);
    xhr.open('POST', '/api/isos/upload?name=' + encodeURIComponent(name));
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-CSRF-Token', state.csrf);
    if (sha256) xhr.setRequestHeader('X-Content-SHA256', sha256);
    xhr.upload.onprogress = (e) => { if (isoUpload) { isoUpload.loaded = e.loaded; changed(); } };
    xhr.upload.onload = () => { if (isoUpload) { isoUpload.loaded = isoUpload.total; isoUpload.checking = true; changed(); } };
    xhr.onload = () => {
      let d = {};
      try { d = JSON.parse(xhr.responseText); } catch (_) { /* not JSON */ }
      if (xhr.status === 200) done(resolve, d);
      else done(reject, Object.assign(new Error(d.error || ('Ошибка ' + xhr.status)), { field: d.field }));
    };
    xhr.onerror = () => done(reject, new Error('Соединение прервано'));
    xhr.onabort = () => done(reject, Object.assign(new Error('Загрузка отменена'), { silent: true }));
    xhr.send(file);
  });
}

function isoUploadCard(info) {
  const card = h('div', { class: 'card' });
  const render = () => {
    if (isoUpload) {
      const u = isoUpload;
      const pct = u.total ? Math.floor(u.loaded * 100 / u.total) : 0;
      const secs = (Date.now() - u.started) / 1000;
      const speed = secs > 0 ? u.loaded / secs : 0;
      const left = speed > 0 ? Math.round((u.total - u.loaded) / speed) : 0;
      fill(card, h('h2', null, 'Загрузка ' + u.name),
        h('div', { class: 'meter' }, h('i', { style: 'width:' + pct + '%' })),
        h('div', { class: 'row mt' },
          h('span', null, u.checking ? 'Проверка и регистрация в CBSD…' : fmtBytes(u.loaded) + ' из ' + fmtBytes(u.total) + ' (' + pct + '%)'),
          !u.checking && speed ? h('span', { class: 'muted small' }, fmtBytes(speed) + '/с, осталось ' + fmtUptimeShort(left)) : null,
          h('span', { style: 'flex:1' }),
          u.checking ? null : h('button', { class: 'danger sm', type: 'button', onclick: () => u.xhr.abort() }, 'Отменить')),
        h('p', { class: 'muted small' }, 'Не закрывайте вкладку до окончания загрузки.'));
      u.onChange = render;
      return;
    }
    const fileInput = h('input', { type: 'file', accept: '.iso,application/x-iso9660-image' });
    const f = buildForm([
      { name: 'name', label: 'Имя файла на сервере', placeholder: 'FreeBSD-14.3-RELEASE-amd64-disc1.iso', help: 'латиница, цифры, . _ -, окончание .iso' },
      { name: 'sha256', label: 'SHA-256 (необязательно)', placeholder: 'проверить контрольную сумму', help: 'с сайта дистрибутива; файл с другой суммой не сохранится' },
    ]);
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (file) f.els.name.input.value = isoFileName(file.name);
    });
    const btn = h('button', { class: 'primary', type: 'button', disabled: !info.writable, onclick: async () => {
      const file = fileInput.files[0];
      if (!file) { toast('Выберите файл ISO', 'err'); return; }
      if (file.size > info.max_bytes) { toast('Файл больше допустимого (' + fmtBytes(info.max_bytes) + ')', 'err'); return; }
      if (info.free_bytes != null && file.size > info.free_bytes) { toast('Недостаточно места: свободно ' + fmtBytes(info.free_bytes), 'err'); return; }
      const v = f.values();
      try {
        const p = uploadISO(file, v.name, v.sha256);
        render();
        const r = await p;
        toast('Образ ' + r.file + ' загружен (' + fmtBytes(r.size) + ')', 'ok');
      } catch (err) { if (!err.silent) f.showError(err); render(); }
    } }, 'Загрузить');
    fill(card, h('h2', null, 'Загрузить с компьютера'),
      h('div', { class: 'field full' }, fileInput), f.form,
      h('div', { class: 'row mt' }, btn,
        h('span', { class: 'muted small' }, 'до ' + fmtBytes(info.max_bytes) + (info.free_bytes != null ? ', свободно ' + fmtBytes(info.free_bytes) : ''))));
  };
  render();
  return card;
}

function fmtUptimeShort(s) {
  if (s < 60) return s + ' с';
  if (s < 3600) return Math.floor(s / 60) + ' мин';
  return Math.floor(s / 3600) + ' ч ' + Math.floor(s % 3600 / 60) + ' мин';
}

function isoFetchCard(info) {
  const f = buildForm([
    { name: 'url', label: 'Адрес (URL)', placeholder: 'https://download.freebsd.org/…/FreeBSD-14.3-RELEASE-amd64-disc1.iso', full: true },
    { name: 'name', label: 'Имя файла на сервере', placeholder: 'по умолчанию из адреса' },
    { name: 'sha256', label: 'SHA-256 (необязательно)' },
  ]);
  f.els.url.input.addEventListener('change', () => {
    if (f.els.name.input.value) return;
    try { f.els.name.input.value = isoFileName(decodeURIComponent(new URL(f.els.url.input.value).pathname.split('/').pop())); } catch (_) { /* not a URL yet */ }
  });
  return h('div', { class: 'card' }, h('h2', null, 'Скачать по ссылке'), f.form,
    h('div', { class: 'row mt' }, h('button', { class: 'primary', type: 'button', disabled: !info.writable, onclick: async () => {
      const v = f.values();
      if (!v.name) delete v.name;
      if (!v.sha256) delete v.sha256;
      try { await runAction('POST', '/api/isos/fetch', v); } catch (err) { f.showError(err); }
    } }, 'Скачать'), h('span', { class: 'muted small' }, 'сервер скачивает сам, прогресс — в окне задачи')));
}

function isoTable(list) {
  if (!list.length) return h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'ISO-образов пока нет'));
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Имя', 'Размер', 'Подключён к', ''].map((t) => h('th', null, t)))),
    h('tbody', null, list.map((it) => h('tr', null,
      h('td', { class: 'wrap', style: 'min-width:220px' }, h('div', null, it.media || it.file),
        h('div', { class: 'mono muted small', style: 'word-break:break-all' }, it.path),
        h('div', { class: 'row' },
          it.uploaded ? h('span', { class: 'pill run' }, 'загружен через веб') : h('span', { class: 'pill off' }, 'CBSD'),
          !it.registered ? h('span', { class: 'pill warn', title: 'будет зарегистрирован при создании ВМ' }, 'не зарегистрирован') : null)),
      h('td', null, fmtBytes(it.size)),
      h('td', null, it.attached_to.length ? it.attached_to.map((j) => h('a', { href: '#/env/' + encodeURIComponent(j) }, j)).reduce((a, b) => [a, ', ', b]) : '—'),
      h('td', { class: 'actions' }, it.uploaded && can('admin') ? h('button', { class: 'danger sm', type: 'button', disabled: it.attached_to.length > 0,
        title: it.attached_to.length ? 'образ подключён к ВМ' : null,
        onclick: async () => {
          if (!(await confirmDialog('Удалить ' + it.file + '?', 'Файл будет удалён с диска и из списка носителей CBSD.', { danger: true, confirmText: 'Удалить' }))) return;
          try { await api('DELETE', '/api/isos/' + encodeURIComponent(it.file)); toast('Образ удалён', 'ok'); refreshCurrent(); } catch (e) { fail(e); }
        } }, 'Удалить') : null))))));
}

async function pageImages() {
  const main = $('#main');
  const render = async () => {
    const [d, iso] = await Promise.all([api('GET', '/api/images'), api('GET', '/api/isos')]);
    const other = d.media.filter((m) => m.type !== 'iso');
    fill(main, pageHead('Образы и ISO', h('button', { type: 'button', onclick: () => refreshCurrent() }, 'Обновить')),
      h('h2', null, 'ISO-образы'),
      h('p', { class: 'muted' }, 'Установочные образы для ВМ. Выберите образ в поле «Установочный ISO» при создании ВМ; без него CBSD скачает ISO профиля сам.'),
      can('admin') && !iso.writable ? h('div', { class: 'banner warn' }, iso.dir_error || 'Каталог для ISO недоступен') : null,
      can('admin') ? h('div', { class: 'grid cols-2' }, isoUploadCard(iso), isoFetchCard(iso)) : null,
      h('div', { class: 'mt' }, isoTable(iso.isos)),
      h('h2', { class: 'mt' }, 'Образы (images)'),
      rowsTable(d.images, [['name', 'Имя'], ['emulator', 'Эмулятор'], ['size', 'Размер', fmtBytes], ['path', 'Путь'], ['created', 'Создан']], 'Нет зарегистрированных образов'),
      h('h2', { class: 'mt' }, 'Диски'),
      rowsTable(other, [['name', 'Имя'], ['type', 'Тип'], ['jname', 'Подключён к'], ['size', 'Размер', fmtBytes], ['path', 'Путь']], 'Нет зарегистрированных дисков'));
  };
  await render();
  refreshFn = render;
}

async function pageBases() {
  const main = $('#main');
  const render = async () => {
    const d = await api('GET', '/api/bases');
    const form = can('admin') ? (() => {
      const f = buildForm([
        { name: 'ver', label: 'Версия', placeholder: '14.3' },
        { name: 'arch', label: 'Архитектура', type: 'select', options: [['', 'как у хоста'], ['amd64', 'amd64'], ['i386', 'i386'], ['arm64', 'arm64']] },
      ]);
      return h('div', { class: 'card mt' }, h('h2', null, 'Скачать базу'), f.form,
        h('div', { class: 'row mt' }, h('button', { class: 'primary', type: 'button', onclick: async () => {
          try { await runAction('POST', '/api/bases', f.values()); } catch (err) { f.showError(err); }
        } }, 'Скачать')));
    })() : null;
    fill(main, pageHead('Базы FreeBSD'),
      h('p', { class: 'muted' }, 'База — это набор файлов FreeBSD, из которого создаются клетки нужной версии.'),
      rowsTable(d.bases, [['ver', 'Версия'], ['arch', 'Arch'], ['targetarch', 'Target'], ['platform', 'Платформа'], ['stable', 'Ветка', (v) => (String(v) === '1' ? 'STABLE' : 'RELEASE')], ['source', 'Источник'], ['date', 'Дата']], 'Базы не установлены — клетки используют базу хоста (native).'),
      form);
  };
  await render();
}

async function pageNodes() {
  const d = await api('GET', '/api/nodes');
  fill($('#main'), pageHead('Узлы кластера'),
    rowsTable(d.nodes, [['nodename', 'Узел'], ['ip', 'IP'], ['port', 'Порт'], ['status', 'Статус', (v) => (String(v) === '1' ? 'online' : 'offline')], ['idle', 'Последняя связь']], 'Удалённые узлы не добавлены. Добавить узел: cbsd node mode=add node=IP pw=…'));
}

async function pageJobs() {
  const main = $('#main');
  const render = async () => {
    const d = await api('GET', '/api/jobs');
    fill(main, pageHead('Задачи'), h('p', { class: 'muted' }, 'Операции выполняются в фоне; их вывод хранится до перезапуска службы.'), jobsTable(d.jobs || []));
  };
  await render();
  autoRefresh(render, 4000);
}

// ---------- setup ----------
async function pageSetup() {
  const d = await api('GET', '/api/setup');
  const checks = h('div', { class: 'card checks' }, h('h2', null, 'Проверка системы'), h('ul', null, d.checks.map((c) => h('li', null,
    h('span', { class: 'mark ' + (c.ok ? 'ok' : 'bad') }, c.ok ? '✓' : '✗'),
    h('div', null, h('div', null, c.title, c.detail ? h('span', { class: 'muted mono small' }, '  ' + c.detail) : null),
      !c.ok && c.hint ? h('div', { class: 'muted small' }, c.hint) : null)))));
  const content = [pageHead('Установка и настройка'), checks];
  if (can('admin')) {
    const f = buildForm([
      { name: 'workdir', label: 'Рабочий каталог CBSD', value: d.workdir || '/usr/jails', help: 'на ZFS — отдельный датасет' },
      { name: 'nodename', label: 'Имя узла', value: 'auto' },
      { name: 'nodeip', label: 'IP узла', value: 'auto' },
      { name: 'jnameserver', label: 'DNS для клеток', value: '8.8.8.8,8.8.4.4' },
      { name: 'nodeippool', label: 'Пул IP для клеток/ВМ', value: '10.0.0.0/24', help: 'сети через пробел' },
      { name: 'natip', label: 'IP для NAT', value: 'auto' },
      { name: 'nat_enable', label: 'NAT', type: 'select', options: [['pf', 'pf'], ['ipfw', 'ipfw'], ['ipfilter', 'ipfilter'], ['0', 'выключен']], value: 'pf' },
      { name: 'parallel', label: 'Параллельных запусков', type: 'number', value: 5, min: 1, max: 64 },
      { name: 'zfsfeat', label: 'Использовать возможности ZFS', type: 'checkbox', value: true },
      { name: 'fbsdrepo', label: 'Официальные зеркала FreeBSD', type: 'checkbox', value: true },
    ]);
    content.push(h('div', { class: 'card mt' },
      h('h2', null, d.initialized ? 'Повторная инициализация (initenv)' : 'Мастер первичной настройки'),
      d.initialized ? h('div', { class: 'banner info' }, 'CBSD уже инициализирован. Повторный запуск initenv обновит настройки узла (так же делают после обновления CBSD).') : h('p', { class: 'muted' }, 'Заполните параметры и запустите initenv — CBSD создаст рабочий каталог, базы данных и настроит rc.conf.'),
      f.form,
      h('div', { class: 'row mt' }, h('button', { class: 'primary', type: 'button', onclick: async () => {
        if (!(await confirmDialog('Запустить initenv?', 'Будут изменены /etc/rc.conf и настройки CBSD на этом хосте.', { confirmText: 'Запустить' }))) return;
        try { await runAction('POST', '/api/setup/initenv', f.values()); } catch (err) { f.showError(err); }
      } }, 'Запустить initenv'))));
  }
  content.push(h('div', { class: 'card mt' }, h('h2', null, 'Установка с нуля'),
    h('p', { class: 'muted' }, 'На чистом FreeBSD веб-интерфейс и CBSD ставятся одним скриптом из комплекта:'),
    h('pre', { class: 'mono' }, 'fetch -o - https://<ваш-сервер>/install.sh | sh\n# или из исходников:\nsh scripts/install.sh')));
  fill($('#main'), content);
}

// ---------- users / audit / account ----------
async function pageUsers() {
  const d = await api('GET', '/api/users');
  const roles = [['viewer', 'наблюдатель — только просмотр'], ['operator', 'оператор — запуск, остановка, создание'], ['admin', 'администратор — всё, включая удаление']];
  const edit = (u) => {
    const f = buildForm([
      { name: 'name', label: 'Имя', value: u ? u.name : '', full: true },
      { name: 'role', label: 'Роль', type: 'select', options: roles, value: u ? u.role : 'operator', full: true },
      { name: 'password', label: u ? 'Новый пароль (пусто — не менять)' : 'Пароль', type: 'password', autocomplete: 'new-password', full: true, help: 'не короче 10 символов' },
    ]);
    if (u) f.els.name.input.disabled = true;
    modal(u ? 'Пользователь ' + u.name : 'Новый пользователь', f.form, [
      { text: 'Отмена' },
      { text: 'Сохранить', class: 'primary', onClick: async () => {
        const v = f.values();
        try { await api('PUT', '/api/users/' + encodeURIComponent(u ? u.name : v.name), { role: v.role, password: v.password }); } catch (err) { f.showError(err); return false; }
        toast('Сохранено', 'ok'); pageUsers();
      } },
    ]);
  };
  fill($('#main'), pageHead('Пользователи', h('button', { class: 'primary', type: 'button', onclick: () => edit(null) }, '+ Добавить')),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Имя'), h('th', null, 'Роль'), h('th', null, ''))),
      h('tbody', null, d.users.map((u) => h('tr', null, h('td', null, u.name), h('td', null, roleTitle(u.role)),
        h('td', { class: 'actions' }, h('div', { class: 'btn-group' },
          h('button', { class: 'sm', type: 'button', onclick: () => edit(u) }, 'Изменить'),
          u.name !== state.user ? h('button', { class: 'sm danger', type: 'button', onclick: async () => {
            if (!(await confirmDialog('Удалить ' + u.name + '?', 'Все сессии пользователя будут закрыты.', { danger: true, confirmText: 'Удалить' }))) return;
            try { await api('DELETE', '/api/users/' + encodeURIComponent(u.name)); pageUsers(); } catch (err) { fail(err); }
          } }, 'Удалить') : null))))))));
}

async function pageAudit() {
  const d = await api('GET', '/api/audit');
  fill($('#main'), pageHead('Журнал аудита'),
    rowsTable(d.entries, [['time', 'Время', fmtTime], ['user', 'Пользователь'], ['ip', 'IP'], ['event', 'Событие'], ['target', 'Объект'], ['result', 'Результат'],
      ['detail', 'Детали', (v) => (v ? Object.entries(v).filter(([, x]) => x).map(([k, x]) => k + '=' + x).join(' ') : '')]], 'Журнал пуст'));
}

function pageAccount() {
  const f = buildForm([
    { name: 'current', label: 'Текущий пароль', type: 'password', autocomplete: 'current-password', full: true },
    { name: 'new', label: 'Новый пароль', type: 'password', autocomplete: 'new-password', full: true, help: 'не короче 10 символов' },
    { name: 'repeat', label: 'Повторите новый пароль', type: 'password', autocomplete: 'new-password', full: true },
  ]);
  const themeSel = h('select', { onchange: () => setTheme(themeSel.value) }, [['', 'как в системе'], ['light', 'светлая'], ['dark', 'тёмная']].map(([v, l]) => h('option', { value: v }, l)));
  themeSel.value = getTheme();
  fill($('#main'), pageHead('Учётная запись'),
    h('div', { class: 'grid cols-2' },
      h('div', { class: 'card' }, h('h2', null, 'Смена пароля'), f.form, h('div', { class: 'row mt' }, h('button', { class: 'primary', type: 'button', onclick: async () => {
        const v = f.values();
        if (v.new !== v.repeat) { f.showError({ field: 'repeat', message: 'Пароли не совпадают' }); return; }
        try { await api('POST', '/api/me/password', { current: v.current, new: v.new }); toast('Пароль изменён, войдите снова', 'ok'); state.user = null; renderLogin(); } catch (err) { f.showError(err); }
      } }, 'Изменить пароль'))),
      h('div', { class: 'card' }, h('h2', null, 'Оформление'), h('div', { class: 'field' }, h('label', null, 'Тема'), themeSel))));
}

function getTheme() { try { return localStorage.getItem('theme') || ''; } catch (_) { return ''; } }
function setTheme(t) {
  try { if (t) localStorage.setItem('theme', t); else localStorage.removeItem('theme'); } catch (_) { /* storage unavailable */ }
  if (t) document.documentElement.setAttribute('data-theme', t); else document.documentElement.removeAttribute('data-theme');
}

// ---------- boot ----------
(async function boot() {
  setTheme(getTheme());
  window.addEventListener('hashchange', route);
  try {
    const r = await fetch('/api/session', { credentials: 'same-origin' });
    const d = await r.json();
    if (r.ok) { Object.assign(state, { user: d.user, role: d.role, csrf: d.csrf, version: d.version, terminal: !!d.terminal }); route(); }
    else renderLogin(d.has_users === false ? 'Пользователи не созданы: выполните на сервере «cbsd-web useradd admin»' : '');
  } catch (_) { renderLogin('Сервер недоступен'); }
})();
