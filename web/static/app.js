'use strict';
// CBSD Web UI. No framework, no build step. All DOM is created with
// textContent (never innerHTML with data) so server data cannot inject markup.

const state = { user: null, role: null, csrf: null, version: '', timer: null, route: '' };
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
  [/^env\/([A-Za-z0-9_.-]+)$/, (m) => pageEnv(m[1]), null],
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
      Object.assign(state, { user: r.user, role: r.role, csrf: r.csrf, version: r.version });
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
  Object.assign(state, { user: null, role: null, csrf: null });
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
  }
  return g;
}

async function pageEnv(name) {
  const main = $('#main');
  const render = async () => {
    const { env: e, busy_job: busyJob } = await api('GET', '/api/envs/' + encodeURIComponent(name));
    const back = { jail: '#/jails', bhyve: '#/vms', xen: '#/xen' }[e.emulator] || '#/';
    const info = [
      ['Тип', EMU_TITLE[e.emulator] || e.emulator], ['IP', e.ip4_addr || '—'], ['Hostname', e.host_hostname || '—'],
      ['Путь', e.path || '—'], ['Интерфейс', e.interface || '—'], ['Автозапуск', e.astart ? 'да' : 'нет'],
      ['Защита от удаления', e.protected ? 'да' : 'нет'],
    ];
    if (e.emulator === 'jail') info.push(['JID', e.jid ? String(e.jid) : '—'], ['База', e.ver || '—'], ['Режим базы', e.baserw ? 'rw (своя копия)' : 'ro (общая)'], ['VNET', e.vnet ? 'да' : 'нет']);
    else info.push(['ОС', e.vm_os_type || '—'], ['Профиль', e.vm_os_profile || '—'], ['CPU', String(e.vm_cpus || '—')], ['RAM', fmtBytes(e.vm_ram)],
      ['VNC', e.vnc_port ? (e.vnc_bind || '127.0.0.1') + ':' + e.vnc_port : 'не назначен']);
    const tools = [];
    if (can('operator')) {
      tools.push(h('button', { type: 'button', onclick: () => editEnv(e) }, 'Настройки'));
      if (e.emulator === 'jail' || e.emulator === 'bhyve') tools.push(h('button', { type: 'button', onclick: () => cloneEnv(e) }, 'Клонировать'));
    }
    if (can('admin')) tools.push(h('button', { class: 'danger', type: 'button', disabled: e.protected || !!busyJob, title: e.protected ? 'Защищено (protected=1)' : '', onclick: async () => {
      if (!(await confirmDialog('Удалить ' + e.jname + '?', 'Окружение и все его данные будут удалены без возможности восстановления.', { danger: true, confirmText: 'Удалить навсегда', typeName: e.jname }))) return;
      try { await runAction('POST', '/api/envs/' + encodeURIComponent(e.jname) + '/action', { action: 'remove' }); location.hash = back; } catch (err) { fail(err); }
    } }, 'Удалить'));
    const content = [
      h('div', { class: 'row', style: 'margin-bottom:16px' }, statusPill(e, busyJob), envButtons(e, busyJob, false), h('span', { style: 'flex:1' }), tools),
      e.maintenance ? h('div', { class: 'banner warn' }, 'Режим обслуживания: ', e.maintenance) : null,
      h('div', { class: 'grid cols-2' },
        h('div', { class: 'card' }, h('h2', null, 'Параметры'), h('dl', { class: 'kv' }, info.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))),
        e.emulator === 'jail' || e.emulator === 'bhyve' ? snapshotCard(e) : null),
    ];
    if (e.emulator !== 'jail' && e.vnc_port) {
      content.push(h('div', { class: 'card mt' }, h('h2', null, 'Консоль VNC'),
        h('p', { class: 'muted' }, 'Подключитесь VNC-клиентом. Если VNC слушает 127.0.0.1, используйте SSH-туннель:'),
        h('pre', { class: 'mono' }, 'ssh -L 5900:127.0.0.1:' + e.vnc_port + ' <пользователь>@' + location.hostname + '\n# затем откройте VNC на localhost:5900')));
    }
    fill(main, pageHead(e.jname, h('a', { class: 'btn', href: back }, '← К списку')), content);
  };
  await render();
  autoRefresh(render, 6000);
}

function snapshotCard(e) {
  const out = h('pre', { class: 'log short' }, 'Нажмите «Показать», чтобы получить список снимков (требуется ZFS).');
  const url = '/api/envs/' + encodeURIComponent(e.jname) + '/snapshots';
  const load = async () => {
    out.textContent = 'Загрузка…';
    try { const r = await api('GET', url); out.textContent = r.error ? r.error + '\n' + (r.text || '') : r.text || 'Снимков нет'; } catch (err) { out.textContent = err.message; }
  };
  const snapOp = async (mode) => {
    const nameIn = h('input', { placeholder: mode === 'create' ? 'необязательно: имя снимка' : 'имя снимка', autocomplete: 'off' });
    const titles = { create: 'Создать снимок', rollback: 'Откатить к снимку', destroy: 'Удалить снимок' };
    modal(titles[mode] + ' — ' + e.jname, h('div', null,
      mode === 'rollback' ? h('div', { class: 'banner warn' }, 'Изменения после снимка будут потеряны. Окружение должно быть остановлено.') : null,
      nameIn), [
      { text: 'Отмена' },
      { text: titles[mode], class: mode === 'create' ? 'primary' : 'danger', onClick: async () => {
        await runAction('POST', url, { mode, snapname: nameIn.value.trim() });
      } },
    ]);
  };
  return h('div', { class: 'card' }, h('h2', null, 'Снимки ZFS'),
    h('div', { class: 'row', style: 'margin-bottom:10px' },
      h('button', { class: 'sm', type: 'button', onclick: load }, 'Показать'),
      can('operator') ? h('button', { class: 'sm', type: 'button', onclick: () => snapOp('create') }, 'Создать') : null,
      can('admin') ? h('button', { class: 'sm', type: 'button', onclick: () => snapOp('rollback') }, 'Откатить') : null,
      can('admin') ? h('button', { class: 'sm danger', type: 'button', onclick: () => snapOp('destroy') }, 'Удалить') : null),
    out);
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
  modal('Клонировать ' + e.jname, h('div', null, e.status === 1 ? h('div', { class: 'banner warn' }, 'Рекомендуется остановить окружение перед клонированием.') : null, f.form), [
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
  const { profiles } = await api('GET', '/api/profiles?emulator=' + emu);
  if (!profiles.length) { toast('Профили ОС не найдены. Проверьте dist_dir и workdir в настройках.', 'err'); return; }
  const types = [...new Set(profiles.map((p) => p.vm_os_type))];
  const profOptions = (t) => profiles.filter((p) => p.vm_os_type === t).map((p) => [p.vm_profile, (p.long_description || p.vm_profile) + (p.cloud ? ' ☁' : '')]);
  const isCloud = (v) => profiles.some((p) => p.vm_profile === v.vm_os_profile && p.vm_os_type === v.vm_os_type && p.cloud);
  const defType = types.includes('freebsd') ? 'freebsd' : types[0];
  const fields = [
    { name: 'jname', label: 'Имя ВМ', placeholder: 'vm1', help: 'латиница, цифры и _' },
    { name: 'vm_os_type', label: 'Тип ОС', type: 'select', options: types.map((t) => [t, t]), value: defType },
    { name: 'vm_os_profile', label: 'Профиль (дистрибутив)', type: 'select', options: profOptions(defType), full: true, help: '☁ — облачный образ с cloud-init: готов к работе без установки' },
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
      for (const k of ['ci_ip4_addr', 'ci_gw4', 'ci_user_add', 'ci_user_pubkey', 'vnc_password']) if (v[k] === '') delete v[k];
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

async function pageImages() {
  const d = await api('GET', '/api/images');
  fill($('#main'), pageHead('Образы и ISO'),
    h('h2', null, 'Образы (images)'),
    rowsTable(d.images, [['name', 'Имя'], ['emulator', 'Эмулятор'], ['size', 'Размер', fmtBytes], ['path', 'Путь'], ['created', 'Создан']], 'Нет зарегистрированных образов'),
    h('h2', { class: 'mt' }, 'Носители (ISO и диски)'),
    rowsTable(d.media, [['name', 'Имя'], ['type', 'Тип'], ['jname', 'Подключён к'], ['size', 'Размер', fmtBytes], ['path', 'Путь']], 'Нет зарегистрированных носителей'),
    h('p', { class: 'muted small mt' }, 'ISO для профилей скачиваются автоматически при создании ВМ.'));
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
    if (r.ok) { Object.assign(state, { user: d.user, role: d.role, csrf: d.csrf, version: d.version }); route(); }
    else renderLogin(d.has_users === false ? 'Пользователи не созданы: выполните на сервере «cbsd-web useradd admin»' : '');
  } catch (_) { renderLogin('Сервер недоступен'); }
})();
