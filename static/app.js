/* AITRC Grievance Portal - front-end.
 * All dynamic content is inserted with textContent / DOM nodes (never innerHTML),
 * so user-supplied text cannot execute as HTML or script (XSS-safe).
 * All data lives on the server (SQLite); nothing sensitive is kept in localStorage.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = {
    csrf: null, user: null, meta: null,
    filter: 'all', rows: [], editingId: null,
    studentMode: 'login', hodMode: 'login', cpType: 'student', lastPin: '',
  };

  const CATEGORY_LABELS = {
    'faculties': '1. Faculties', 'teaching': '2. Teaching', 'classroom issue': '3. Classroom Issue',
    'attendance issue': '4. Attendance Issue', 'personal issue': '5. Personal Issue', 'others': '6. Others',
  };
  const TAB_ON = 'flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition bg-indigo-600 text-white shadow-md flex items-center justify-center space-x-2';
  const TAB_OFF = 'flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition bg-transparent text-slate-600 hover:bg-slate-100 flex items-center justify-center space-x-2';
  const FILTER_ON = 'px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white transition';
  const FILTER_OFF = 'px-4 py-2 rounded-xl text-xs font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 transition';
  const BADGE = {
    'Pending': 'bg-amber-100 text-amber-800 border-amber-300',
    'In Progress': 'bg-blue-100 text-blue-800 border-blue-300',
    'Resolved': 'bg-emerald-100 text-emerald-800 border-emerald-300',
  };
  const STATUS_ICON = { 'Pending': 'fa-clock', 'In Progress': 'fa-spinner', 'Resolved': 'fa-circle-check' };

  // ---------- tiny DOM helper ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children) {
      if (c == null || c === false) continue;
      el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const icon = (cls) => h('i', { class: `fa-solid ${cls}` });
  const label = (cat, custom) => (custom ? `${cat}: ${custom}` : cat);
  const fmtDate = (iso) => {
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  function fillSelect(sel, values, { placeholder, labels } = {}) {
    sel.replaceChildren();
    if (placeholder) sel.append(h('option', { value: '', disabled: true, selected: true, text: placeholder }));
    for (const v of values) sel.append(h('option', { value: v, text: labels ? labels[v] || v : v }));
  }
  function show(el, visible) { if (el) el.classList.toggle('hidden', !visible); }

  function notify(message, type = 'info') {
    const colors = { info: 'bg-slate-800', success: 'bg-emerald-600', error: 'bg-red-600' };
    const toast = h('div', { class: `${colors[type] || colors.info} text-white text-sm px-4 py-3 rounded-xl shadow-lg`, role: 'status', text: message });
    $('toast-container').append(toast);
    setTimeout(() => toast.remove(), type === 'error' ? 7000 : 4000);
  }

  // ---------- API ----------
  class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }

  async function api(path, { method = 'GET', body } = {}) {
    const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-CSRF-Token'] = state.csrf || '';
      opts.body = JSON.stringify(body || {});
    }
    let res;
    try { res = await fetch(path, opts); }
    catch { throw new ApiError('Cannot reach the server. Check that it is running.', 0); }
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON */ }
    if (!res.ok) throw new ApiError((data && data.error) || `Request failed (${res.status})`, res.status);
    return data;
  }

  // Wrap UI handlers so errors become toasts and expired sessions return to the login screen.
  const guarded = (fn) => async (...args) => {
    try { return await fn(...args); }
    catch (err) {
      if (!(err instanceof ApiError)) { console.error(err); notify(`Unexpected error: ${err && err.message ? err.message : err}`, 'error'); return; }
      if (err.status === 401 && state.user) {
        state.user = null; routeView(); notify('Your session has expired. Please log in again.', 'error');
      } else if (err.status === 403 && /token/i.test(err.message)) {
        await loadSession(); notify('Please try that again.', 'error');
      } else notify(err.message, 'error');
    }
  };

  async function loadSession() {
    const data = await api('/api/session');
    state.csrf = data.csrf; state.user = data.user; state.meta = data.meta;
  }

  // ---------- setup ----------
  function populateStaticSelects() {
    const m = state.meta;
    for (const id of ['student-level-select', 'hod-level-select', 'cp-level']) fillSelect($(id), m.levels);
    for (const id of ['hod-dept-select', 'cp-dept']) fillSelect($(id), m.departments);
    fillSelect($('c-level'), m.levels, { placeholder: 'Select level' });
    fillSelect($('c-dept'), m.departments, { placeholder: 'Select branch' });
    fillSelect($('c-year'), [], { placeholder: 'Select year' });
    fillSelect($('c-category'), m.categories, { placeholder: 'Select category', labels: CATEGORY_LABELS });
    fillSelect($('detail-status'), m.statuses);
    const bar = $('filter-buttons'); bar.replaceChildren();
    for (const f of ['all', ...m.statuses]) {
      bar.append(h('button', { type: 'button', 'data-action': 'filter', 'data-filter': f, id: `filter-btn-${f}`, class: FILTER_OFF, text: f === 'all' ? 'All Complaints' : f }));
    }
  }

  function updateYearOptions() {
    const level = $('c-level').value;
    fillSelect($('c-year'), level ? state.meta.years[level] : [], { placeholder: 'Select year' });
  }

  function toggleCustomCategory() {
    const needs = state.meta.customCategories.includes($('c-category').value);
    show($('custom-category-container'), needs);
    $('c-custom-text').required = needs;
    if (!needs) $('c-custom-text').value = '';
  }

  // ---------- navigation / views ----------
  function updateNav() {
    const nav = $('nav-auth-section'); nav.replaceChildren();
    const u = state.user;
    if (!u) { nav.append(h('span', { class: 'text-xs text-indigo-200', text: 'Welcome to AITRC Portal' })); return; }
    const title = u.role === 'hod' ? `HOD (${u.level} - ${u.dept})` : `Student (${u.level} | PRN: ${u.prn})`;
    nav.append(h('div', { class: 'flex items-center space-x-3 bg-white/10 px-3.5 py-1.5 rounded-xl border border-white/20' },
      h('div', { class: 'w-8 h-8 rounded-full bg-indigo-500 text-white flex items-center justify-center text-xs' }, icon(u.role === 'hod' ? 'fa-user-tie' : 'fa-user')),
      h('div', { class: 'text-left' },
        h('p', { class: 'text-xs font-bold text-white', text: title }),
        h('p', { class: 'text-[10px] text-indigo-200', text: 'AITRC Vita' })),
      h('button', { type: 'button', 'data-action': 'logout', title: 'Logout', 'aria-label': 'Logout', class: 'ml-2 text-indigo-200 hover:text-white p-1 transition' }, icon('fa-right-from-bracket'))));
  }

  function routeView() {
    updateNav();
    show($('view-login'), !state.user);
    show($('view-student'), state.user && state.user.role === 'student');
    show($('view-hod'), state.user && state.user.role === 'hod');
    if (!state.user) return;
    if (state.user.role === 'student') {
      $('form-logged-prn').textContent = state.user.prn;
      $('c-level').value = state.user.level || 'Degree';
      $('c-level').disabled = true;
      updateYearOptions();
      switchStudentTab('submit');
    } else {
      $('c-level').disabled = false;
      $('hod-banner-dept-title').textContent = `${state.user.level} - ${state.user.dept} Department HOD Portal`;
      state.filter = 'all'; $('search-input').value = '';
      refreshFilterButtons();
      loadHod();
    }
  }

  function switchStudentTab(tab) {
    show($('student-tab-submit'), tab === 'submit');
    show($('student-tab-track'), tab === 'track');
    $('tab-btn-submit').className = tab === 'submit' ? TAB_ON : TAB_OFF;
    $('tab-btn-track').className = tab === 'track' ? TAB_ON : TAB_OFF;
  }

  function toggleLoginFields() {
    const hod = $('login-role').value === 'hod';
    show($('student-login-container'), !hod);
    show($('hod-login-container'), hod);
    show($('student-info-note'), !hod);
    updateLoginButton();
  }

  const codeRequired = () => !state.meta || state.meta.hodCodeRequired !== false;

  function updateLoginButton() {
    const hod = $('login-role').value === 'hod';
    const hodReg = hod && state.hodMode === 'register';
    const register = (!hod && state.studentMode === 'register') || hodReg;
    show($('student-confirm-group'), !hod && register);
    show($('hod-confirm-group'), hodReg);
    show($('hod-code-group'), hodReg && codeRequired());
    if ($('hod-pass-input')) $('hod-pass-input').setAttribute('autocomplete', hodReg ? 'new-password' : 'current-password');
    if ($('hod-pass-label')) $('hod-pass-label').textContent = hodReg ? 'New Password *' : 'HOD Password *';
    if ($('student-pass-label')) $('student-pass-label').textContent = (!hod && register) ? 'New Password *' : 'Password *';
    if ($('toggle-hod-register-btn')) $('toggle-hod-register-btn').textContent = hodReg ? 'Already registered? Log in' : 'New HOD? Register';
    $('login-submit-label').textContent = register ? (hodReg ? 'Register HOD & Continue' : 'Create Account & Continue') : 'Access Portal';
    $('toggle-register-btn').textContent = register ? 'Already registered? Log in' : 'New student? Create account';
    if ($('student-pass-input')) $('student-pass-input').setAttribute('autocomplete', register ? 'new-password' : 'current-password');
  }

  function clearLoginFields() {
    for (const id of ['student-prn-input', 'student-pass-input', 'student-confirm-input', 'hod-pass-input', 'hod-confirm-input', 'hod-code-input']) { const el = $(id); if (el) el.value = ''; }
    state.studentMode = 'login'; state.hodMode = 'login'; updateLoginButton();
  }

  // ---------- auth ----------
  const handleLogin = guarded(async (e) => {
    e.preventDefault();
    const role = $('login-role').value;
    let data;
    if (role === 'hod') {
      const password = $('hod-pass-input').value;
      if (!password) return notify('Please enter the HOD password.', 'error');
      const level = $('hod-level-select').value, dept = $('hod-dept-select').value;
      if (state.hodMode === 'register') {
        if (password !== $('hod-confirm-input').value) return notify('Passwords do not match.', 'error');
        const codeEl = $('hod-code-input');
        const setup_code = codeEl ? codeEl.value : '';
        if (codeRequired() && !setup_code) return notify('Please enter the HOD setup code.', 'error');
        data = await api('/api/register-hod', { method: 'POST', body: { level, dept, password, confirm_password: $('hod-confirm-input').value, setup_code } });
        notify('HOD account registered. Welcome!', 'success');
      } else {
        data = await api('/api/login', { method: 'POST', body: { role, level, dept, password } });
      }
    } else {
      const prn = $('student-prn-input').value.trim();
      const password = $('student-pass-input').value;
      const level = $('student-level-select').value;
      if (!level) return notify('Please select Degree or Diploma.', 'error');
      if (!prn || !password) return notify('Please enter both PRN number and password.', 'error');
      if (state.studentMode === 'register') {
        if (password !== $('student-confirm-input').value) return notify('Passwords do not match.', 'error');
        data = await api('/api/register', { method: 'POST', body: { level, prn, password, confirm_password: $('student-confirm-input').value } });
        notify('Account created. Welcome!', 'success');
      } else {
        data = await api('/api/login', { method: 'POST', body: { role, level, prn, password } });
      }
    }
    state.csrf = data.csrf; state.user = data.user;
    clearLoginFields();
    routeView();
  });

  const logout = guarded(async () => {
    const data = await api('/api/logout', { method: 'POST' });
    state.csrf = data.csrf; state.user = null; state.rows = [];
    $('track-result-container').replaceChildren(); show($('track-result-container'), false);
    $('track-pin-input').value = '';
    clearLoginFields(); routeView();
  });

  // ---------- change password ----------
  function openChangePassword(type) {
    state.cpType = type;
    $('cp-modal-title').textContent = type === 'hod' ? 'Change Department HOD Password' : 'Change Student Password';
    show($('cp-student-group'), type === 'student');
    show($('cp-hod-group'), type === 'hod');
    $('cp-old').value = ''; $('cp-new').value = '';
    if (type === 'student') $('cp-prn').value = $('student-prn-input').value.trim();
    else { $('cp-level').value = $('hod-level-select').value; $('cp-dept').value = $('hod-dept-select').value; }
    show($('modal-change-pass'), true);
  }
  function closeChangePassword() { $('cp-old').value = ''; $('cp-new').value = ''; show($('modal-change-pass'), false); }

  const submitChangePassword = guarded(async (e) => {
    e.preventDefault();
    const old_password = $('cp-old').value, new_password = $('cp-new').value;
    if (!old_password || !new_password) return notify('Please fill out all password fields.', 'error');
    const body = state.cpType === 'hod'
      ? { role: 'hod', level: $('cp-level').value, dept: $('cp-dept').value, old_password, new_password }
      : { role: 'student', prn: $('cp-prn').value.trim(), old_password, new_password };
    await api('/api/change-password', { method: 'POST', body });
    closeChangePassword();
    notify('Password updated successfully.', 'success');
  });

  // ---------- student: submit & track ----------
  const submitComplaint = guarded(async (e) => {
    e.preventDefault();
    const body = {
      level: $('c-level').value, dept: $('c-dept').value, year: $('c-year').value,
      category: $('c-category').value, custom_text: $('c-custom-text').value,
      name: $('c-name').value, subject: $('c-subject').value, description: $('c-desc').value,
    };
    const res = await api('/api/complaints', { method: 'POST', body });
    state.lastPin = res.pin;
    $('complaint-form').reset();
    $('c-level').value = state.user.level || 'Degree';
    $('c-level').disabled = true;
    updateYearOptions(); toggleCustomCategory();
    $('modal-pin-display').textContent = res.pin;
    $('modal-ref').textContent = res.ref;
    show($('modal-success'), true);
  });

  function closeSuccess() {
    show($('modal-success'), false);
    $('modal-pin-display').textContent = '------'; state.lastPin = '';
    switchStudentTab('track');
  }

  const trackComplaint = guarded(async (e) => {
    e.preventDefault();
    const pin = $('track-pin-input').value.trim();
    const box = $('track-result-container');
    if (!pin) return notify('Please enter your tracking code.', 'error');
    box.replaceChildren(); show(box, true);
    let c;
    try { c = await api('/api/track', { method: 'POST', body: { pin } }); }
    catch (err) {
      if (err.status === 404) {
        box.append(h('div', { class: 'bg-red-50 border border-red-200 rounded-2xl p-6 text-center text-red-700' },
          icon('fa-circle-xmark text-3xl mb-2'),
          h('h4', { class: 'font-bold text-lg', text: 'Complaint Not Found' }),
          h('p', { class: 'text-xs mt-1', text: err.message })));
        return;
      }
      show(box, false); throw err;
    }
    const cls = BADGE[c.status] || BADGE.Pending;
    box.append(h('div', { class: 'bg-white rounded-2xl shadow-xl border border-slate-200 p-6 sm:p-8 space-y-6' },
      h('div', { class: 'flex flex-wrap justify-between items-start gap-3 border-b border-slate-100 pb-4' },
        h('div', {},
          h('span', { class: 'font-mono text-xs font-bold px-3 py-1 bg-indigo-50 text-indigo-700 rounded-lg', text: `Ref: ${c.ref}` }),
          h('h4', { class: 'text-lg font-bold text-slate-800 mt-2 break-words', text: c.subject }),
          h('p', { class: 'text-xs text-slate-400 mt-0.5', text: `Submitted ${fmtDate(c.created_at)} • Dept: ${c.dept}` })),
        h('span', { class: `inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-full text-xs font-bold border ${cls}` },
          icon(STATUS_ICON[c.status] || 'fa-clock'), h('span', { text: c.status }))),
      h('div', { class: 'grid grid-cols-2 gap-4 text-xs bg-slate-50 p-4 rounded-xl border border-slate-200' },
        h('div', {}, h('span', { class: 'text-slate-400 font-semibold block', text: 'Category' }), h('span', { class: 'font-semibold text-indigo-700 capitalize break-words', text: label(c.category, c.custom_text) })),
        h('div', {}, h('span', { class: 'text-slate-400 font-semibold block', text: 'Level & Year' }), h('span', { class: 'font-semibold text-slate-700', text: `${c.level} - ${c.year}` }))),
      h('div', {}, h('span', { class: 'text-xs font-bold text-slate-500 uppercase tracking-wider block mb-1', text: 'Description' }),
        h('p', { class: 'text-sm bg-slate-50 p-4 rounded-xl text-slate-700 border border-slate-200 whitespace-pre-wrap break-words', text: c.description })),
      h('div', { class: 'bg-indigo-50/50 border border-indigo-100 rounded-xl p-4 space-y-1' },
        h('span', { class: 'text-xs font-bold text-indigo-900 uppercase tracking-wider flex items-center' }, icon('fa-user-tie text-indigo-600 mr-1'), 'Department HOD Remarks / Action Taken'),
        h('p', { class: 'text-sm text-indigo-950 font-medium whitespace-pre-wrap break-words', text: c.remarks || 'Pending review and action by Department HOD.' }))));
  });

  // ---------- HOD ----------
  function refreshFilterButtons() {
    document.querySelectorAll('#filter-buttons button').forEach((b) => { b.className = b.dataset.filter === state.filter ? FILTER_ON : FILTER_OFF; });
  }

  const loadHod = guarded(async () => {
    const params = new URLSearchParams({ status: state.filter });
    const q = $('search-input').value.trim();
    if (q) params.set('q', q);
    const data = await api(`/api/hod/complaints?${params}`);
    state.rows = data.complaints;
    $('stat-total').textContent = data.stats.total;
    $('stat-pending').textContent = data.stats.pending;
    $('stat-progress').textContent = data.stats.in_progress;
    $('stat-resolved').textContent = data.stats.resolved;
    renderHodTable();
  });

  function renderHodTable() {
    const tbody = $('hod-table-body'); tbody.replaceChildren();
    show($('no-complaints-msg'), state.rows.length === 0);
    for (const c of state.rows) {
      const anon = !c.student_prn;
      tbody.append(h('tr', { class: 'hover:bg-slate-50 transition border-b border-slate-100' },
        h('td', { class: 'py-4 px-6' },
          h('span', { class: 'font-mono font-bold text-indigo-600 text-xs bg-indigo-50 px-2 py-1 rounded', text: c.ref }),
          h('p', { class: 'text-[11px] text-slate-400 mt-1', text: fmtDate(c.created_at) })),
        h('td', { class: 'py-4 px-6' },
          h('p', { class: 'font-semibold text-slate-800 break-words', text: c.student_name }),
          h('p', { class: 'text-xs font-mono text-indigo-600 font-medium', text: anon ? 'PRN: hidden (anonymous)' : `PRN: ${c.student_prn}` })),
        h('td', { class: 'py-4 px-6' },
          h('span', { class: 'font-semibold text-xs text-indigo-700 capitalize block break-words', text: label(c.category, c.custom_text) }),
          h('span', { class: 'text-[11px] text-slate-500', text: `${c.level} • ${c.year}` })),
        h('td', { class: 'py-4 px-6 max-w-xs' },
          h('p', { class: 'font-semibold text-slate-800 truncate', text: c.subject }),
          h('p', { class: 'text-xs text-slate-500 truncate', text: c.description })),
        h('td', { class: 'py-4 px-6' }, h('span', { class: `px-2.5 py-1 rounded-full text-xs font-bold border ${BADGE[c.status] || BADGE.Pending}`, text: c.status })),
        h('td', { class: 'py-4 px-6 text-center' },
          h('button', { type: 'button', 'data-action': 'open-detail', 'data-id': c.id, title: 'Review & Update', 'aria-label': `Review ${c.ref}`, class: 'bg-indigo-50 hover:bg-indigo-600 hover:text-white text-indigo-600 p-2.5 rounded-xl transition shadow-sm' }, icon('fa-pen-to-square')))));
    }
  }

  function openDetail(id) {
    const c = state.rows.find((r) => r.id === id);
    if (!c) return;
    state.editingId = id;
    $('detail-ref-badge').textContent = c.ref;
    $('detail-subject').textContent = c.subject;
    $('detail-category').textContent = label(c.category, c.custom_text);
    $('detail-year').textContent = `${c.level} - ${c.year}`;
    $('detail-name').textContent = c.student_prn ? `${c.student_name} (PRN: ${c.student_prn})` : 'Anonymous';
    $('detail-date').textContent = fmtDate(c.created_at);
    $('detail-desc').textContent = c.description;
    $('detail-status').value = c.status;
    $('detail-remarks').value = c.remarks || '';
    show($('modal-detail'), true);
  }
  function closeDetail() { show($('modal-detail'), false); state.editingId = null; }

  const saveDetail = guarded(async () => {
    if (state.editingId == null) return;
    await api(`/api/hod/complaints/${state.editingId}`, { method: 'PATCH', body: { status: $('detail-status').value, remarks: $('detail-remarks').value } });
    closeDetail(); notify('Complaint updated.', 'success');
    await loadHod();
  });

  // ---------- events ----------
  const actions = {
    'toggle-register': () => { state.studentMode = state.studentMode === 'login' ? 'register' : 'login'; updateLoginButton(); },
    'toggle-hod-register': () => { state.hodMode = state.hodMode === 'login' ? 'register' : 'login'; updateLoginButton(); },
    'open-change-password': (el) => openChangePassword(el.dataset.type),
    'close-change-password': closeChangePassword,
    'student-tab': (el) => switchStudentTab(el.dataset.tab),
    'logout': logout,
    'close-success': closeSuccess,
    'copy-pin': async () => {
      try { await navigator.clipboard.writeText(state.lastPin); notify('Tracking code copied.', 'success'); }
      catch { notify('Could not copy automatically. Please select and copy the code.', 'error'); }
    },
    'filter': (el) => { state.filter = el.dataset.filter; refreshFilterButtons(); loadHod(); },
    'open-detail': (el) => openDetail(Number(el.dataset.id)),
    'close-detail': closeDetail,
    'save-detail': saveDetail,
    'export': () => { const a = h('a', { href: '/api/hod/export' }); document.body.append(a); a.click(); a.remove(); },
  };

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (el && actions[el.dataset.action]) actions[el.dataset.action](el, e);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    closeDetail(); closeChangePassword();
  });

  let searchTimer;
  window.addEventListener('DOMContentLoaded', guarded(async () => {
    await loadSession();
    populateStaticSelects();
    $('login-role').addEventListener('change', toggleLoginFields);
    $('c-level').addEventListener('change', updateYearOptions);
    $('c-category').addEventListener('change', toggleCustomCategory);
    $('login-form').addEventListener('submit', handleLogin);
    $('complaint-form').addEventListener('submit', submitComplaint);
    $('track-form').addEventListener('submit', trackComplaint);
    $('change-pass-form').addEventListener('submit', submitChangePassword);
    $('search-input').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadHod, 250); });
    toggleLoginFields();
    routeView();
  }));
})();
