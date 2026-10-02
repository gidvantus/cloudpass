// CloudPass web portal.
//
// This file renders and routes; it does not decide anything about the vault. It never sees a
// key, and it does not see every password: the list carries titles and usernames, and the
// «Скопировать» button calls into the module so that the secret goes to the clipboard *there*.
// A password crosses into this file in exactly one place — the editor, for one entry, when the
// user opens it — and that is the only place it should ever appear.
//
// Two rules throughout, because they are cheap here and expensive later: user text is written
// with textContent and never innerHTML, and every field that held a secret is cleared as soon
// as the call that used it returns.
//
// A third rule is the language. This file holds no wording of its own: every phrase comes from
// `locales-ru.js` or `locales-en.js` through `i18n.js`, including the ones that depend on
// state. Where a label changes with the state — «Новая запись» against «Запись», «Показать»
// against «Скрыть» — what changes is the *key* (`data-i18n`), never the text, so switching the
// language re-derives the label from the state instead of freezing it.

import init, {
  create_account,
  unlock,
  lock,
  status,
  list_items,
  list_projects,
  reveal_item,
  copy_password,
  copy_username,
  add_item,
  update_item,
  delete_item,
  sync_now,
} from './pkg/cloudpass_web.js';

import { createI18n } from './i18n.js';
import localesRu from './locales-ru.js';
import localesEn from './locales-en.js';

const byId = (id) => document.getElementById(id);

// --- the language -----------------------------------------------------------

/** Where the choice lives. The only thing this portal ever writes to `localStorage`. */
const LANGUAGE_KEY = 'cloudpass.language';
const DEFAULT_LOCALE = 'ru';

const i18n = createI18n({ ru: localesRu, en: localesEn }, DEFAULT_LOCALE);
const t = (key, params) => i18n.t(key, params);

/** The stored language, or the default for anything that is not one of the two. */
function storedLocale() {
  try {
    return window.localStorage.getItem(LANGUAGE_KEY) === 'en' ? 'en' : DEFAULT_LOCALE;
  } catch {
    // A browser that refuses `localStorage` — private mode, a policy — is not a broken
    // portal: the language simply does not survive the reload.
    return DEFAULT_LOCALE;
  }
}

/**
 * Writes an element's wording by key, keeping `data-i18n` in step with it.
 *
 * The attribute matters more than the text: it is what `applyTranslations()` reads on the
 * next language switch, so an element whose label depends on state has to change the key
 * when the state changes, or the switch would put the wrong label back.
 */
function say(element, key, params) {
  element.dataset.i18n = key;
  element.textContent = params ? t(key, params) : t(key);
}

/** Switches the language and remembers it, so the next load is not a fresh start. */
function setLocale(next) {
  const applied = applyLocale(next);
  try {
    window.localStorage.setItem(LANGUAGE_KEY, applied);
  } catch {
    // Losing the choice on reload is a smaller failure than a page that will not switch.
  }
}

/**
 * Puts a language on the page: the translator, the text, the document language, the pickers.
 *
 * The translator is switched here rather than by the caller, because this is the one function
 * both paths go through — the picker, and a stored choice read at load. Switching it only on
 * the first of those leaves a page whose `lang` says `en` while every word on it is Russian,
 * which is precisely the state this change exists to make impossible.
 *
 * Deliberately nothing else. Re-rendering is limited to what is derived from state
 * (`renderDynamic`), so the emergency kit on screen, the values typed into a form, the record
 * being edited and the position in the route all survive a switch untouched.
 */
function applyLocale(locale) {
  const applied = i18n.setLocale(locale);
  document.documentElement.lang = applied;
  for (const select of document.querySelectorAll('select[data-testid="language-select"]')) {
    select.value = applied;
  }
  i18n.applyTranslations();
  renderDynamic();
  return applied;
}

const views = {
  landing: byId('view-landing'),
  register: byId('view-register'),
  login: byId('view-login'),
  kit: byId('view-kit'),
  vault: byId('view-vault'),
  item: byId('view-item'),
};

/** Where to put the caret when a screen is shown for the first time. */
const firstField = {
  register: 'register-identifier',
  login: 'login-identifier',
  item: 'item-name',
};

const banner = byId('banner');
const boot = byId('boot');

let unlocked = false;
/** A kit was just issued and has not been acknowledged. It exists only in memory. */
let kitPending = false;
let shown = null;

/** Everything the last list fetch returned, kept so that filtering does not need a round trip. */
let items = [];
let projects = [];
/**
 * Which project the password list is showing.
 *
 * `null` means every entry; `''` means the ones filed under no project at all. Those are two
 * different questions and collapsing them — by using `''` for "all", say — would make it
 * impossible to ask for the ungrouped ones.
 */
let selectedProject = null;

/** The last synchronization note the module reported, as a key plus numbers. */
let lastSync = null;
/** Whether the editor holds an existing record or a new one. */
let editingItem = false;
/** What the server offers as a desktop build, if anything. */
let desktopBuild = null;
/** Why the module never started, if it did not. */
let bootFailure = null;

// --- plumbing ---------------------------------------------------------------

function complain(message) {
  banner.textContent = message;
  banner.hidden = false;
}

function dismiss() {
  banner.hidden = true;
  banner.textContent = '';
}

/** Turns an error code from the module into the key its sentence lives under. */
function errorKey(code) {
  return `err-${String(code).replaceAll('_', '-')}`;
}

/**
 * Turns a rejection into something worth showing.
 *
 * The module rejects with a JSON string, because an exception is the only channel
 * wasm-bindgen gives us and a string is the only thing that survives it intact.
 *
 * The code it carries is the contract and the sentence is looked up by it. The message the
 * module also sends is English prose from crates shared with the desktop client, so it is a
 * fallback for a code this page has never heard of — never the thing shown by default.
 */
function describe(error) {
  let parsed = null;
  if (typeof error === 'string') {
    try {
      parsed = JSON.parse(error);
    } catch {
      return error;
    }
  } else if (error && typeof error === 'object') {
    parsed = error;
  }

  if (parsed && typeof parsed === 'object') {
    if (parsed.code) {
      const key = errorKey(parsed.code);
      const phrase = t(key);
      // `t` answers with the key itself when there is no entry, and a sentence is never
      // equal to its key — so this tells "translated" from "unknown" without a second table.
      if (phrase !== key) {
        return phrase;
      }
    }
    if (parsed.message) {
      return parsed.message;
    }
  }

  return t('err-unknown');
}

function show(name) {
  for (const [key, element] of Object.entries(views)) {
    element.hidden = key !== name;
  }

  // Before the early return: the header answers "is this tab signed in?", and that can change
  // without the screen changing — locking and immediately landing back here, for instance.
  renderAuthAction();

  if (shown === name) {
    return;
  }
  shown = name;
  window.scrollTo({ top: 0 });

  const target = firstField[name];
  if (target) {
    byId(target).focus({ preventScroll: true });
  }
}

/** Clears every field that may have held a secret. */
function wipeSecretFields() {
  for (const id of [
    'register-password',
    'register-confirm',
    'login-password',
    'item-password',
  ]) {
    byId(id).value = '';
  }
}

async function withBusy(button, work) {
  button.disabled = true;
  try {
    return await work();
  } finally {
    button.disabled = false;
  }
}

/** Confirms an action on the button itself, without a dialog in the way. */
function flash(button, key) {
  // The button's own key is what it goes back to — not the text captured here, which would
  // be in the language that was current when the click happened.
  const original = button.dataset.i18n;
  button.textContent = t(key);
  button.disabled = true;
  window.setTimeout(() => {
    button.textContent = original ? t(original) : '';
    button.disabled = false;
  }, 1200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// --- what depends on state --------------------------------------------------

/**
 * Everything whose wording is decided by state rather than by the markup.
 *
 * This is the whole of what a language switch redraws. It deliberately does not touch form
 * fields, the emergency kit on screen or the route: those are the things a switch must not
 * be able to lose.
 */
function renderDynamic() {
  renderBoot();
  renderAuthAction();
  renderVaultStatus();
  renderProjects();
  renderItems();
  renderItemTitle();
  renderDesktop();
}

function renderBoot() {
  if (bootFailure === null) {
    return;
  }
  // The failure is a sentence with a parameter, which `applyTranslations()` cannot build, so
  // this element gives up its key and is rebuilt here on every switch instead.
  delete boot.dataset.i18n;
  boot.textContent = t('boot-failed', { error: bootFailure });
}

/**
 * The header's one control: «Войти» while the vault is shut, «Выйти» once it is open.
 *
 * It reads `unlocked`, which the module owns, rather than a copy kept here, so there is one
 * answer to "is this tab signed in?" and the header cannot drift away from the screens.
 */
function renderAuthAction() {
  const action = byId('topbar-auth');
  say(action, unlocked ? 'nav-sign-out' : 'nav-sign-in');
  action.dataset.action = unlocked ? 'sign-out' : 'sign-in';
}

/**
 * The status line: numbers, not a sentence.
 *
 * `sync-ok` is a marker rather than a phrase — a completed synchronization is described by how
 * much moved, and this page owns the words for the numbers. Every other key is a sentence and
 * carries no counts. `error_detail` is never read here: it is English prose from a shared
 * crate, and the localized key above is what a person is meant to see.
 */
function renderVaultStatus() {
  if (!lastSync) {
    byId('vault-status').textContent = '';
    return;
  }

  const parts = [];
  if (lastSync.key !== 'sync-ok') {
    parts.push(t(lastSync.key));
  }
  if (lastSync.received !== null && lastSync.received !== undefined) {
    parts.push(t('sync-received', { count: lastSync.received }));
  }
  if (lastSync.sent !== null && lastSync.sent !== undefined) {
    parts.push(t('sync-sent', { count: lastSync.sent }));
  }
  if (lastSync.head_rejected) {
    parts.push(t('sync-head-rejected'));
  } else if (lastSync.conflicts !== null && lastSync.conflicts !== undefined) {
    parts.push(t('sync-conflicts', { count: lastSync.conflicts }));
  }
  byId('vault-status').textContent = parts.join(' · ');
}

/**
 * Ends the session and returns to the landing page.
 *
 * Locking the wasm module is what actually signs the user out — it drops the vault and every
 * key with it. The page's own copies go too, so a stale list cannot be painted over the top of
 * a signed-out screen by a render that was already in flight.
 */
async function signOut() {
  dismiss();
  wipeSecretFields();
  await lock();
  unlocked = false;
  items = [];
  projects = [];
  selectedProject = null;
  lastSync = null;
  go('#/');
}

function parseRoute() {
  const raw = window.location.hash.replace(/^#\/?/, '');
  const [head, param] = raw.split('/');
  return { name: head || 'landing', param: param || '' };
}

function go(hash) {
  if (window.location.hash === hash) {
    render();
    return;
  }
  window.location.hash = hash;
}

async function render() {
  dismiss();
  const { name, param } = parseRoute();

  // The kit is the one thing this client cannot re-fetch: it was handed over once and stored
  // nowhere. Until the user says they kept it, every other route leads back here.
  if (kitPending && name !== 'kit') {
    go('#/kit');
    return;
  }

  switch (name) {
    case 'landing':
      show('landing');
      return;

    case 'register':
      if (unlocked) {
        go('#/vault');
        return;
      }
      show('register');
      return;

    case 'login':
      if (unlocked) {
        go('#/vault');
        return;
      }
      show('login');
      return;

    case 'kit':
      if (!kitPending) {
        go(unlocked ? '#/vault' : '#/');
        return;
      }
      show('kit');
      return;

    case 'vault':
      if (!unlocked) {
        go('#/login');
        return;
      }
      show('vault');
      await loadVault();
      return;

    case 'item':
      if (!unlocked) {
        go('#/login');
        return;
      }
      show('item');
      await loadItem(param);
      return;

    default:
      go('#/');
  }
}

// --- the vault --------------------------------------------------------------

async function loadVault() {
  const state = JSON.parse(await status());
  unlocked = state.unlocked;
  lastSync = state.last_sync || null;

  byId('vault-who').textContent = state.identifier || '';
  byId('vault-foot-account').textContent = state.identifier || '';

  items = JSON.parse(await list_items());
  projects = JSON.parse(await list_projects());

  // A project exists exactly as long as an entry is filed under it, so the selected one can
  // stop existing between two loads. Falling back to «Все пароли» is the only honest answer:
  // the alternative is an empty list and nothing on screen to click away from.
  if (selectedProject && !projects.includes(selectedProject)) {
    selectedProject = null;
  }

  renderVaultStatus();
  renderProjects();
  renderItems();
}

/**
 * The project list, and with it the choice of what the password list shows.
 *
 * «Все пароли» is always first, because it is what a person wants most of the time and because
 * a list that can be left with nothing selected has to offer a way back.
 */
function renderProjects() {
  const list = byId('project-list');
  list.replaceChildren();

  list.append(projectRow(t('vault-all-passwords'), items.length, null));

  for (const name of projects) {
    list.append(projectRow(name, items.filter((item) => item.project === name).length, name));
  }

  // Only offered when it would actually show something. An «Без проекта» row that leads to an
  // empty list is a worse answer than not offering it at all.
  const ungrouped = items.filter((item) => !item.project).length;
  if (ungrouped > 0) {
    list.append(projectRow(t('vault-no-project'), ungrouped, ''));
  }

  byId('project-empty').hidden = projects.length > 0;
}

function projectRow(label, count, value) {
  const row = document.createElement('li');
  row.className = 'project';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'project-button';
  button.setAttribute('data-testid', 'project');
  // Three different rows, told apart by this attribute alone: «Все пароли» has no `data-project`
  // at all, a named project carries its name, and «Без проекта» carries the empty string. The
  // absent attribute is what keeps "everything" from looking identical to "filed under nothing".
  if (value !== null) {
    button.setAttribute('data-project', value);
  }
  // The state is on the element as `aria-current`, not as a class: it is a statement about
  // what the list is showing, and there is exactly one such element at any moment.
  button.setAttribute('aria-current', String(selectedProject === value));

  const name = document.createElement('span');
  name.textContent = label;
  button.append(name);

  const badge = document.createElement('span');
  badge.className = 'project-count';
  badge.textContent = String(count);
  button.append(badge);

  button.addEventListener('click', () => {
    selectedProject = value;
    renderProjects();
    renderItems();
  });

  row.append(button);
  return row;
}

/** Whether an entry belongs to what the project list currently has selected. */
function matchesSelection(item) {
  if (selectedProject === null) {
    return true;
  }
  return (item.project || '') === selectedProject;
}

function renderItems() {
  const list = byId('item-list');
  list.replaceChildren();

  const visible = items.filter(matchesSelection);
  const empty = byId('item-empty');
  empty.hidden = visible.length > 0;
  say(empty, selectedProject === null ? 'vault-empty-all' : 'vault-empty-project');

  const scope = byId('item-scope');
  if (selectedProject === null) {
    delete scope.dataset.i18n;
    scope.textContent = '';
  } else if (selectedProject === '') {
    say(scope, 'vault-scope-no-project');
  } else {
    // A project name is the user's own text, so it is written as it is and not translated.
    delete scope.dataset.i18n;
    scope.textContent = selectedProject;
  }

  for (const item of visible) {
    const row = document.createElement('li');
    row.className = 'item';
    row.setAttribute('data-testid', 'item-row');
    row.setAttribute('data-item-id', item.id);

    const text = document.createElement('div');
    text.className = 'item-text';

    const title = document.createElement('span');
    title.className = 'item-title';
    title.textContent = item.title || t('vault-untitled');
    text.append(title);

    // Only worth a badge when the list is showing more than one project; inside a single
    // project every row would carry the same three words.
    if (selectedProject === null && item.project) {
      const badge = document.createElement('span');
      badge.className = 'item-project';
      badge.setAttribute('data-testid', 'item-project-badge');
      badge.textContent = item.project;
      text.append(badge);
    }

    const sub = document.createElement('span');
    sub.className = 'item-sub';
    const parts = [item.username, item.url].filter(Boolean);
    if (item.pending) {
      parts.push(t('sync-pending'));
    }
    sub.textContent = parts.join(' · ');
    text.append(sub);

    row.append(text);

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    // The button that matters: the password goes from the vault to the clipboard inside the
    // wasm module and never appears in this file or in the document.
    actions.append(
      actionButton('vault-copy', 'btn-solid', 'copy-password', async (button) => {
        await copy_password(item.id);
        flash(button, 'vault-copied');
      }),
    );

    if (item.username) {
      actions.append(
        actionButton('vault-copy-username', 'btn-outline', 'copy-username', async (button) => {
          await copy_username(item.id);
          flash(button, 'vault-copied');
        }),
      );
    }

    actions.append(
      actionButton('vault-open', 'btn-outline', 'open-item', () => go(`#/item/${item.id}`)),
    );

    row.append(actions);
    list.append(row);
  }
}

function actionButton(key, variant, testId, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `btn btn-small ${variant}`;
  button.setAttribute('data-testid', testId);
  say(button, key);
  button.addEventListener('click', async () => {
    dismiss();
    try {
      await withBusy(button, () => onClick(button));
    } catch (error) {
      complain(describe(error));
    }
  });
  return button;
}

// --- the editor -------------------------------------------------------------

function renderItemTitle() {
  // The heading says which of the two things this screen is — a new entry or an existing
  // one — so the key follows that state and the wording follows the key.
  say(byId('item-title'), editingItem ? 'item-edit' : 'item-new');
}

async function loadItem(id) {
  const form = byId('item-form');
  form.reset();
  byId('item-password').type = 'password';
  say(byId('item-reveal'), 'item-reveal');

  projects = await loadProjectNames();

  if (id && id !== 'new') {
    // The one place a secret crosses into this file, for one entry, on purpose.
    const item = JSON.parse(await reveal_item(id));
    byId('item-id').value = id;
    byId('item-name').value = item.title;
    byId('item-project').value = item.project || '';
    byId('item-username').value = item.username;
    byId('item-password').value = item.password;
    byId('item-url').value = item.url;
    byId('item-notes').value = item.notes;
    editingItem = true;
    byId('item-delete').hidden = false;
  } else {
    byId('item-id').value = '';
    // A new entry lands in whatever project the cabinet was showing. That is the whole point
    // of picking one before pressing «Добавить» — otherwise the choice would be decoration.
    byId('item-project').value = selectedProject || '';
    editingItem = false;
    byId('item-delete').hidden = true;
  }

  renderItemTitle();
  renderProjectOptions();
}

/**
 * The project names already in use, or none if they cannot be read.
 *
 * They are only a suggestion for the project field, so a failure here must not be able to
 * stop someone from saving a password.
 */
async function loadProjectNames() {
  try {
    return JSON.parse(await list_projects());
  } catch {
    return [];
  }
}

/** Offers the names already in use, without preventing a new one from being typed. */
function renderProjectOptions() {
  const options = byId('project-options');
  options.replaceChildren();

  for (const name of projects) {
    const option = document.createElement('option');
    option.value = name;
    options.append(option);
  }
}

function currentDraft() {
  return {
    title: byId('item-name').value,
    project: byId('item-project').value,
    username: byId('item-username').value,
    password: byId('item-password').value,
    url: byId('item-url').value,
    notes: byId('item-notes').value,
    totp: null,
  };
}

// --- event wiring -----------------------------------------------------------

// Every picker on every screen, so a language chosen in the header of one screen is the
// language of all of them.
for (const select of document.querySelectorAll('select[data-testid="language-select"]')) {
  select.addEventListener('change', (event) => setLocale(event.target.value));
}

byId('register-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  dismiss();

  const password = byId('register-password').value;
  const identifier = byId('register-identifier').value.trim();

  if (!identifier) {
    complain(t('register-error-identifier'));
    return;
  }
  if (password !== byId('register-confirm').value) {
    complain(t('register-error-mismatch'));
    return;
  }
  if (password.length < 12) {
    complain(t('register-error-short'));
    return;
  }

  try {
    const created = JSON.parse(
      await withBusy(byId('register-submit'), () =>
        create_account(window.location.origin, identifier, password),
      ),
    );
    unlocked = true;
    kitPending = true;
    byId('kit-text').textContent = created.emergency_kit;
    say(byId('kit-copy'), 'kit-copy');
    go('#/kit');
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  dismiss();

  const identifier = byId('login-identifier').value.trim();
  const password = byId('login-password').value;

  if (!identifier || !password) {
    complain(t('login-error-missing'));
    return;
  }

  try {
    await withBusy(byId('login-submit'), () =>
      unlock(window.location.origin, identifier, password),
    );
    unlocked = true;
    go('#/vault');
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('kit-copy').addEventListener('click', async () => {
  const copied = await copyText(byId('kit-text').textContent);
  say(byId('kit-copy'), copied ? 'kit-copied' : 'kit-copy-manual');
});

byId('kit-done').addEventListener('click', () => {
  kitPending = false;
  go('#/vault');
});

byId('vault-sync').addEventListener('click', async () => {
  dismiss();
  try {
    await withBusy(byId('vault-sync'), () => sync_now());
    await loadVault();
  } catch (error) {
    complain(describe(error));
    await loadVault().catch(() => {});
  }
});

byId('vault-add').addEventListener('click', () => go('#/item/new'));

byId('vault-lock').addEventListener('click', signOut);

// The header control, whichever of the two things it currently is.
byId('topbar-auth').addEventListener('click', async () => {
  if (unlocked) {
    await signOut().catch((error) => complain(describe(error)));
    return;
  }
  go('#/login');
});

byId('item-reveal').addEventListener('click', () => {
  const field = byId('item-password');
  const revealing = field.type === 'password';
  field.type = revealing ? 'text' : 'password';
  say(byId('item-reveal'), revealing ? 'item-hide' : 'item-reveal');
});

byId('item-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  dismiss();

  const id = byId('item-id').value;
  try {
    await withBusy(byId('item-submit'), async () => {
      const draft = JSON.stringify(currentDraft());
      if (id) {
        await update_item(id, draft);
      } else {
        await add_item(draft);
      }
    });
    go('#/vault');
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('item-delete').addEventListener('click', async () => {
  const id = byId('item-id').value;
  if (!id) {
    return;
  }
  if (!window.confirm(t('item-delete-confirm'))) {
    return;
  }

  dismiss();
  try {
    await delete_item(id);
    go('#/vault');
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

window.addEventListener('hashchange', () => {
  render().catch((error) => complain(describe(error)));
});

// --- the desktop build ------------------------------------------------------

/**
 * Offers the desktop application, if this server has one to offer.
 *
 * The server describes the build it is serving — name, size, SHA-256 — rather than the page
 * hard-coding a file name. That is what keeps the link honest: a download section appears only
 * when there is a file behind it, and the hash shown is computed from the bytes being served,
 * so it cannot describe a build that was replaced yesterday.
 */
async function loadDesktopBuild() {
  try {
    const response = await fetch('/api/v1/meta');
    if (!response.ok) {
      return;
    }
    const { desktop } = await response.json();
    if (!desktop) {
      return;
    }

    desktopBuild = desktop;
    renderDesktop();
  } catch {
    // Nothing to do and nothing to say: a server that offers no desktop build is a normal
    // server, and an empty section is a better answer than an error nobody can act on.
  }
}

function renderDesktop() {
  if (!desktopBuild) {
    return;
  }

  // The label on the link is a translation key and is set by `applyTranslations()`; only the
  // target is filled in here.
  byId('desktop-link').href = desktopBuild.url;
  byId('desktop-meta').textContent = `${desktopBuild.file} · ${formatBytes(desktopBuild.size)}`;
  byId('desktop-hash').textContent = `SHA-256 ${desktopBuild.sha256}`;
  byId('desktop-hash').hidden = false;
  byId('desktop-block').hidden = false;
}

function formatBytes(bytes) {
  const mebibytes = bytes / (1024 * 1024);
  if (mebibytes >= 1) {
    return t('size-megabytes', { value: mebibytes.toFixed(1) });
  }
  return t('size-kilobytes', { value: Math.max(1, Math.round(bytes / 1024)) });
}

// --- start ------------------------------------------------------------------

// Before anything is shown: the stored language is put on the page, so a reader who chose
// English does not get a screen of Russian first. The markup is the Russian default, which is
// also the fallback for a stored value that is neither language.
applyLocale(storedLocale());

init()
  .then(async () => {
    boot.hidden = true;
    byId('app').hidden = false;

    // The module starts locked on every load — it holds nothing between page loads — so the
    // status is only needed to seed the guard, not to restore a session.
    const state = JSON.parse(await status());
    unlocked = state.unlocked;
    lastSync = state.last_sync || null;

    await render();

    // After the first screen is up: this is a side note on the landing page, not a reason to
    // hold the portal back if the server is slow to answer.
    loadDesktopBuild();
  })
  .catch((error) => {
    bootFailure = describe(error);
    renderBoot();
  });
