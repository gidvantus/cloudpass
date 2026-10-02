// CloudPass desktop frontend.
//
// This layer renders and nothing else. It never sees a key, and it does not hold every
// password: `list_items` returns titles and usernames, and a password arrives only when
// the user opens one item. All cryptography happens in Rust, behind these commands.
//
// Two rules are followed throughout because they are cheap here and expensive later:
// user-supplied text is written with textContent, never innerHTML, and every password
// field is cleared as soon as the call that used it returns.
//
// The third rule is the language, and it is why this file has no wording in it. Every phrase
// comes from `locales-ru.js` or `locales-en.js` through `i18n.js` — including the ones that
// depend on state. Where a label changes with the state — «Новая запись» against «Правка
// записи» — what changes is the *key* (`data-i18n`), never the text, so switching the language
// re-derives the label from the state instead of freezing it in the language it was drawn in.

import { createI18n } from './i18n.js';
import localesRu from './locales-ru.js';
import localesEn from './locales-en.js';

const { invoke } = window.__TAURI__.core;

const byId = (id) => document.getElementById(id);

// --- the language -----------------------------------------------------------

/** Where the choice lives. The only thing this client ever writes to `localStorage`. */
const LANGUAGE_KEY = 'cloudpass.language';
const DEFAULT_LOCALE = 'ru';

const i18n = createI18n({ ru: localesRu, en: localesEn }, DEFAULT_LOCALE);
const t = (key, params) => i18n.t(key, params);

/** The stored language, or the default for anything that is not one of the two. */
function storedLocale() {
  try {
    return window.localStorage.getItem(LANGUAGE_KEY) === 'en' ? 'en' : DEFAULT_LOCALE;
  } catch {
    // A web view that refuses `localStorage` is not a broken application: the language
    // simply does not survive a restart.
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
function say(element, key) {
  element.dataset.i18n = key;
  element.textContent = t(key);
}

/** Switches the language and remembers it, so the next start is not a fresh start. */
function setLocale(next) {
  const applied = applyLocale(next);
  try {
    window.localStorage.setItem(LANGUAGE_KEY, applied);
  } catch {
    // Losing the choice on restart is a smaller failure than a panel that will not switch.
  }
}

/**
 * Puts a language on the page: the translator, the text, the document language, the picker.
 *
 * The translator is switched here rather than by the caller, because this is the one function
 * both paths go through — the picker, and a stored choice read at start. Switching it only on
 * the first of those leaves a window whose `lang` says `en` while every word in it is Russian,
 * which is precisely the state this change exists to make impossible.
 *
 * Deliberately nothing else. `renderDynamic` redraws only what is derived from state, and the
 * panel that is open is never touched — so the emergency kit on screen, the values typed into
 * the editor and the record being edited all survive a switch untouched.
 */
function applyLocale(locale) {
  const applied = i18n.setLocale(locale);
  document.documentElement.lang = applied;
  byId('language-select').value = applied;
  i18n.applyTranslations();
  renderDynamic();
  return applied;
}

/** Everything whose wording is decided by state rather than by the markup. */
function renderDynamic() {
  // The banner first: it is the one thing on the screen that was written by an action rather
  // than by the markup, and the action's language is not necessarily the reader's.
  renderBanner();
  drawStatus();
  drawItems();
}

const panels = {
  create: byId('create-panel'),
  join: byId('join-panel'),
  unlock: byId('unlock-panel'),
  recover: byId('recover-panel'),
  kit: byId('kit-panel'),
  vault: byId('vault-panel'),
  security: byId('security-panel'),
  editor: byId('editor-panel'),
};

const banner = byId('banner');
const statusLine = byId('status');
const itemList = byId('item-list');
const emptyHint = byId('empty-hint');
const syncNote = byId('sync-note');

/** The last status the vault reported, kept so a language switch does not need another call. */
let lastStatus = null;
/** The last list the vault reported, for the same reason. */
let lastItems = [];

/** What the banner is showing, as a key to translate. */
let complaint = null;

/**
 * Raises a complaint: a locale key, or a descriptor from [`describe`].
 *
 * The banner holds the *key*, not the sentence, because it outlives the language it was raised
 * in. A validation error reported in Russian and then switched to English has to say the same
 * thing in English — the same problem `#editor-title` solves the same way, by keeping the state
 * in `data-i18n` and letting the tables supply the words.
 */
function complain(issue) {
  complaint = typeof issue === 'string' ? { key: issue } : issue;
  renderBanner();
}

function clearComplaint() {
  complaint = null;
  banner.hidden = true;
  banner.textContent = '';
}

/** The text of a complaint: its sentence, translated. */
function renderIssue(issue) {
  return t(issue.key, issue.params);
}

function renderBanner() {
  if (!complaint) {
    return;
  }
  banner.textContent = renderIssue(complaint);
  banner.hidden = false;
}

/**
 * The same complaint, reachable from a script the Rust side evaluates in this window.
 *
 * A refused clipboard write happens in the page and inside a promise, so the command that
 * asked for it has already returned by the time it is known. This is the way back: the
 * clipboard script calls it with a locale key, and the key is translated here like any other.
 */
window.cloudpassSayBanner = (key) => complain({ key });

/**
 * Turns a rejected command into something worth showing.
 *
 * A command rejects with `{ key, detail }`. The key is the contract, and the sentence is looked
 * up by it when the banner is drawn — which happens again after every language switch. `detail`
 * is English prose from the crates shared with the portal and is read by nobody — not the log,
 * and certainly not the screen. A key this client has never heard of falls back to a generic
 * sentence rather than to that prose.
 */
function describe(error) {
  const key = error && typeof error === 'object' ? error.key : null;
  if (key) {
    const lookup = `err-${String(key).replaceAll('_', '-')}`;
    // `t` answers with the key itself when there is no entry, and a sentence is never equal
    // to its key — so this tells "translated" from "unknown" without a second table.
    if (t(lookup) !== lookup) {
      return { key: lookup };
    }
  }
  return { key: 'err-unknown' };
}

function showPanel(name) {
  for (const [key, element] of Object.entries(panels)) {
    element.hidden = key !== name;
  }
}

/** Clears every field of a form that may have held a secret. */
function wipeSecretFields() {
  for (const id of [
    'create-password',
    'create-confirm',
    'join-password',
    'unlock-password',
    'recover-key',
    'recover-password',
    'recover-confirm',
    'password-current',
    'password-new',
    'password-confirm',
    'kit-password',
    'editor-password',
  ]) {
    byId(id).value = '';
  }
}

/**
 * What synchronization last did, as numbers with words around them.
 *
 * `sync-ok` is a marker rather than a sentence — a synchronization that ran is described by
 * how much moved — so it contributes no phrase of its own. Every other key names a state and
 * carries no counts. `error_detail` is never read: it is English prose from a shared crate,
 * and the localized key above is what a person is meant to see.
 */
function describeSync(note) {
  if (!note) {
    return '';
  }

  const parts = [];
  if (note.key !== 'sync-ok') {
    parts.push(t(note.key));
  }
  if (note.received !== null && note.received !== undefined) {
    parts.push(t('sync-received', { count: note.received }));
  }
  if (note.sent !== null && note.sent !== undefined) {
    parts.push(t('sync-sent', { count: note.sent }));
  }
  if (note.head_rejected) {
    parts.push(t('sync-head-rejected'));
  } else if (note.conflicts !== null && note.conflicts !== undefined) {
    parts.push(t('sync-conflicts', { count: note.conflicts }));
  }
  return parts.join(' · ');
}

function renderStatus(status) {
  lastStatus = status;
  drawStatus();
}

function drawStatus() {
  const status = lastStatus;
  if (!status) {
    return;
  }

  const items = t('status-items', { count: status.item_count });
  if (!status.unlocked) {
    statusLine.textContent = status.has_account ? t('status-locked') : t('status-no-vault');
  } else if (status.pending_count > 0) {
    statusLine.textContent = t('status-unlocked-pending', {
      items,
      pending: t('status-pending', { count: status.pending_count }),
    });
  } else {
    statusLine.textContent = t('status-unlocked', { items });
  }

  // What synchronization last did, and whether the server is reachable at all. The
  // vault works without it, so an unreachable server is a note rather than an error.
  const notes = [];
  if (status.last_sync) {
    notes.push(describeSync(status.last_sync));
  }
  if (status.unlocked && !status.connected) {
    notes.push(t('sync-not-connected', { url: status.server_url }));
  }
  syncNote.textContent = notes.join(' · ');
  syncNote.hidden = notes.length === 0;
}

function renderItems(items) {
  lastItems = items;
  drawItems();
}

/** The row markup every item is drawn from, cloned rather than built element by element. */
const itemRowTemplate = byId('item-row-template');

/** Draws the item list. Titles are user data, so they are set as text. */
function drawItems() {
  itemList.replaceChildren();
  emptyHint.hidden = lastItems.length > 0;

  for (const item of lastItems) {
    const row = itemRowTemplate.content.firstElementChild.cloneNode(true);
    row.setAttribute('data-item-id', item.id);

    const button = row.querySelector('.item-button');
    button.addEventListener('click', () => openEditor(item.id));

    button.querySelector('.item-title').textContent = item.title || t('vault-untitled');

    const subtitle = button.querySelector('.item-subtitle');
    const parts = [item.username, item.url].filter(Boolean);
    if (item.pending) {
      parts.push(t('vault-pending'));
    }
    subtitle.textContent = parts.join(' · ');

    // The password never reaches this code: the click asks the vault to put it on the
    // clipboard itself, and the most this side ever learns is whether that worked.
    const copy = row.querySelector('.item-copy');
    copy.setAttribute('data-testid', `copy-password-${item.id}`);
    copy.addEventListener('click', () => copyPassword(item.id, copy));

    itemList.append(row);
  }
}

/** Copies one item's password, without the password entering this page. */
async function copyPassword(id, button) {
  clearComplaint();
  try {
    await withBusy(button, () => invoke('copy_password', { id }));
    flash(button, 'vault-copied');
  } catch (error) {
    complain(describe(error));
  }
}

async function refresh() {
  const status = await invoke('vault_status');
  renderStatus(status);

  if (status.unlocked) {
    showPanel('vault');
    renderItems(await invoke('list_items'));
  } else {
    // Signing in is the first gate: on a machine with no account yet the user is asked to
    // enrol, not to create, and reaches creation through a link from that screen.
    showPanel(status.has_account ? 'unlock' : 'join');
    // Offering a route that cannot work would be worse than not offering it: an account
    // whose record predates the kit has no recovery envelope, and saying so is kinder
    // than a dead end.
    byId('recover-hint').hidden = !status.has_recovery_kit;
  }

  return status;
}

/**
 * Shows the Emergency Kit, which is the only copy the user will ever see.
 *
 * The document is put in a `<pre>` as text, never as markup, and the screen stays up
 * until the user says they saved it. Nothing here writes the key anywhere, so a
 * dismissed panel is a key that no longer exists.
 *
 * The heading is chosen by key rather than by text: an issued kit is a different heading from
 * a kit that was there all along, and which one it is has to survive a language switch.
 */
function showKit(document_, { titleKey = 'kit-title' } = {}) {
  say(byId('kit-title'), titleKey);
  byId('kit-text').textContent = document_;
  say(byId('kit-copy'), 'kit-copy');
  showPanel('kit');
}

/** Opens the editor, either empty or filled from an existing item. */
async function openEditor(id) {
  clearComplaint();
  const form = byId('editor-form');
  form.reset();

  if (id) {
    // The one place a password crosses the boundary, and only for one item.
    const item = await invoke('reveal_item', { id });
    byId('editor-id').value = id;
    byId('editor-name').value = item.title;
    byId('editor-username').value = item.username;
    byId('editor-password').value = item.password;
    byId('editor-url').value = item.url;
    byId('editor-notes').value = item.notes;
    say(byId('editor-title'), 'editor-title-edit');
    byId('editor-delete').hidden = false;
  } else {
    byId('editor-id').value = '';
    say(byId('editor-title'), 'editor-title-new');
    byId('editor-delete').hidden = true;
  }

  showPanel('editor');
  byId('editor-name').focus();
}

function currentDraft() {
  return {
    title: byId('editor-name').value,
    username: byId('editor-username').value,
    password: byId('editor-password').value,
    url: byId('editor-url').value,
    notes: byId('editor-notes').value,
    totp: null,
  };
}

async function withBusy(button, work) {
  button.disabled = true;
  try {
    return await work();
  } finally {
    button.disabled = false;
  }
}

/**
 * Confirms an action on the button itself, without a dialog in the way.
 *
 * What is remembered is the button's *key*, not the sentence on it: a language switched
 * while "Скопировано" is up would otherwise be answered in the language that has just been
 * left. For the same reason the key is put back through `say`, which carries it into
 * `data-i18n` — and a switch in the meantime redraws the list and this button with it.
 */
function flash(button, key) {
  const original = button.dataset.i18n;
  say(button, key);
  button.disabled = true;
  window.setTimeout(() => {
    if (original) {
      say(button, original);
    } else {
      button.textContent = '';
    }
    button.disabled = false;
  }, 1200);
}

// --- wiring -----------------------------------------------------------------

byId('language-select').addEventListener('change', (event) => setLocale(event.target.value));

byId('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const password = byId('create-password').value;
  if (password !== byId('create-confirm').value) {
    complain('err-passwords-mismatch');
    return;
  }
  if (password.length < 12) {
    complain('err-password-short');
    return;
  }

  try {
    const created = await withBusy(byId('create-submit'), () =>
      invoke('create_vault', {
        identifier: byId('create-identifier').value,
        masterPassword: password,
      }),
    );
    await refresh();
    // The kit is shown only after the vault screen exists behind it, so dismissing the
    // panel lands somewhere sensible.
    showKit(created.emergency_kit);
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

// --- joining an account that already exists on the server -------------------

byId('show-join').addEventListener('click', () => {
  clearComplaint();
  wipeSecretFields();
  showPanel('join');
  byId('join-identifier').focus();
});

byId('show-create').addEventListener('click', () => {
  clearComplaint();
  wipeSecretFields();
  showPanel('create');
  byId('create-identifier').focus();
});

byId('join-cancel').addEventListener('click', async () => {
  clearComplaint();
  wipeSecretFields();
  await refresh();
});

byId('join-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const password = byId('join-password').value;
  if (!byId('join-identifier').value.trim()) {
    complain('err-account-name-required');
    return;
  }
  if (!password) {
    complain('err-master-password-required');
    return;
  }

  try {
    await withBusy(byId('join-submit'), () =>
      invoke('enrol_vault', {
        identifier: byId('join-identifier').value,
        masterPassword: password,
      }),
    );
    await refresh();
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('show-recover').addEventListener('click', () => {
  clearComplaint();
  wipeSecretFields();
  showPanel('recover');
  byId('recover-key').focus();
});

byId('recover-cancel').addEventListener('click', async () => {
  clearComplaint();
  wipeSecretFields();
  await refresh();
});

byId('recover-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const password = byId('recover-password').value;
  if (password !== byId('recover-confirm').value) {
    complain('err-passwords-mismatch');
    return;
  }
  if (password.length < 12) {
    complain('err-password-short');
    return;
  }
  if (!byId('recover-key').value.trim()) {
    complain('err-recovery-key-required');
    return;
  }

  try {
    const created = await withBusy(byId('recover-submit'), () =>
      invoke('recover_vault', {
        recoveryKey: byId('recover-key').value,
        masterPassword: password,
      }),
    );
    await refresh();
    // A new kit was issued and the old one is now scrap, so this document is the only
    // working copy in existence.
    showKit(created.emergency_kit, { titleKey: 'kit-new-title' });
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('kit-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(byId('kit-text').textContent);
    say(byId('kit-copy'), 'kit-copied');
  } catch {
    // A clipboard the platform refuses is not a reason to lose the key: the text is
    // selectable on screen, and the button says so.
    say(byId('kit-copy'), 'kit-copy-manual');
  }
});

byId('kit-done').addEventListener('click', async () => {
  clearComplaint();
  await refresh();
});

// --- security ---------------------------------------------------------------

byId('show-security').addEventListener('click', () => {
  clearComplaint();
  wipeSecretFields();
  showPanel('security');
});

byId('security-cancel').addEventListener('click', async () => {
  clearComplaint();
  wipeSecretFields();
  await refresh();
});

byId('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const next = byId('password-new').value;
  if (next !== byId('password-confirm').value) {
    complain('err-passwords-mismatch-new');
    return;
  }
  if (next.length < 12) {
    complain('err-password-short');
    return;
  }

  try {
    await withBusy(byId('password-submit'), () =>
      invoke('change_master_password', {
        currentPassword: byId('password-current').value,
        masterPassword: next,
      }),
    );
    await refresh();
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('new-kit-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  // Read at the moment of the call, not when the page loaded: a dialog that asks in the
  // language the reader has just left is a dialog that has to be answered twice.
  if (!window.confirm(t('security-kit-confirm'))) {
    return;
  }

  try {
    const issued = await withBusy(byId('new-kit-submit'), () =>
      invoke('revive_emergency_kit', {
        masterPassword: byId('kit-password').value,
      }),
    );
    // The password field is cleared before the kit is shown, so a screenshot of the
    // kit cannot also contain the master password.
    wipeSecretFields();
    showKit(issued.emergency_kit, { titleKey: 'kit-new-title' });
  } catch (error) {
    complain(describe(error));
    wipeSecretFields();
  }
});

byId('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  try {
    await withBusy(byId('unlock-submit'), () =>
      invoke('unlock_vault', { masterPassword: byId('unlock-password').value }),
    );
    await refresh();
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('add-item').addEventListener('click', () => openEditor(null));

byId('sync-now').addEventListener('click', async () => {
  clearComplaint();
  try {
    await withBusy(byId('sync-now'), () => invoke('sync_now'));
    await refresh();
  } catch (error) {
    complain(describe(error));
    // The status may still have changed — a refused push updates the head revision —
    // so the view is refreshed either way.
    await refresh().catch(() => {});
  }
});

byId('lock-vault').addEventListener('click', async () => {
  clearComplaint();
  await invoke('lock_vault');
  await refresh();
});

byId('editor-cancel').addEventListener('click', async () => {
  wipeSecretFields();
  await refresh();
});

byId('editor-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const id = byId('editor-id').value;
  try {
    await withBusy(byId('editor-submit'), async () => {
      if (id) {
        await invoke('update_item', { id, draft: currentDraft() });
      } else {
        await invoke('add_item', { draft: currentDraft() });
      }
    });
    await refresh();
  } catch (error) {
    complain(describe(error));
  }
});

byId('editor-delete').addEventListener('click', async () => {
  const id = byId('editor-id').value;
  if (!id) {
    return;
  }
  // Deleting is a tombstone, not a wipe, but the user should still mean it.
  if (!window.confirm(t('editor-delete-confirm'))) {
    return;
  }

  clearComplaint();
  try {
    await invoke('delete_item', { id });
    await refresh();
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

// Before the first panel is up: the stored language is put on the page, so a reader who chose
// English does not get a screen of Russian first. The markup is the Russian default, which is
// also the fallback for a stored value that is neither language.
applyLocale(storedLocale());

refresh().catch((error) => complain(describe(error)));
