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

const byId = (id) => document.getElementById(id);

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

/**
 * Russian wording for the error codes the module reports.
 *
 * The module's own messages come from crates shared with the desktop client and are in
 * English. Rather than translate those — which would drag this language into a client that
 * has nothing to do with the portal — the code is mapped here and the English sentence is
 * kept as a fallback for anything not in the table. A code is a stable contract; a sentence
 * is not.
 */
const MESSAGES = {
  busy: 'Другая операция ещё выполняется. Подождите секунду.',
  locked: 'Хранилище заблокировано. Войдите заново.',
  no_account: 'На этом устройстве нет такого аккаунта.',
  account_exists: 'Аккаунт уже существует.',
  wrong_password: 'Неверное имя аккаунта или мастер-пароль.',
  no_recovery_kit: 'У этого аккаунта нет ключа восстановления.',
  wrong_recovery_key: 'Ключ восстановления не подходит к этому аккаунту.',
  item_not_found: 'Запись не найдена.',
  empty_item: 'В записи нечего сохранять — заполните хотя бы название.',
  crypto: 'Криптографическая операция не удалась. Данные не изменены.',
  storage: 'Ошибка локального хранилища браузера.',
  corrupt: 'Сохранённые данные не читаются.',
  serialization: 'Не удалось собрать данные запроса.',
  network: 'Сервер недоступен. Проверьте, что он запущен, и попробуйте снова.',
  server_refused: 'Сервер отказал в запросе.',
  protocol: 'Сервер ответил чем-то, что этот клиент не понимает.',
};

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

// --- plumbing ---------------------------------------------------------------

function complain(message) {
  banner.textContent = message;
  banner.hidden = false;
}

function dismiss() {
  banner.hidden = true;
  banner.textContent = '';
}

/**
 * Turns a rejection into something worth showing.
 *
 * The module rejects with a JSON string, because an exception is the only channel
 * wasm-bindgen gives us and a string is the only thing that survives it intact.
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
    if (parsed.code && MESSAGES[parsed.code]) {
      return MESSAGES[parsed.code];
    }
    if (parsed.message) {
      return parsed.message;
    }
  }

  return String(error);
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
function flash(button, label) {
  const original = button.textContent;
  button.textContent = label;
  button.disabled = true;
  window.setTimeout(() => {
    button.textContent = original;
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

// --- routing ----------------------------------------------------------------

/**
 * The header's one control: «Войти» while the vault is shut, «Выйти» once it is open.
 *
 * It reads `unlocked`, which the module owns, rather than a copy kept here, so there is one
 * answer to "is this tab signed in?" and the header cannot drift away from the screens.
 */
function renderAuthAction() {
  const action = byId('topbar-auth');
  action.textContent = unlocked ? 'Выйти' : 'Войти';
  action.dataset.action = unlocked ? 'sign-out' : 'sign-in';
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

  byId('vault-who').textContent = state.identifier || '';
  byId('vault-foot-account').textContent = state.identifier || '';
  byId('vault-status').textContent = state.last_sync || '';

  items = JSON.parse(await list_items());
  projects = JSON.parse(await list_projects());

  // A project exists exactly as long as an entry is filed under it, so the selected one can
  // stop existing between two loads. Falling back to «Все пароли» is the only honest answer:
  // the alternative is an empty list and nothing on screen to click away from.
  if (selectedProject && !projects.includes(selectedProject)) {
    selectedProject = null;
  }

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

  list.append(projectRow('Все пароли', items.length, null));

  for (const name of projects) {
    list.append(projectRow(name, items.filter((item) => item.project === name).length, name));
  }

  // Only offered when it would actually show something. An «Без проекта» row that leads to an
  // empty list is a worse answer than not offering it at all.
  const ungrouped = items.filter((item) => !item.project).length;
  if (ungrouped > 0) {
    list.append(projectRow('Без проекта', ungrouped, ''));
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
  byId('item-empty').hidden = visible.length > 0;
  byId('item-empty').textContent =
    selectedProject === null
      ? 'Записей пока нет. Начните с «Добавить».'
      : 'В этом проекте пока пусто. Нажмите «Добавить», чтобы положить сюда запись.';

  byId('item-scope').textContent =
    selectedProject === null
      ? ''
      : selectedProject === ''
        ? 'без проекта'
        : selectedProject;

  for (const item of visible) {
    const row = document.createElement('li');
    row.className = 'item';
    row.setAttribute('data-testid', 'item-row');
    row.setAttribute('data-item-id', item.id);

    const text = document.createElement('div');
    text.className = 'item-text';

    const title = document.createElement('span');
    title.className = 'item-title';
    title.textContent = item.title || '(без названия)';
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
      parts.push('не отправлено');
    }
    sub.textContent = parts.join(' · ');
    text.append(sub);

    row.append(text);

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    // The button that matters: the password goes from the vault to the clipboard inside the
    // wasm module and never appears in this file or in the document.
    actions.append(
      actionButton('Скопировать', 'btn-solid', 'copy-password', async (button) => {
        await copy_password(item.id);
        flash(button, 'Скопировано');
      }),
    );

    if (item.username) {
      actions.append(
        actionButton('Логин', 'btn-outline', 'copy-username', async (button) => {
          await copy_username(item.id);
          flash(button, 'Скопировано');
        }),
      );
    }

    actions.append(
      actionButton('Открыть', 'btn-outline', 'open-item', () => go(`#/item/${item.id}`)),
    );

    row.append(actions);
    list.append(row);
  }
}

function actionButton(label, variant, testId, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `btn btn-small ${variant}`;
  button.setAttribute('data-testid', testId);
  button.textContent = label;
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

async function loadItem(id) {
  const form = byId('item-form');
  form.reset();
  byId('item-password').type = 'password';
  byId('item-reveal').textContent = 'Показать';

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
    byId('item-title').textContent = 'Запись';
    byId('item-delete').hidden = false;
  } else {
    byId('item-id').value = '';
    // A new entry lands in whatever project the cabinet was showing. That is the whole point
    // of picking one before pressing «Добавить» — otherwise the choice would be decoration.
    byId('item-project').value = selectedProject || '';
    byId('item-title').textContent = 'Новая запись';
    byId('item-delete').hidden = true;
  }

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

byId('register-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  dismiss();

  const password = byId('register-password').value;
  const identifier = byId('register-identifier').value.trim();

  if (!identifier) {
    complain('Введите имя аккаунта.');
    return;
  }
  if (password !== byId('register-confirm').value) {
    complain('Пароли не совпадают.');
    return;
  }
  if (password.length < 12) {
    complain('Минимум 12 символов: этот пароль — единственное, что защищает хранилище.');
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
    byId('kit-copy').textContent = 'Скопировать';
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
    complain('Введите имя аккаунта и мастер-пароль.');
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
  byId('kit-copy').textContent = copied ? 'Скопировано' : 'Выделите текст и скопируйте';
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
  byId('item-reveal').textContent = revealing ? 'Скрыть' : 'Показать';
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
  if (!window.confirm('Удалить запись? Она исчезнет из списка.')) {
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

    byId('desktop-link').href = desktop.url;
    byId('desktop-link').textContent = 'Скачать для Windows';
    byId('desktop-meta').textContent = `${desktop.file} · ${formatBytes(desktop.size)}`;

    const fingerprint = byId('desktop-hash');
    fingerprint.textContent = `SHA-256 ${desktop.sha256}`;
    fingerprint.hidden = false;

    byId('desktop-block').hidden = false;
  } catch {
    // Nothing to do and nothing to say: a server that offers no desktop build is a normal
    // server, and an empty section is a better answer than an error nobody can act on.
  }
}

function formatBytes(bytes) {
  const mebibytes = bytes / (1024 * 1024);
  if (mebibytes >= 1) {
    return `${mebibytes.toFixed(1)} МБ`;
  }
  return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
}

// --- start ------------------------------------------------------------------

init()
  .then(async () => {
    boot.hidden = true;
    byId('app').hidden = false;

    // The module starts locked on every load — it holds nothing between page loads — so the
    // status is only needed to seed the guard, not to restore a session.
    const state = JSON.parse(await status());
    unlocked = state.unlocked;

    await render();

    // After the first screen is up: this is a side note on the landing page, not a reason to
    // hold the portal back if the server is slow to answer.
    loadDesktopBuild();
  })
  .catch((error) => {
    boot.textContent = `CloudPass не запустился: ${describe(error)}`;
  });
