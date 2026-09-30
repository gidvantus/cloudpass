// CloudPass desktop frontend.
//
// This layer renders and nothing else. It never sees a key, and it does not hold every
// password: `list_items` returns titles and usernames, and a password arrives only when
// the user opens one item. All cryptography happens in Rust, behind these commands.
//
// Two rules are followed throughout because they are cheap here and expensive later:
// user-supplied text is written with textContent, never innerHTML, and every password
// field is cleared as soon as the call that used it returns.

const { invoke } = window.__TAURI__.core;

const byId = (id) => document.getElementById(id);

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
const footer = byId('footer');
const syncNote = byId('sync-note');

/** Shows a message above the panels. */
function complain(message) {
  banner.textContent = message;
  banner.hidden = false;
}

function clearComplaint() {
  banner.hidden = true;
  banner.textContent = '';
}

/** Turns a rejected command into something worth reading. */
function describe(error) {
  if (error && typeof error === 'object' && 'message' in error) {
    return error.message;
  }
  return String(error);
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

function renderStatus(status) {
  const items = `${status.item_count} item${status.item_count === 1 ? '' : 's'}`;
  if (!status.unlocked) {
    statusLine.textContent = status.has_account ? 'locked' : 'no vault yet';
  } else if (status.pending_count > 0) {
    statusLine.textContent = `unlocked · ${items} · ${status.pending_count} to send`;
  } else {
    statusLine.textContent = `unlocked · ${items}`;
  }

  // What synchronization last did, and whether the server is reachable at all. The
  // vault works without it, so an unreachable server is a note rather than an error.
  const notes = [];
  if (status.last_sync) {
    notes.push(status.last_sync);
  }
  if (status.unlocked && !status.connected) {
    notes.push(`not connected to ${status.server_url}`);
  }
  syncNote.textContent = notes.join(' · ');
  syncNote.hidden = notes.length === 0;

  footer.textContent = status.has_account
    ? `${status.identifier} · Argon2id m=${status.kdf_m_kib} KiB, t=${status.kdf_t}, p=${status.kdf_p} · ${status.data_directory}`
    : `The vault is stored only on this machine. Server: ${status.server_url}`;
}

/** Draws the item list. Titles are user data, so they are set as text. */
function renderItems(items) {
  itemList.replaceChildren();
  emptyHint.hidden = items.length > 0;

  for (const item of items) {
    const row = document.createElement('li');
    row.className = 'item';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'item-button';
    button.addEventListener('click', () => openEditor(item.id));

    const title = document.createElement('span');
    title.className = 'item-title';
    title.textContent = item.title || '(untitled)';
    button.append(title);

    const subtitle = document.createElement('span');
    subtitle.className = 'item-subtitle';
    const parts = [item.username, item.url].filter(Boolean);
    if (item.pending) {
      parts.push('not sent yet');
    }
    subtitle.textContent = parts.join(' · ');
    button.append(subtitle);

    row.append(button);
    itemList.append(row);
  }
}

async function refresh() {
  const status = await invoke('vault_status');
  renderStatus(status);

  if (status.unlocked) {
    showPanel('vault');
    renderItems(await invoke('list_items'));
  } else {
    showPanel(status.has_account ? 'unlock' : 'create');
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
 */
function showKit(document_, { title } = {}) {
  byId('kit-title').textContent = title || 'Your Emergency Kit';
  byId('kit-text').textContent = document_;
  byId('kit-copy').textContent = 'Copy';
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
    byId('editor-title').textContent = 'Edit an item';
    byId('editor-delete').hidden = false;
  } else {
    byId('editor-id').value = '';
    byId('editor-title').textContent = 'Add an item';
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

// --- wiring -----------------------------------------------------------------

byId('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearComplaint();

  const password = byId('create-password').value;
  if (password !== byId('create-confirm').value) {
    complain('The two passwords do not match.');
    return;
  }
  if (password.length < 12) {
    complain('Use at least 12 characters. This password is the only thing protecting the vault.');
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
    showKit(created.emergency_kit, { title: 'Your Emergency Kit' });
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
    complain('Type the account name you registered with.');
    return;
  }
  if (!password) {
    complain('Type the master password for that account.');
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
    complain('The two passwords do not match.');
    return;
  }
  if (password.length < 12) {
    complain('Use at least 12 characters. This password is the only thing protecting the vault.');
    return;
  }
  if (!byId('recover-key').value.trim()) {
    complain('Type the recovery key from the Emergency Kit.');
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
    showKit(created.emergency_kit, { title: 'Your new Emergency Kit' });
  } catch (error) {
    complain(describe(error));
  } finally {
    wipeSecretFields();
  }
});

byId('kit-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(byId('kit-text').textContent);
    byId('kit-copy').textContent = 'Copied';
  } catch {
    // A clipboard the platform refuses is not a reason to lose the key: the text is
    // selectable on screen, and the button says so.
    byId('kit-copy').textContent = 'Select the text and copy it';
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
    complain('The two new passwords do not match.');
    return;
  }
  if (next.length < 12) {
    complain('Use at least 12 characters. This password is the only thing protecting the vault.');
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

  if (
    !window.confirm(
      'Issue a new Emergency Kit? The old recovery key stops working immediately.',
    )
  ) {
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
    showKit(issued.emergency_kit, { title: 'Your new Emergency Kit' });
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
  if (!window.confirm('Delete this item? It will be removed from the list.')) {
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

refresh().catch((error) => complain(describe(error)));
