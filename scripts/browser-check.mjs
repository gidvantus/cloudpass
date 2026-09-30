// Drives the portal in a real browser, over the Chrome DevTools Protocol.
//
// Why this exists: everything else in the repository tests the wasm module or the server, and
// neither of those can see the page. A routing bug, a `hidden` attribute that does not hide, a
// stylesheet that overrides it, a form whose submit handler throws — all of those pass every
// Rust test and every Node smoke check, and all of them are invisible until someone opens the
// page. This opens the page.
//
// No dependencies on purpose. Node 22+ has a global `WebSocket`, and CDP is JSON over it, so
// the whole driver is one file that needs nothing installed.
//
// Usage:
//   1. start the server            cargo run -p cloudpass-server
//   2. start a debuggable browser  chrome --headless=new --remote-debugging-port=9222 \
//                                        --user-data-dir=<dir> --no-sandbox about:blank
//   3. node scripts/browser-check.mjs http://127.0.0.1:8091
//
// The browser is launched separately because starting a child process with piped stdio is
// blocked in the environment this was written in, and a driver that cannot run where the code
// lives is a driver nobody runs.

const origin = (process.argv[2] || 'http://127.0.0.1:8091').replace(/\/$/, '');
const port = process.argv[3] || '9222';

let failures = 0;
const problems = [];

function check(label, ok, detail) {
  if (ok) {
    console.log(`ok    ${label}`);
  } else {
    failures += 1;
    problems.push(`${label}${detail === undefined ? '' : `: ${detail}`}`);
    console.log(`FAIL  ${label}${detail === undefined ? '' : `: ${detail}`}`);
  }
}

// --- a very small CDP client ------------------------------------------------

class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];

    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== undefined && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) {
          reject(new Error(`${message.error.message} (${JSON.stringify(message.error.data ?? '')})`));
        } else {
          resolve(message.result);
        }
        return;
      }
      for (const listener of this.listeners) {
        listener(message);
      }
    });
  }

  on(listener) {
    this.listeners.push(listener);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) {
      payload.sessionId = sessionId;
    }
    this.socket.send(JSON.stringify(payload));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.delete(id)) {
          reject(new Error(`${method} timed out`));
        }
      }, 30000);
    });
  }
}

async function connect() {
  const target = await fetch(`http://127.0.0.1:${port}/json/version`);
  const info = await target.json();
  const socket = new WebSocket(info.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('the debugger socket failed')), {
      once: true,
    });
  });
  return new Cdp(socket);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --- the run ----------------------------------------------------------------

const cdp = await connect();
const pageErrors = [];

const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });

cdp.on((message) => {
  if (message.method === 'Runtime.exceptionThrown') {
    const details = message.params?.exceptionDetails;
    pageErrors.push(details?.exception?.description || details?.text || 'unknown exception');
  }
  if (message.method === 'Log.entryAdded' && message.params?.entry?.level === 'error') {
    pageErrors.push(message.params.entry.text);
  }
});

await cdp.send('Runtime.enable', {}, sessionId);
await cdp.send('Log.enable', {}, sessionId);
await cdp.send('Page.enable', {}, sessionId);

/** Evaluates an expression in the page and returns its value. */
async function evaluate(expression, { awaitPromise = false } = {}) {
  const result = await cdp.send(
    'Runtime.evaluate',
    { expression, awaitPromise, returnByValue: true, userGesture: true },
    sessionId,
  );
  if (result.exceptionDetails) {
    throw new Error(
      result.exceptionDetails.exception?.description || result.exceptionDetails.text,
    );
  }
  return result.result.value;
}

/** Evaluates and waits until `ready` reports true, or gives up. */
async function waitFor(description, expression, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) {
      return true;
    }
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${description}`);
}

/** Visible means: the element has a box, and no ancestor is hidden. */
const visible = (id) => `(() => {
  const el = document.getElementById(${JSON.stringify(id)});
  if (!el) return false;
  const style = getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden' && el.getClientRects().length > 0;
})()`;

await cdp.send('Page.navigate', { url: `${origin}/` }, sessionId);
await waitFor('the module to start', `document.getElementById('boot').hidden === true`);
console.log('ok    the portal started in a real browser');

// 1. The thing that was broken: `hidden` has to actually hide.
{
  const displayed = await evaluate(`(() => {
    const names = ['view-landing','view-register','view-login','view-kit','view-vault','view-item'];
    return names.filter((id) => {
      const el = document.getElementById(id);
      return el && getComputedStyle(el).display !== 'none';
    });
  })()`);
  check(
    'exactly one screen is displayed',
    Array.isArray(displayed) && displayed.length === 1,
    `displayed: ${JSON.stringify(displayed)}`,
  );
  check('and it is the landing', displayed?.[0] === 'view-landing');
}

// 2. Separate screens for registration and sign-in.
await evaluate(`location.hash = '#/register'`);
await waitFor('the registration screen', visible('view-register'));
check('the registration screen shows', await evaluate(visible('view-register')));
check('and the landing is gone', !(await evaluate(visible('view-landing'))));
check('and sign-in is not also on screen', !(await evaluate(visible('view-login'))));

await evaluate(`location.hash = '#/login'`);
await waitFor('the sign-in screen', visible('view-login'));
check('the sign-in screen shows', await evaluate(visible('view-login')));
check('and registration is gone', !(await evaluate(visible('view-register'))));

// 3. Registration, as a person would do it.
const identifier = `browser-${Date.now()}@example.com`;
const password = 'a thoroughly unremarkable master password';

await evaluate(`location.hash = '#/register'`);
await waitFor('the registration screen', visible('view-register'));
await evaluate(`(() => {
  document.getElementById('register-identifier').value = ${JSON.stringify(identifier)};
  document.getElementById('register-password').value = ${JSON.stringify(password)};
  document.getElementById('register-confirm').value = ${JSON.stringify(password)};
  document.getElementById('register-form').requestSubmit();
  return true;
})()`);

try {
  await waitFor('the emergency kit', visible('view-kit'));
  check('registration reaches the emergency kit', true);
} catch (error) {
  const banner = await evaluate(
    `document.getElementById('banner').hidden ? '' : document.getElementById('banner').textContent`,
  );
  check('registration reaches the emergency kit', false, banner || error.message);
}

const kitLength = await evaluate(`document.getElementById('kit-text').textContent.length`);
check('the kit carries a document', kitLength > 100, `length ${kitLength}`);
check(
  'the kit screen is the only one shown',
  (await evaluate(`['view-landing','view-register','view-login','view-vault'].filter((id) => getComputedStyle(document.getElementById(id)).display !== 'none').length`)) === 0,
);

// The kit cannot be navigated away from while it is unacknowledged.
await evaluate(`location.hash = '#/vault'`);
await sleep(400);
check('the kit screen holds the user until acknowledged', await evaluate(visible('view-kit')));

await evaluate(`document.getElementById('kit-done').click()`);
await waitFor('the vault', visible('view-vault'));
check('acknowledging the kit opens the vault', await evaluate(visible('view-vault')));

// 4. Saving a password.
await evaluate(`document.getElementById('vault-add').click()`);
await waitFor('the editor', visible('view-item'));
await evaluate(`(() => {
  document.getElementById('item-name').value = 'GitHub';
  document.getElementById('item-username').value = 'octocat';
  document.getElementById('item-password').value = 's3cr3t-from-the-browser';
  document.getElementById('item-url').value = 'https://github.com';
  document.getElementById('item-form').requestSubmit();
  return true;
})()`);
await waitFor('the vault after saving', visible('view-vault'));
await waitFor(
  'the item to appear',
  `document.getElementById('item-list').children.length === 1`,
);
check('the saved entry is listed', true);
check(
  'the list does not leak the password into the page',
  !(await evaluate(`document.body.textContent.includes('s3cr3t-from-the-browser')`)),
);

// 5. Locking and signing back in, which is the flow that was reported broken.
await evaluate(`document.getElementById('vault-lock').click()`);
await waitFor('the landing after locking', visible('view-landing'));
check('locking returns to the landing', true);
check('and the session is gone', !(await evaluate(visible('view-vault'))));

await evaluate(`location.hash = '#/login'`);
await waitFor('the sign-in screen', visible('view-login'));
await evaluate(`(() => {
  document.getElementById('login-identifier').value = ${JSON.stringify(identifier)};
  document.getElementById('login-password').value = ${JSON.stringify(password)};
  document.getElementById('login-form').requestSubmit();
  return true;
})()`);

try {
  await waitFor('the vault after signing in', visible('view-vault'));
  await waitFor('the stored item', `document.getElementById('item-list').children.length === 1`);
  check('signing in reaches the vault with the stored entry', true);
} catch (error) {
  const banner = await evaluate(
    `document.getElementById('banner').hidden ? '' : document.getElementById('banner').textContent`,
  );
  check('signing in reaches the vault with the stored entry', false, banner || error.message);
}

// 6. A wrong password has to say so, on the page.
await evaluate(`document.getElementById('vault-lock').click()`);
await waitFor('the landing', visible('view-landing'));
await evaluate(`location.hash = '#/login'`);
await waitFor('the sign-in screen', visible('view-login'));
await evaluate(`(() => {
  document.getElementById('login-identifier').value = ${JSON.stringify(identifier)};
  document.getElementById('login-password').value = 'not the password';
  document.getElementById('login-form').requestSubmit();
  return true;
})()`);
await waitFor('the complaint', `document.getElementById('banner').hidden === false`);
const complaint = await evaluate(`document.getElementById('banner').textContent`);
check('a wrong password is refused with a readable message', complaint.length > 0, complaint);
check('and the vault stays shut', !(await evaluate(visible('view-vault'))));
check(
  'and the message is not raw English crypto jargon',
  !/ciphertext|associated data|AuthFailed/.test(complaint),
  complaint,
);

// 7. The desktop build, if this server has one to offer.
//
// The expectation is read from the server rather than hard-coded, so this is correct both for a
// server with a build and for one without. When there is a build, the file is downloaded and
// hashed in the page: the whole promise of publishing a SHA-256 is that the bytes you receive
// are the bytes that hash describes, and that promise is worth nothing unless something checks
// it.
{
  await evaluate(`location.hash = '#/'`);
  await waitFor('the landing', visible('view-landing'));
  await sleep(300);

  const meta = await evaluate(`fetch('/api/v1/meta').then((r) => r.json())`, {
    awaitPromise: true,
  });

  const offered = await evaluate(`(() => {
    const block = document.getElementById('desktop-block');
    return {
      shown: block ? !block.hidden && getComputedStyle(block).display !== 'none' : false,
      href: document.getElementById('desktop-link').getAttribute('href'),
      label: document.getElementById('desktop-link').textContent.trim(),
      meta: document.getElementById('desktop-meta').textContent,
      hash: document.getElementById('desktop-hash').textContent,
    };
  })()`);

  if (meta.desktop) {
    check('the desktop build is offered on the page', offered.shown, JSON.stringify(offered));
    check(
      'the link points at the file the server advertised',
      typeof offered.href === 'string' && offered.href.endsWith(meta.desktop.file),
      `${offered.href} vs ${meta.desktop.file}`,
    );
    check('the link has a readable label', offered.label.length > 0, offered.label);
    check(
      'the page shows the advertised hash',
      offered.hash.includes(meta.desktop.sha256),
      offered.hash,
    );

    const downloaded = await evaluate(
      `(async () => {
        const response = await fetch(${JSON.stringify(meta.desktop.url)});
        const buffer = await response.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        const hex = [...new Uint8Array(digest)]
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('');
        return {
          status: response.status,
          bytes: buffer.byteLength,
          hex,
          disposition: response.headers.get('content-disposition'),
        };
      })()`,
      { awaitPromise: true },
    );

    check('the download answers', downloaded.status === 200, `status ${downloaded.status}`);
    check(
      'the downloaded bytes hash to the advertised SHA-256',
      downloaded.hex === meta.desktop.sha256,
      `${downloaded.hex} vs ${meta.desktop.sha256}`,
    );
    check(
      'and the size matches too',
      downloaded.bytes === meta.desktop.size,
      `${downloaded.bytes} vs ${meta.desktop.size}`,
    );
    check(
      'the installer arrives as a download',
      typeof downloaded.disposition === 'string' &&
        downloaded.disposition.startsWith('attachment'),
      downloaded.disposition,
    );
  } else {
    check('no build to offer, and the page offers none', !offered.shown);
  }
}

// 8. Nothing threw along the way.
check(
  'no uncaught errors in the page',
  pageErrors.length === 0,
  pageErrors.slice(0, 3).join(' | '),
);

console.log(
  failures === 0 ? '\nAll browser checks passed.' : `\n${failures} check(s) failed.`,
);
process.exit(failures === 0 ? 0 : 1);
