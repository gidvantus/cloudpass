// End-to-end smoke test for the shipped web portal.
//
// This drives the *actual* artifact the server hands to a browser — the generated
// `apps/web/ui/pkg/cloudpass_web.js` and its wasm — against a *real* running server. It
// is the only check that covers the parts a Rust test cannot reach: the wasm-bindgen glue,
// the module's exported ABI, and the `fetch` transport.
//
// It runs under Node rather than a browser because Node 18+ has the same globals the
// transport uses: `fetch`, `Request`, `Headers`, `Response`, `Uint8Array`, `TextEncoder`.
// `window` is defined below to point at the Node global, which is what `web_sys::window()`
// looks for. The one thing that genuinely cannot work here is the clipboard — there is no
// `navigator.clipboard` outside a secure browser context — and that is asserted to fail
// cleanly rather than to crash.
//
// Usage:
//   node scripts/web-smoke.mjs [server-url] [pkg-dir]
//
// The second argument is what makes this usable against a container: point it at a
// directory holding the `cloudpass_web.js` and `cloudpass_web_bg.wasm` that were *downloaded
// from the server*, and the test exercises exactly the artifact a browser would load rather
// than the one on this disk.

import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const serverUrl = process.argv[2] || 'http://127.0.0.1:8090';
const here = dirname(fileURLToPath(import.meta.url));
// `resolve`, not `join`: the second argument is very often an absolute path, and `join`
// would happily glue it onto the working directory and produce a path that cannot exist.
const pkg = process.argv[3]
  ? resolve(process.argv[3])
  : join(here, '..', 'apps', 'web', 'ui', 'pkg');

// `web_sys::window()` looks for a global `window`; in Node the global object is it.
globalThis.window = globalThis;

// The status line is user-facing prose produced by the module, so these two assertions track
// its wording. That is deliberate: asserting on a summary a person reads is what catches a
// push that quietly became a no-op, and the wording is the only thing the API reports about
// it. If the portal's language changes, this is the line that has to change with it.
const SENT_ONE = 'отправлено 1';

let failures = 0;
function check(label, condition, detail) {
  if (condition) {
    console.log(`ok    ${label}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${label}${detail === undefined ? '' : `: ${detail}`}`);
  }
}

function parse(value) {
  return JSON.parse(value);
}

const identifier = `smoke-${Date.now()}@example.com`;
const password = 'a thoroughly unremarkable master password';

// A file URL, not a Windows path: the ESM loader only accepts `file:`/`data:`/`node:`.
const module = await import(pathToFileURL(join(pkg, 'cloudpass_web.js')).href);
const wasmBytes = await readFile(join(pkg, 'cloudpass_web_bg.wasm'));
await module.default({ module_or_path: wasmBytes });
console.log('ok    the wasm module instantiated');

// The API the page uses must all be there; a renamed export is a page that half works.
for (const name of [
  'create_account',
  'unlock',
  'lock',
  'status',
  'list_items',
  'list_projects',
  'reveal_item',
  'copy_password',
  'copy_username',
  'add_item',
  'update_item',
  'delete_item',
  'sync_now',
]) {
  check(`export ${name}`, typeof module[name] === 'function');
}

check('starts locked', parse(module.status()).unlocked === false);

// 1. Register, exactly as the page does.
const created = parse(await module.create_account(serverUrl, identifier, password));
check('registration returns a kit', created.emergency_kit.includes('CPRK1-'));
check('registration leaves the portal unlocked', created.status.unlocked === true);
check('registration reports no items', created.status.item_count === 0);

// 2. Save a password.
const added = parse(
  await module.add_item(
    JSON.stringify({
      title: 'GitHub',
      username: 'octocat',
      password: 's3cr3t-from-the-browser',
      url: 'https://github.com',
      notes: '',
      totp: null,
    }),
  ),
);
const itemId = added.id;
check('the item was added', typeof itemId === 'string' && itemId.length > 0);
check('the status counts it', added.status.item_count === 1);
check(
  'the push reached the server',
  String(added.status.last_sync).includes(SENT_ONE),
  added.status.last_sync,
);

// 3. The list must not carry the secret.
const listed = await module.list_items();
check('the list has one entry', parse(listed).length === 1);
check('the list has no password field', !listed.includes('s3cr3t-from-the-browser'));
check('the list carries the title', listed.includes('GitHub'));

// 4. Revealing is explicit and returns the secret.
const revealed = parse(module.reveal_item(itemId));
check(
  'reveal returns the password',
  revealed.password === 's3cr3t-from-the-browser',
  revealed.password,
);

// 5. Editing, then deleting.
const updated = parse(
  await module.update_item(
    itemId,
    JSON.stringify({
      title: 'GitHub (work)',
      username: 'octocat',
      password: 'rotated',
      url: 'https://github.com',
      notes: 'rotated by the smoke test',
      totp: null,
    }),
  ),
);
check('update reports one item', updated.item_count === 1);
check('update kept the secret out of reach', !JSON.stringify(updated).includes('rotated'));

// 6. Locking forgets everything, and signing in again gets it back.
module.lock();
check('lock forgets the session', parse(module.status()).unlocked === false);
try {
  module.list_items();
  check('a locked portal refuses to list', false, 'it returned items');
} catch {
  check('a locked portal refuses to list', true);
}

// 7. A fresh sign-in, which is what a second browser tab does.
const reopened = parse(await module.unlock(serverUrl, identifier, password));
check('sign-in succeeds', reopened.unlocked === true);
check('sign-in pulls the stored item', reopened.item_count === 1, reopened.item_count);
const afterUnlock = parse(await module.list_items());
check('the item survived the round trip', afterUnlock[0].title === 'GitHub (work)');
check(
  'the updated password came back',
  parse(module.reveal_item(afterUnlock[0].id)).password === 'rotated',
);

// 8. The clipboard has no browser here, so this must fail as an error rather than a panic.
let clipboardFailedCleanly = false;
try {
  await module.copy_password(afterUnlock[0].id);
} catch (error) {
  clipboardFailedCleanly = String(error).length > 0;
}
check('copying outside a browser fails cleanly', clipboardFailedCleanly);

// 9. A wrong password must not sign in.
try {
  await module.unlock(serverUrl, identifier, 'not the password');
  check('a wrong password is refused', false, 'it signed in');
} catch (error) {
  check('a wrong password is refused', String(error).includes('wrong_password'), String(error));
}

// 10. Delete, and confirm it is gone from the server too.
const status = parse(await module.delete_item(afterUnlock[0].id));
check('delete empties the vault', status.item_count === 0);
check(
  'the deletion was sent',
  String(status.last_sync).includes(SENT_ONE),
  status.last_sync,
);

console.log(failures === 0 ? '\nAll smoke checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
