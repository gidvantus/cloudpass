// Every English word the portal shows.
//
// A translation of `locales-ru.js`, key for key. That table is the source of meaning: it
// carries the wording the portal had before it could be translated, moved across verbatim.
// `scripts/locales-check.mjs` holds the two together — it fails on a key that exists in one
// table and not the other, on an empty string, and on an entry that is identical in both
// languages, because that last one is what an untranslated line looks like.
//
// `err-*` keys are looked up as `err-` plus the error code the wasm module reports, with
// underscores turned into dashes: `err-wrong-password` answers the module's `wrong_password`.
// The code is the contract, and this is where it becomes a sentence.
//
// There is deliberately no `sync-ok` entry. A completed synchronization is not a phrase but
// a set of numbers — received, sent, conflicts, a refusal — and the page composes the line
// from `sync-received`, `sync-sent` and friends. See `renderSync` in `app.js`.

export default {
  'page-title': 'CloudPass — password manager',

  'nav-sign-in': 'Sign in',
  'nav-sign-out': 'Sign out',
  'nav-home': 'Home',
  'nav-to-vault': 'To the vault',
  'nav-language': 'Interface language',
  'language-ru': 'Russian',
  'language-en': 'English',

  'landing-eyebrow': 'Password manager',
  'landing-title': 'Passwords nobody but you can read.',
  'landing-lede':
    'Encryption happens in your browser. The server receives ciphertext and cannot open it — even if it wanted to.',
  'landing-create-account': 'Create an account',
  'landing-principle-1-title': 'Zero knowledge',
  'landing-principle-1-text':
    'The master password never leaves the device. The key is derived locally with Argon2id, and the server keeps only what it cannot decrypt.',
  'landing-principle-2-title': 'A key of its own for every record',
  'landing-principle-2-text':
    'AES-256-GCM, and a separate key for every record. Associated data ties the ciphertext to its place and revision: a record cannot be swapped or moved.',
  'landing-principle-3-title': 'A way back, on paper',
  'landing-principle-3-text':
    'The Emergency Kit with its recovery key is the only way back. That key is stored nowhere: not on the server, not on your disk.',
  'landing-callout-title': 'Start with one password.',
  'landing-callout-text':
    'An account takes a minute to create. The master password cannot be recovered — keep the Emergency Kit, which is issued right after registration.',
  'landing-desktop-eyebrow': 'Windows application',
  'landing-desktop-title': 'The same vault, on your own computer',
  'landing-desktop-lede':
    'The portal and the application open the same account: save a password here and it appears there. The application does not need a browser and works when the server is unreachable.',
  'landing-desktop-download': 'Download for Windows',

  'footer-tagline': 'Encryption in the browser · the server never reads your data',

  'register-eyebrow': 'Registration',
  'register-title': 'Create an account',
  'register-lede':
    'The master password is the only key to the vault. It is never sent to the server and is stored nowhere.',
  'register-identifier-label': 'Account name',
  'register-identifier-placeholder': 'alice@example.com',
  'register-password-label': 'Master password',
  'register-confirm-label': 'Repeat the password',
  'register-note': 'At least 12 characters. It cannot be recovered.',
  'register-submit': 'Create an account',
  'register-alt-question': 'Already have an account?',
  'register-error-identifier': 'Type the account name.',
  'register-error-mismatch': 'The passwords do not match.',
  'register-error-short':
    'At least 12 characters: this password is the only thing protecting the vault.',

  'login-eyebrow': 'Sign in',
  'login-title': 'Sign in to the vault',
  'login-lede':
    'The vault is decrypted here, in this tab. The server hands over ciphertext and nothing else.',
  'login-identifier-label': 'Account name',
  'login-password-label': 'Master password',
  'login-submit': 'Sign in',
  'login-alt-question': 'No account yet?',
  'login-register-link': 'Create one',
  'login-error-missing': 'Type the account name and the master password.',

  'kit-warning': 'Do not close the tab',
  'kit-eyebrow': 'Emergency Kit',
  'kit-title': 'Keep the recovery key',
  'kit-lede':
    'This is the only copy. It exists on this screen alone — not on the server, not on your disk. Print the document, or save it in another password manager.',
  'kit-copy': 'Copy',
  'kit-copied': 'Copied',
  'kit-copy-manual': 'Select the text and copy it',
  'kit-done': 'I have saved it',

  'vault-projects': 'Projects',
  'vault-projects-empty':
    'No projects yet. Name one in a record and it will appear here.',
  'vault-passwords': 'Passwords',
  'vault-sync': 'Sync',
  'vault-add': 'Add',
  'vault-all-passwords': 'All passwords',
  'vault-no-project': 'No project',
  'vault-scope-no-project': 'no project',
  'vault-untitled': '(untitled)',
  'vault-empty-all': 'No records yet. Start with “Add”.',
  'vault-empty-project':
    'This project is empty so far. Press “Add” to file a record here.',
  'vault-copy': 'Copy',
  'vault-copy-username': 'Username',
  'vault-open': 'Open',
  'vault-copied': 'Copied',

  'item-eyebrow': 'Record',
  'item-new': 'New record',
  'item-edit': 'Record',
  'item-name-label': 'Title',
  'item-project-label': 'Project',
  'item-project-new-option': '＋ New project…',
  'item-project-new-placeholder': 'Name of the new project',
  'item-project-orphan': '{name} — no such project among the records any more',
  'item-project-orphan-hint':
    'This project has no records left, so it is not in the list. Saving keeps its name on this record.',
  'item-project-error-empty': 'Enter a name for the new project, or choose “No project”.',
  'item-username-label': 'Username',
  'item-password-label': 'Password',
  'item-url-label': 'URL',
  'item-notes-label': 'Notes',
  'item-reveal': 'Show',
  'item-hide': 'Hide',
  'item-submit': 'Save',
  'item-cancel': 'Cancel',
  'item-delete': 'Delete',
  'item-delete-confirm': 'Delete this record? It will disappear from the list.',

  'boot-loading': 'Loading…',
  'boot-failed': 'CloudPass did not start: {error}',

  'size-megabytes': '{value} MB',
  'size-kilobytes': '{value} KB',

  'sync-received': 'received {count}',
  'sync-sent': 'sent {count}',
  'sync-conflicts': 'conflicts: {count}',
  'sync-head-rejected': 'the server refused the change',
  'sync-registered': 'account registered',
  'sync-signed-in': 'signed in, but the first synchronization failed',
  'sync-unavailable': 'saved in the tab, not sent yet',
  'sync-pending': 'not sent',

  'err-busy': 'Another operation is still running. Wait a second.',
  'err-locked': 'The vault is locked. Sign in again.',
  'err-no-account': 'There is no such account on this device.',
  'err-account-exists': 'The account already exists.',
  'err-wrong-password': 'Wrong account name or master password.',
  'err-no-recovery-kit': 'This account has no recovery key.',
  'err-wrong-recovery-key': 'The recovery key does not match this account.',
  'err-item-not-found': 'Record not found.',
  'err-empty-item': 'There is nothing to save — fill in at least the title.',
  'err-crypto': 'The cryptographic operation failed. Nothing was changed.',
  'err-storage': 'The browser’s local storage failed.',
  'err-corrupt': 'The stored data cannot be read.',
  'err-serialization': 'The request could not be assembled.',
  'err-network': 'The server is unreachable. Check that it is running and try again.',
  'err-server-refused': 'The server refused the request.',
  'err-protocol': 'The server answered with something this client does not understand.',
  'err-clipboard-insecure-origin':
    'The browser does not give access to the clipboard: that needs https or localhost.',
  'err-clipboard-denied': 'The browser refused access to the clipboard.',
  'err-unknown': 'The operation failed.',
};
