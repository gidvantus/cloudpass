// Every English word the desktop client shows.
//
// A translation of `locales-ru.js`, key for key. That table is the source of meaning and
// Russian is what this application starts in; this one is what a reader gets who has chosen
// English in the picker. `scripts/locales-check.mjs` holds the two together — it fails on a
// key that exists in one table and not the other, on an empty string, and on an entry that is
// identical in both languages, because that last one is what an untranslated line looks like.
//
// `err-*` keys are looked up as `err-` plus the key the Rust command reported, with
// underscores turned into dashes: `err-wrong-password` answers `wrong_password`. The command
// also sends an English `detail` string; nothing here reads it, because this is where prose
// lives and that is a diagnostic.

export default {
  'nav-language': 'Interface language',
  'language-ru': 'Russian',
  'language-en': 'English',

  'status-starting': 'starting…',
  'status-locked': 'locked',
  'status-no-vault': 'no vault on this machine',
  'status-unlocked': 'unlocked · {items}',
  'status-unlocked-pending': 'unlocked · {items} · {pending}',
  'status-items': 'items: {count}',
  'status-pending': 'to send: {count}',

  'join-title': 'Sign in to an existing account',
  'join-hint':
    'Enter the account name and master password you registered with. Everything on the server is ciphertext, so it is these two things — not a copied file — that make this machine able to read your vault. This machine gets its own device key; nothing is copied from the other one.',
  'join-identifier-label': 'Account name',
  'join-password-label': 'Master password',
  'join-submit': 'Sign in',
  'join-cancel': 'Back',
  'join-trust-hint':
    "This is the first time this machine has met the server, so it has to take the server's key on trust at this moment. Every later sign-in is checked against it.",
  'join-no-account': 'No account on this server yet?',
  'join-show-create': 'Create a vault on this machine',

  'thesis-password-title': 'The master password',
  'thesis-password-text': 'It is stretched with Argon2id on this machine and never leaves it.',
  'thesis-server-title': 'What the server holds',
  'thesis-server-text':
    'Ciphertext: envelopes it cannot open, plus no key that could open them.',
  'thesis-opaque-title': 'What sign-in tells the server',
  'thesis-opaque-text':
    'Nothing that checks a password: OPAQUE keeps it off the network and leaves the server with a record it cannot test guesses against.',
  'thesis-kit-title': 'If the master password is gone',
  'thesis-kit-text':
    'The Emergency Kit is the only way back: the recovery key is stored nowhere, so neither this machine nor the server can reproduce it.',

  'create-title': 'Create a vault',
  'create-hint':
    'The master password is stretched with Argon2id on this machine and never leaves it. It cannot be recovered — lose it and the vault is gone.',
  'create-identifier-label': 'Account name',
  'create-password-label': 'Master password',
  'create-confirm-label': 'Repeat it',
  'create-submit': 'Create',
  'create-alt': 'Already have an account — for example one you created in the web portal?',
  'create-show-join': 'Sign in on this machine',

  'unlock-title': 'Unlock',
  'unlock-hint': 'The key is derived here. Nothing is sent anywhere.',
  'unlock-password-label': 'Master password',
  'unlock-submit': 'Unlock',
  'unlock-recover-hint': 'Forgotten the master password?',
  'unlock-show-recover': 'Use a recovery key',

  'recover-title': 'Recover with the Emergency Kit',
  'recover-hint':
    'Type the recovery key exactly as it appears on the kit. Capitalisation and dashes do not matter. The kit keeps no copy of your passwords and neither does this screen: the vault is decrypted on this machine, as always.',
  'recover-key-label': 'Recovery key',
  'recover-new-password-label': 'New master password',
  'recover-confirm-label': 'Repeat it',
  'recover-submit': 'Recover',
  'recover-cancel': 'Cancel',
  'recover-note':
    'A recovery issues a new Emergency Kit and retires the old one. The key you have just used will not work again.',

  'kit-title': 'Your Emergency Kit',
  'kit-new-title': 'Your new Emergency Kit',
  'kit-hint':
    'This is the only copy. It is stored nowhere — not on this machine, not on the server — so print it, or copy it into another password manager, before you close this screen. Anyone who has the recovery key can open the vault.',
  'kit-copy': 'Copy',
  'kit-copied': 'Copied',
  'kit-copy-manual': 'Select the text and copy it',
  'kit-done': 'I have saved it',

  'security-title': 'Security',
  'security-password-title': 'Change the master password',
  'security-password-hint':
    'Re-wraps the vault key, on this machine and on the server, so the new password works everywhere. Your Emergency Kit keeps working: the recovery key does not depend on the password.',
  'security-current-label': 'Current password',
  'security-new-label': 'New password',
  'security-confirm-label': 'Repeat it',
  'security-submit': 'Change password',
  'security-cancel': 'Back',
  'security-kit-title': 'Emergency Kit',
  'security-kit-hint':
    'Issuing a new kit retires the old one immediately: the recovery key on the old piece of paper stops working the moment this succeeds. Do it if the kit has been read aloud, photographed, or left somewhere it should not have been.',
  'security-kit-password-label': 'Master password',
  'security-kit-submit': 'Issue a new kit',
  'security-kit-confirm':
    'Issue a new Emergency Kit? The old recovery key stops working immediately.',

  'vault-title': 'Items',
  'vault-sync': 'Sync',
  'vault-add': 'Add',
  'vault-security': 'Security',
  'vault-lock': 'Lock',
  'vault-empty': 'No items yet. Use “Add”.',
  'vault-untitled': '(untitled)',
  'vault-pending': 'not sent yet',

  'editor-title-new': 'Add an item',
  'editor-title-edit': 'Edit an item',
  'editor-name-label': 'Title',
  'editor-username-label': 'Username',
  'editor-password-label': 'Password',
  'editor-url-label': 'URL',
  'editor-notes-label': 'Notes',
  'editor-submit': 'Save',
  'editor-cancel': 'Cancel',
  'editor-delete': 'Delete',
  'editor-delete-confirm': 'Delete this item? It will be removed from the list.',

  'sync-received': 'received {count}',
  'sync-sent': 'sent {count}',
  'sync-conflicts': '{count} conflict(s)',
  'sync-head-rejected': 'the server refused the change',
  'sync-registered': 'account registered',
  'sync-signed-in': 'signed in',
  'sync-offline': 'the server is unreachable',
  'sync-joined': 'joined an existing account',
  'sync-join-failed': 'joined, but the first sync failed',
  'sync-recovered': 'recovered with the Emergency Kit',
  'sync-kit-issued': 'a new Emergency Kit was issued',
  'sync-password-changed': 'master password changed',
  'sync-not-connected': 'not connected to {url}',

  'err-passwords-mismatch': 'The two passwords do not match.',
  'err-passwords-mismatch-new': 'The two new passwords do not match.',
  'err-password-short':
    'Use at least 12 characters. This password is the only thing protecting the vault.',
  'err-account-name-required': 'Type the account name you registered with.',
  'err-master-password-required': 'Type the master password for that account.',
  'err-recovery-key-required': 'Type the recovery key from the Emergency Kit.',

  'err-locked': 'The vault is locked. Unlock it.',
  'err-no-account': 'There is no such account on this machine.',
  'err-account-exists': 'The account already exists.',
  'err-wrong-password': 'Wrong master password.',
  'err-no-recovery-kit': 'This account has no recovery key.',
  'err-wrong-recovery-key': 'The recovery key does not match this account.',
  'err-item-not-found': 'Item not found.',
  'err-empty-item': 'There is nothing to save — fill in at least the title.',
  'err-crypto': 'The cryptographic operation failed. Nothing was changed.',
  'err-storage': 'The local storage failed.',
  'err-corrupt': 'The stored data cannot be read.',
  'err-serialization': 'The request could not be assembled.',
  'err-network': 'The server is unreachable. Check that it is running and try again.',
  'err-server-refused': 'The server refused the request.',
  'err-protocol': 'The server answered with something this client does not understand.',
  'err-bad-recovery-key': 'That recovery key does not look complete; check it against the kit.',
  'err-bad-id': 'That item identifier is not valid.',
  'err-server-fixed': 'This vault is already registered; the server cannot be changed.',
  'err-not-signed-in': 'Not signed in — lock the vault and unlock it again.',
  'err-unknown': 'The operation failed.',
};
