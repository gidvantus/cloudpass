// Holds the two locale tables of each application together.
//
// A translation pair drifts in exactly three ways, and this catches all three: a key that was
// added to one table and not the other (a missing phrase becomes the key itself on screen), an
// entry that was emptied, and an entry that was never translated at all — which looks like the
// same string in both tables.
//
// It also checks the other direction: every `data-i18n` key written in a page has to exist in
// both tables, because a marked element with no wording is a control that stays in the language
// of the markup. The reverse — every table key appearing in the markup — is deliberately *not*
// checked: `err-*` and `sync-*` keys are chosen from data at run time, and a check that cannot
// tell them from an unused key would have to be told, in a list, which is a list nobody keeps
// up to date.
//
// No dependencies. The tables are ES modules, and so is this file; they are loaded through a
// `data:` URL because the repository has no `package.json` and a `.js` file without one is
// CommonJS to Node. That is a property of the file extension, not of the file — a browser
// loading the same table as `<script type="module">` sees a module. A `package.json` saying
// `"type": "module"` would fix it too, and would also make every other `.js` file in a Rust
// repository an npm one; an import specifier here is the smaller change.
//
// Usage:  node scripts/locales-check.mjs

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The two applications, and the entries that are allowed to be identical.
 *
 * Those few entries are identical because the text is not language: an example address, and
 * the name of a feature that is called the Emergency Kit in every language the project speaks.
 */
const APPS = [
  {
    name: 'web portal',
    dir: 'apps/web/ui',
    html: 'index.html',
    tables: { ru: 'locales-ru.js', en: 'locales-en.js' },
    identicalOnPurpose: {
      'register-identifier-placeholder': 'an example address, not a sentence',
      'kit-eyebrow': 'the feature is called the Emergency Kit in every language',
    },
  },
  {
    name: 'desktop client',
    dir: 'apps/desktop/ui',
    html: 'index.html',
    tables: { ru: 'locales-ru.js', en: 'locales-en.js' },
    identicalOnPurpose: {
      'security-kit-title': 'the feature is called the Emergency Kit in every language',
    },
  },
];

/** The languages each application must offer, and the default among them. */
const LOCALES = ['ru', 'en'];

let failures = 0;

function check(label, condition, detail) {
  if (condition) {
    console.log(`ok    ${label}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${label}${detail === undefined ? '' : `: ${detail}`}`);
  }
}

/** Imports a file as an ES module whatever its extension means to Node. */
async function loadModule(path) {
  const source = await readFile(path, 'utf8');
  const url = `data:text/javascript;charset=utf-8,${encodeURIComponent(source)}`;
  const module = await import(url);
  return module.default;
}

/** The `data-i18n` keys a page carries, whichever form the element uses. */
function markedKeys(html) {
  // Comments are removed first: this file's own explanation of the convention writes
  // `data-i18n="<key>"` as an example, and an example is not an element.
  const markup = html.replace(/<!--[\s\S]*?-->/g, '');
  return [...markup.matchAll(/data-i18n="([^"]+)"/g)].map((match) => match[1]);
}

for (const app of APPS) {
  const directory = join(root, app.dir);
  console.log(`\n${app.name} (${app.dir})`);

  const tables = {};
  for (const locale of LOCALES) {
    tables[locale] = await loadModule(join(directory, app.tables[locale]));
  }

  const counts = LOCALES.map((locale) => `${locale} ${Object.keys(tables[locale]).length}`);
  console.log(`      ${counts.join(', ')}`);

  // 1. The same set of keys on both sides.
  const reference = LOCALES[0];
  const referenceKeys = new Set(Object.keys(tables[reference]));
  for (const locale of LOCALES.slice(1)) {
    const keys = new Set(Object.keys(tables[locale]));
    const missing = [...referenceKeys].filter((key) => !keys.has(key));
    const extra = [...keys].filter((key) => !referenceKeys.has(key));
    check(
      `${locale} has every key ${reference} has`,
      missing.length === 0,
      missing.slice(0, 5).join(', ') || undefined,
    );
    check(
      `${locale} has no key ${reference} lacks`,
      extra.length === 0,
      extra.slice(0, 5).join(', ') || undefined,
    );
  }

  // 2. Nothing empty, and nothing left untranslated.
  for (const locale of LOCALES) {
    const empty = Object.entries(tables[locale])
      .filter(([, text]) => typeof text !== 'string' || text.trim() === '')
      .map(([key]) => key);
    check(`${locale} has no empty entry`, empty.length === 0, empty.slice(0, 5).join(', ') || undefined);
  }

  const identical = Object.keys(tables[reference])
    .filter((key) => tables.ru[key] === tables.en[key])
    .filter((key) => !(key in app.identicalOnPurpose));
  check(
    'no entry is the same in both languages',
    identical.length === 0,
    identical.length === 0 ? undefined : identical.slice(0, 5).join(', '),
  );

  // 3. Every key the markup asks for is answered by both tables.
  const html = await readFile(join(directory, app.html), 'utf8');
  const marked = new Set(markedKeys(html));
  for (const locale of LOCALES) {
    const unanswered = [...marked].filter((key) => !Object.hasOwn(tables[locale], key));
    check(
      `every data-i18n key in ${app.html} exists in ${app.tables[locale]}`,
      unanswered.length === 0,
      unanswered.slice(0, 5).join(', ') || undefined,
    );
  }
}

console.log(failures === 0 ? '\nAll locale checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
