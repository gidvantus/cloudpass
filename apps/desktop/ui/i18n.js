// The desktop client's translation mechanism, and nothing else.
//
// This file holds no language of its own: every word lives in `locales-ru.js` and
// `locales-en.js`, and this is only the machinery that puts them on the page. The web portal
// has a file with the same shape beside its own tables, because the two are separate
// applications with separate strings — but the contract is deliberately identical, so the
// same habits and the same review apply to both.
//
// Three things are worth stating because they are the whole design:
//
// - `t(key)` returns the **key itself** when there is no entry for it. A real translation is
//   never equal to a key, so a caller can tell "translated" from "missing" without a second
//   function, and a missing key shows up as `err-something` on screen instead of as
//   `undefined`.
// - `applyTranslations()` walks `[data-i18n]` and sets text, or — when `data-i18n-attr` is
//   present — that attribute instead. The attribute form exists for `placeholder`, `title`
//   and `aria-label`, which are not text nodes.
// - Nothing here knows what a locale is called. `createI18n` takes the tables and the default
//   up front, so adding a language is adding a file.

/**
 * Builds a translator over a fixed set of locale tables.
 *
 * @param {Record<string, Record<string, string>>} locales — table per locale, e.g. `{ ru, en }`.
 * @param {string} defaultLocale — the locale used for anything unknown.
 */
export function createI18n(locales, defaultLocale) {
  const fallback = locales[defaultLocale];
  if (!fallback) {
    throw new Error(`no locale table for the default locale ${defaultLocale}`);
  }

  let currentLocale = defaultLocale;
  let table = fallback;

  /**
   * Substitutes `{name}` placeholders.
   *
   * A placeholder with no matching parameter is left alone rather than blanked: half a
   * sentence that still says `{count}` is a bug you can see, and an empty space is not.
   */
  function t(key, params) {
    const template = table[key] ?? fallback[key] ?? key;
    if (typeof template !== 'string' || !params) {
      return template;
    }
    return template.replace(/\{(\w+)\}/g, (whole, name) =>
      Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
    );
  }

  /** Translates every marked element under `root`, attribute form included. */
  function applyTranslations(root = document) {
    for (const element of root.querySelectorAll('[data-i18n]')) {
      const key = element.dataset.i18n;
      const attribute = element.dataset.i18nAttr;
      if (attribute) {
        element.setAttribute(attribute, t(key));
      } else {
        element.textContent = t(key);
      }
    }
  }

  /** Switches the language. An unknown locale falls back to the default. */
  function setLocale(next) {
    currentLocale = Object.prototype.hasOwnProperty.call(locales, next) ? next : defaultLocale;
    table = locales[currentLocale];
    return currentLocale;
  }

  return {
    t,
    applyTranslations,
    get currentLocale() {
      return currentLocale;
    },
    setLocale,
  };
}
