// Every Russian word the portal shows.
//
// This table is the source of meaning for the portal: it carries the wording that was in
// `index.html` and `app.js` before they learned to translate, moved here verbatim. The
// English table beside it is a translation of this one.
//
// Keys are kebab-case and grouped by prefix: `landing-*` and `footer-*` for the public page,
// `register-*` / `login-*` / `kit-*` for the account screens, `vault-*` and `item-*` for the
// cabinet, `nav-*` for controls that appear on more than one screen, and `sync-*` / `err-*`
// for status and failure — the two groups that both applications share in spirit, because
// the desktop client reports the same events.
//
// `err-*` keys are looked up as `err-` plus the error code the wasm module reports, with
// underscores turned into dashes. Those keys are therefore never written out as literals in
// the page: the code is the contract, and this is where it gets a sentence.
//
// There is deliberately no `sync-ok` entry. A completed synchronization is not a phrase but
// a set of numbers — received, sent, conflicts, a refusal — and the page composes the line
// from `sync-received`, `sync-sent` and friends. See `renderSync` in `app.js`.

export default {
  'page-title': 'CloudPass — менеджер паролей',

  'nav-sign-in': 'Войти',
  'nav-sign-out': 'Выйти',
  'nav-home': 'На главную',
  'nav-to-vault': 'К хранилищу',
  'nav-language': 'Язык интерфейса',
  // The language names are translated rather than left as endonyms: on an English screen a
  // Russian word in the picker is a Russian word on an English screen, and the rule this
  // table exists for is that no such word is left anywhere. Only the value of the option —
  // `ru`, `en` — is a contract; the label is ordinary interface text.
  'language-ru': 'Русский',
  'language-en': 'Английский',

  'landing-eyebrow': 'Менеджер паролей',
  'landing-title': 'Пароли, которые не\u00a0прочитает никто, кроме вас.',
  'landing-lede':
    'Шифрование происходит в вашем браузере. Сервер получает только шифротекст и не может его открыть — даже если захочет.',
  'landing-create-account': 'Создать аккаунт',
  'landing-principle-1-title': 'Нулевое знание',
  'landing-principle-1-text':
    'Мастер-пароль не покидает устройство. Ключ выводится локально через Argon2id, а сервер хранит только то, что не умеет расшифровывать.',
  'landing-principle-2-title': 'Свой ключ на запись',
  'landing-principle-2-text':
    'AES-256-GCM и отдельный ключ для каждой записи. Связанные данные привязывают шифротекст к месту и ревизии: подменить или перенести запись нельзя.',
  'landing-principle-3-title': 'Возврат на бумаге',
  'landing-principle-3-text':
    'Emergency Kit с ключом восстановления — единственный путь назад. Этот ключ не хранится нигде: ни на сервере, ни на вашем диске.',
  'landing-callout-title': 'Начните с одного пароля.',
  'landing-callout-text':
    'Аккаунт создаётся за минуту. Мастер-пароль восстановить нельзя — сохраните Emergency Kit, который выдаётся сразу после регистрации.',
  'landing-desktop-eyebrow': 'Приложение для Windows',
  'landing-desktop-title': 'То же хранилище, но на своём компьютере',
  'landing-desktop-lede':
    'Портал и приложение открывают один и тот же аккаунт: сохраните пароль здесь — он появится там. Приложение не зависит от браузера и работает, когда сервер недоступен.',
  'landing-desktop-download': 'Скачать для Windows',

  'footer-tagline': 'Шифрование в браузере · сервер не читает данные',

  'register-eyebrow': 'Регистрация',
  'register-title': 'Создать аккаунт',
  'register-lede':
    'Мастер-пароль — единственный ключ к хранилищу. Он не отправляется на сервер и не хранится нигде.',
  'register-identifier-label': 'Имя аккаунта',
  'register-identifier-placeholder': 'alice@example.com',
  'register-password-label': 'Мастер-пароль',
  'register-confirm-label': 'Повторите пароль',
  'register-note': 'Минимум 12 символов. Восстановить его нельзя.',
  'register-submit': 'Создать аккаунт',
  'register-alt-question': 'Уже есть аккаунт?',
  'register-error-identifier': 'Введите имя аккаунта.',
  'register-error-mismatch': 'Пароли не совпадают.',
  'register-error-short':
    'Минимум 12 символов: этот пароль — единственное, что защищает хранилище.',

  'login-eyebrow': 'Вход',
  'login-title': 'Войти в хранилище',
  'login-lede':
    'Хранилище расшифровывается здесь, в этой вкладке. Сервер отдаёт шифротекст и ничего больше.',
  'login-identifier-label': 'Имя аккаунта',
  'login-password-label': 'Мастер-пароль',
  'login-submit': 'Войти',
  'login-alt-question': 'Нет аккаунта?',
  'login-register-link': 'Создать',
  'login-error-missing': 'Введите имя аккаунта и мастер-пароль.',

  'kit-warning': 'Не закрывайте вкладку',
  'kit-eyebrow': 'Emergency Kit',
  'kit-title': 'Сохраните ключ восстановления',
  'kit-lede':
    'Это единственная копия. Она существует только на этом экране — ни на сервере, ни на диске её нет. Распечатайте документ или сохраните его в другом менеджере паролей.',
  'kit-copy': 'Скопировать',
  'kit-copied': 'Скопировано',
  'kit-copy-manual': 'Выделите текст и скопируйте',
  'kit-done': 'Я сохранил',

  'vault-projects': 'Проекты',
  'vault-projects-empty':
    'Проектов пока нет. Назовите проект в записи — он появится здесь.',
  'vault-passwords': 'Пароли',
  'vault-sync': 'Синхронизировать',
  'vault-add': 'Добавить',
  'vault-all-passwords': 'Все пароли',
  'vault-no-project': 'Без проекта',
  'vault-scope-no-project': 'без проекта',
  'vault-untitled': '(без названия)',
  'vault-empty-all': 'Записей пока нет. Начните с «Добавить».',
  'vault-empty-project':
    'В этом проекте пока пусто. Нажмите «Добавить», чтобы положить сюда запись.',
  'vault-copy': 'Скопировать',
  'vault-copy-username': 'Логин',
  'vault-open': 'Открыть',
  'vault-copied': 'Скопировано',

  'item-eyebrow': 'Запись',
  'item-new': 'Новая запись',
  'item-edit': 'Запись',
  'item-name-label': 'Название',
  'item-project-label': 'Проект',
  'item-project-placeholder': 'Без проекта',
  'item-username-label': 'Логин',
  'item-password-label': 'Пароль',
  'item-url-label': 'Адрес',
  'item-notes-label': 'Заметки',
  'item-reveal': 'Показать',
  'item-hide': 'Скрыть',
  'item-submit': 'Сохранить',
  'item-cancel': 'Отмена',
  'item-delete': 'Удалить',
  'item-delete-confirm': 'Удалить запись? Она исчезнет из списка.',

  'boot-loading': 'Загрузка…',
  'boot-failed': 'CloudPass не запустился: {error}',

  'size-megabytes': '{value} МБ',
  'size-kilobytes': '{value} КБ',

  'sync-received': 'получено {count}',
  'sync-sent': 'отправлено {count}',
  'sync-conflicts': 'конфликтов: {count}',
  'sync-head-rejected': 'сервер отказался принять изменение',
  'sync-registered': 'аккаунт зарегистрирован',
  'sync-signed-in': 'вход выполнен, но первая синхронизация не удалась',
  'sync-unavailable': 'сохранено во вкладке, ещё не отправлено',
  'sync-pending': 'не отправлено',

  'err-busy': 'Другая операция ещё выполняется. Подождите секунду.',
  'err-locked': 'Хранилище заблокировано. Войдите заново.',
  'err-no-account': 'На этом устройстве нет такого аккаунта.',
  'err-account-exists': 'Аккаунт уже существует.',
  'err-wrong-password': 'Неверное имя аккаунта или мастер-пароль.',
  'err-no-recovery-kit': 'У этого аккаунта нет ключа восстановления.',
  'err-wrong-recovery-key': 'Ключ восстановления не подходит к этому аккаунту.',
  'err-item-not-found': 'Запись не найдена.',
  'err-empty-item': 'В записи нечего сохранять — заполните хотя бы название.',
  'err-crypto': 'Криптографическая операция не удалась. Данные не изменены.',
  'err-storage': 'Ошибка локального хранилища браузера.',
  'err-corrupt': 'Сохранённые данные не читаются.',
  'err-serialization': 'Не удалось собрать данные запроса.',
  'err-network': 'Сервер недоступен. Проверьте, что он запущен, и попробуйте снова.',
  'err-server-refused': 'Сервер отказал в запросе.',
  'err-protocol': 'Сервер ответил чем-то, что этот клиент не понимает.',
  'err-clipboard-insecure-origin':
    'Браузер не даёт доступ к буферу обмена: для этого нужен https или localhost.',
  'err-clipboard-denied': 'Браузер отказал в доступе к буферу обмена.',
  'err-unknown': 'Операция не удалась.',
};
