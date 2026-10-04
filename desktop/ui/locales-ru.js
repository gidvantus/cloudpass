// Every Russian word the desktop client shows.
//
// This table is the source of meaning for the application, and Russian is what it starts in:
// a fresh install has no stored choice, and the default is `ru`. The English table beside it
// is a translation of this one — the other way round from what the code looked like before,
// when every phrase in this client was English and lived in `commands.rs`.
//
// Keys are kebab-case and grouped by prefix: `status-*` for the line at the top, `join-*` /
// `create-*` / `unlock-*` / `recover-*` for the account screens, `kit-*` for the Emergency
// Kit, `security-*` for the panel that rotates credentials, `vault-*` and `editor-*` for the
// entries, and `sync-*` / `err-*` for status and failure.
//
// `sync-*` is split in two on purpose. A synchronization that ran is not a phrase but a set of
// numbers, and the words for them are `sync-received`, `sync-sent`, `sync-conflicts` and
// `sync-head-rejected`; the other `sync-*` keys name a state — signed in, offline, recovered —
// and carry no counts. Rust sends the key and the numbers; this is the only place either
// becomes a sentence.
//
// `err-*` keys are looked up as `err-` plus the key the Rust command reported, with
// underscores turned into dashes: `err-wrong-password` answers `wrong_password`. A command
// also sends an English `detail` string alongside its key; it is never read, because it is
// prose from crates shared with the portal and this file is where prose lives.

export default {
  'nav-language': 'Язык интерфейса',
  'language-ru': 'Русский',
  'language-en': 'Английский',

  'status-starting': 'запуск…',
  'status-locked': 'заблокировано',
  'status-no-vault': 'на этой машине нет хранилища',
  'status-unlocked': 'разблокировано · {items}',
  'status-unlocked-pending': 'разблокировано · {items} · {pending}',
  // A label and a number rather than `1 запись` / `2 записи`: the label form is correct for
  // every count in both languages, and a plural rule is a mechanism this table does not have.
  'status-items': 'записей: {count}',
  'status-pending': 'к отправке: {count}',

  'join-title': 'Вход в существующий аккаунт',
  'join-hint':
    'Введите имя аккаунта и мастер-пароль, с которыми вы регистрировались. Всё на сервере — шифротекст, поэтому именно эти две вещи, а не скопированный файл, делают эту машину способной прочитать ваше хранилище. Ключ устройства у этой машины свой; с другой ничего не копируется.',
  'join-identifier-label': 'Имя аккаунта',
  'join-password-label': 'Мастер-пароль',
  'join-submit': 'Войти',
  'join-cancel': 'Назад',
  'join-trust-hint':
    'Эта машина встречает сервер впервые, поэтому сейчас она принимает его ключ на доверие. Каждый следующий вход сверяется с ним.',
  'join-no-account': 'Ещё нет аккаунта на этом сервере?',
  'join-show-create': 'Создать хранилище на этой машине',

  'thesis-password-title': 'Мастер-пароль',
  'thesis-password-text':
    'Мастер-пароль не покидает устройство. Ключ выводится локально через Argon2id, а сервер хранит только то, что не умеет расшифровывать.',
  'thesis-server-title': 'Что хранит сервер',
  'thesis-server-text':
    'Шифротекст: конверты, которые он не может открыть, и никакого ключа, который мог бы их открыть.',
  'thesis-opaque-title': 'Что вход сообщает серверу',
  'thesis-opaque-text':
    'Ничего, что проверяло бы пароль: OPAQUE не пускает его в сеть и оставляет серверу запись, по которой нельзя проверять догадки.',
  'thesis-kit-title': 'Если мастер-пароль потерян',
  'thesis-kit-text':
    'Emergency Kit — единственный путь назад: ключ восстановления не хранится нигде, поэтому ни эта машина, ни сервер не могут его воспроизвести.',

  'create-title': 'Создать хранилище',
  'create-hint':
    'Мастер-пароль растягивается Argon2id на этой машине и никогда её не покидает. Восстановить его нельзя: потеряете — хранилище пропадёт.',
  'create-identifier-label': 'Имя аккаунта',
  'create-password-label': 'Мастер-пароль',
  'create-confirm-label': 'Повторите',
  'create-submit': 'Создать',
  'create-alt': 'Уже есть аккаунт — например созданный в web-портале?',
  'create-show-join': 'Войти на этой машине',

  'unlock-title': 'Разблокировать',
  'unlock-hint': 'Ключ выводится здесь. Никуда ничего не отправляется.',
  'unlock-password-label': 'Мастер-пароль',
  'unlock-submit': 'Разблокировать',
  'unlock-recover-hint': 'Забыли мастер-пароль?',
  'unlock-show-recover': 'Использовать ключ восстановления',

  'recover-title': 'Восстановление по Emergency Kit',
  'recover-hint':
    'Введите ключ восстановления точно так, как он напечатан в Kit. Регистр и дефисы не важны. В Kit нет копии ваших паролей, и на этом экране её тоже нет: хранилище расшифровывается на этой машине, как всегда.',
  'recover-key-label': 'Ключ восстановления',
  'recover-new-password-label': 'Новый мастер-пароль',
  'recover-confirm-label': 'Повторите',
  'recover-submit': 'Восстановить',
  'recover-cancel': 'Отмена',
  'recover-note':
    'Восстановление выпускает новый Emergency Kit и отменяет старый. Ключ, который вы только что использовали, больше не сработает.',

  'kit-title': 'Ваш Emergency Kit',
  'kit-new-title': 'Ваш новый Emergency Kit',
  'kit-hint':
    'Это единственная копия. Она не хранится нигде — ни на этой машине, ни на сервере, — поэтому распечатайте её или перенесите в другой менеджер паролей, прежде чем закрыть этот экран. Открыть хранилище сможет любой, у кого есть ключ восстановления.',
  'kit-copy': 'Скопировать',
  'kit-copied': 'Скопировано',
  'kit-copy-manual': 'Выделите текст и скопируйте',
  'kit-done': 'Я сохранил',

  'security-title': 'Безопасность',
  'security-password-title': 'Смена мастер-пароля',
  'security-password-hint':
    'Заново оборачивает ключ хранилища — на этой машине и на сервере, чтобы новый пароль работал везде. Emergency Kit продолжает работать: ключ восстановления не зависит от пароля.',
  'security-current-label': 'Текущий пароль',
  'security-new-label': 'Новый пароль',
  'security-confirm-label': 'Повторите',
  'security-submit': 'Сменить пароль',
  'security-cancel': 'Назад',
  'security-kit-title': 'Emergency Kit',
  'security-kit-hint':
    'Выпуск нового Kit сразу отменяет старый: ключ восстановления на прежней бумажке перестаёт работать в тот момент, когда это удаётся. Делайте так, если Kit читали вслух, фотографировали или оставляли там, где его не должно быть.',
  'security-kit-password-label': 'Мастер-пароль',
  'security-kit-submit': 'Выпустить новый Kit',
  // Asked by a `window.confirm` at the moment of the call, not when the page loaded.
  'security-kit-confirm':
    'Выпустить новый Emergency Kit? Старый ключ восстановления перестанет работать сразу.',

  'vault-title': 'Записи',
  'vault-sync': 'Синхронизировать',
  'vault-add': 'Добавить',
  'vault-security': 'Безопасность',
  'vault-lock': 'Заблокировать',
  'vault-empty': 'Записей пока нет. Нажмите «Добавить».',
  'vault-untitled': '(без названия)',
  'vault-pending': 'не отправлено',
  'vault-copy': 'Скопировать',
  'vault-copied': 'Скопировано',

  'editor-title-new': 'Новая запись',
  'editor-title-edit': 'Правка записи',
  'editor-name-label': 'Название',
  'editor-username-label': 'Логин',
  'editor-password-label': 'Пароль',
  'editor-url-label': 'Адрес',
  'editor-notes-label': 'Заметки',
  'editor-submit': 'Сохранить',
  'editor-cancel': 'Отмена',
  'editor-delete': 'Удалить',
  'editor-delete-confirm': 'Удалить запись? Она исчезнет из списка.',

  'sync-received': 'получено {count}',
  'sync-sent': 'отправлено {count}',
  'sync-conflicts': 'конфликтов: {count}',
  'sync-head-rejected': 'сервер отказался принять изменение',
  'sync-registered': 'аккаунт зарегистрирован',
  'sync-signed-in': 'вход выполнен',
  'sync-offline': 'сервер недоступен',
  'sync-joined': 'подключено к существующему аккаунту',
  'sync-join-failed': 'подключено, но первая синхронизация не удалась',
  'sync-recovered': 'восстановлено по Emergency Kit',
  'sync-kit-issued': 'выпущен новый Emergency Kit',
  'sync-password-changed': 'мастер-пароль изменён',
  'sync-not-connected': 'нет связи с {url}',

  // `update-*` speaks about this application rather than the vault: a newer build is on
  // the server, and the only thing this window may do about it is hand the person the
  // address. `update-available` and `update-copied` are chosen from data at run time, so
  // they are never written in the markup.
  'update-available': 'Доступна версия {latest} — у вас {current}.',
  'update-download': 'Скопировать адрес портала',
  'update-copied': 'Адрес скопирован',
  'update-dismiss': 'Скрыть',

  'err-passwords-mismatch': 'Пароли не совпадают.',
  'err-passwords-mismatch-new': 'Новые пароли не совпадают.',
  'err-password-short':
    'Минимум 12 символов: этот пароль — единственное, что защищает хранилище.',
  'err-account-name-required': 'Введите имя аккаунта, с которым вы регистрировались.',
  'err-master-password-required': 'Введите мастер-пароль для этого аккаунта.',
  'err-recovery-key-required': 'Введите ключ восстановления из Emergency Kit.',

  'err-locked': 'Хранилище заблокировано. Разблокируйте его.',
  'err-no-account': 'На этой машине нет такого аккаунта.',
  'err-account-exists': 'Аккаунт уже существует.',
  'err-wrong-password': 'Неверный мастер-пароль.',
  'err-no-recovery-kit': 'У этого аккаунта нет ключа восстановления.',
  'err-wrong-recovery-key': 'Ключ восстановления не подходит к этому аккаунту.',
  'err-item-not-found': 'Запись не найдена.',
  'err-empty-item': 'В записи нечего сохранять — заполните хотя бы название.',
  'err-crypto': 'Криптографическая операция не удалась. Данные не изменены.',
  'err-storage': 'Ошибка локального хранилища.',
  'err-corrupt': 'Сохранённые данные не читаются.',
  'err-serialization': 'Не удалось собрать данные запроса.',
  'err-network': 'Сервер недоступен. Проверьте, что он запущен, и попробуйте снова.',
  'err-server-refused': 'Сервер отказал в запросе.',
  'err-protocol': 'Сервер ответил чем-то, что этот клиент не понимает.',
  'err-bad-recovery-key': 'Ключ восстановления выглядит неполным — сверьте его с Kit.',
  'err-bad-id': 'Идентификатор записи неверен.',
  'err-server-fixed': 'Это хранилище уже зарегистрировано, сменить сервер нельзя.',
  'err-not-signed-in': 'Вход не выполнен — заблокируйте хранилище и войдите снова.',
  'err-clipboard-insecure-origin':
    'Окно приложения не предоставляет доступ к буферу обмена.',
  'err-clipboard-denied': 'Приложение отказало в доступе к буферу обмена.',
  'err-update-check-failed':
    'Не удалось проверить обновления. Проверьте, что сервер запущен, и попробуйте снова.',
  'err-unknown': 'Операция не удалась.',
};
