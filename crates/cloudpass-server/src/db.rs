//! Storage: schema and the handful of primitives the handlers need.
//!
//! # What the database is allowed to contain
//!
//! The schema is part of the security argument, not just a persistence detail. Every
//! column either holds a non-secret value (identifiers, revisions, sequence numbers),
//! an opaque blob the server never parses, or OPAQUE protocol material. There is no
//! column for a key, a password or a plaintext item, and the invariant test in
//! `tests/server.rs` asserts that a request trying to supply one is rejected at the
//! deserialization boundary before it can ever reach a statement.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqliteConnection, SqlitePool};
use std::str::FromStr;

use crate::error::ApiResult;

/// The complete schema, applied on every startup.
///
/// `IF NOT EXISTS` throughout makes this idempotent, which is what lets the server
/// boot against a fresh file and an existing one with the same code path.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS server_state (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    user_id              TEXT PRIMARY KEY,
    identifier           TEXT NOT NULL UNIQUE,
    kdf_salt             BLOB NOT NULL,
    kdf_m_kib            INTEGER NOT NULL,
    kdf_t                INTEGER NOT NULL,
    kdf_p                INTEGER NOT NULL,
    account_key_required INTEGER NOT NULL DEFAULT 0,
    opaque_record        BLOB NOT NULL,
    created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS key_envelopes (
    user_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    envelope   BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, kind)
);

-- Credentials other than the master password. Right now exactly one row per account
-- exists, with purpose `recovery`: an OPAQUE registration record for the key printed
-- in the Emergency Kit. It lives here rather than in a column of `accounts` because a
-- second credential is a second record, and because an existing database gains a new
-- table from `CREATE TABLE IF NOT EXISTS` while a new column needs a hand-written
-- migration.
CREATE TABLE IF NOT EXISTS auth_records (
    user_id    TEXT NOT NULL,
    purpose    TEXT NOT NULL,
    record     BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, purpose)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    name               TEXT NOT NULL,
    signing_public_key BLOB,
    created_at         INTEGER NOT NULL,
    last_seen_at       INTEGER,
    revoked_at         INTEGER
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);

-- The signed head of an account's vault: a monotone revision plus a device signature
-- over a commitment to the complete item set. The server stores it but cannot forge
-- one, because it never sees a device's private key. That is what turns a rollback
-- from a silent corruption into a detected attack.
CREATE TABLE IF NOT EXISTS vault_heads (
    user_id          TEXT PRIMARY KEY,
    head_rev         INTEGER NOT NULL,
    state_root       BLOB NOT NULL,
    signature        BLOB NOT NULL,
    signer_device_id TEXT NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);

-- OPAQUE login state between the two requests of one exchange. It holds the server's
-- ephemeral Diffie-Hellman secret, so it is short-lived and never leaves the server:
-- the client gets only an opaque attempt id. `purpose` separates an ordinary login on
-- the master password from one on a recovery key, which are different credentials.
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    state      BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    purpose    TEXT NOT NULL DEFAULT 'master'
);
CREATE INDEX IF NOT EXISTS login_attempts_expiry ON login_attempts(expires_at);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id       TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    name_envelope  BLOB NOT NULL,
    created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS vaults_user ON vaults(user_id);

CREATE TABLE IF NOT EXISTS items (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    vault_id   TEXT NOT NULL,
    rev        INTEGER NOT NULL,
    base_rev   INTEGER NOT NULL,
    envelope   BLOB NOT NULL,
    meta       TEXT NOT NULL DEFAULT '{}',
    deleted    INTEGER NOT NULL DEFAULT 0,
    seq        INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    device_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS items_user_seq ON items(user_id, seq);
CREATE INDEX IF NOT EXISTS items_vault ON items(vault_id);

CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO counters(name, value) VALUES ('sync_seq', 0);
"#;

/// Opens the pool and makes sure the schema exists.
pub async fn connect(database_url: &str) -> ApiResult<SqlitePool> {
    let in_memory = database_url.contains(":memory:");

    let options = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| crate::error::ApiError::Internal(format!("database url: {e}")))?
        .create_if_missing(true)
        .foreign_keys(true);

    // An in-memory SQLite database belongs to the connection that created it, so a
    // multi-connection pool would hand out several different empty databases. Pinning
    // the pool to one connection is what makes `:memory:` mean one database. Handlers
    // are written so that nothing holds a transaction and a second connection at the
    // same time, which is what keeps this from deadlocking.
    let max_connections = if in_memory { 1 } else { 8 };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;

    apply_schema(&pool).await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Applies [`SCHEMA`]. Idempotent.
pub async fn apply_schema(pool: &SqlitePool) -> ApiResult<()> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    Ok(())
}

/// Brings an existing database up to the current schema.
///
/// `CREATE TABLE IF NOT EXISTS` covers new tables but silently does nothing about a
/// column added to an existing one, so columns are checked explicitly. This is a
/// deliberately small mechanism: when the schema starts changing in ways this cannot
/// express, it should be replaced by a real migration tool rather than grown.
pub async fn migrate(pool: &SqlitePool) -> ApiResult<()> {
    // Device signing keys arrived with vault heads. Older rows keep NULL and any
    // device that has not logged in since simply cannot sign a head yet.
    ensure_column(pool, "devices", "signing_public_key", "BLOB").await?;

    // Recovery credentials arrived with the Emergency Kit. An attempt row written by
    // an older build was an ordinary login by construction, so `master` is the correct
    // value for it rather than a hopeful default.
    ensure_column(
        pool,
        "login_attempts",
        "purpose",
        "TEXT NOT NULL DEFAULT 'master'",
    )
    .await?;
    Ok(())
}

async fn ensure_column(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> ApiResult<()> {
    // Table and column names come from constants in this file, never from a request.
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await?;

    if rows
        .iter()
        .any(|row| row.get::<String, _>("name") == column)
    {
        return Ok(());
    }

    sqlx::raw_sql(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

/// Reads a blob from `server_state`, generating and storing it on first use.
///
/// The server's OPAQUE setup and the secret behind fake KDF salts both live here. If
/// the setup is lost, every account becomes unable to log in, so in a real deployment
/// this row belongs in a backup that is separate from the item data.
pub async fn load_or_create_state<F>(
    pool: &SqlitePool,
    name: &str,
    generate: F,
) -> ApiResult<Vec<u8>>
where
    F: FnOnce() -> Vec<u8>,
{
    if let Some(row) = sqlx::query("SELECT value FROM server_state WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?
    {
        use sqlx::Row;
        return Ok(row.get::<Vec<u8>, _>("value"));
    }

    let value = generate();
    sqlx::query("INSERT INTO server_state(name, value) VALUES (?, ?)")
        .bind(name)
        .bind(&value)
        .execute(pool)
        .await?;
    Ok(value)
}

/// Allocates the next sync sequence number.
///
/// Monotonic by construction and assigned inside the caller's transaction, so a
/// client's cursor can never miss a row: either the write committed and its sequence
/// is visible, or it did not happen at all.
pub async fn next_seq(conn: &mut SqliteConnection) -> ApiResult<i64> {
    sqlx::query("UPDATE counters SET value = value + 1 WHERE name = 'sync_seq'")
        .execute(&mut *conn)
        .await?;
    let seq: i64 = sqlx::query_scalar("SELECT value FROM counters WHERE name = 'sync_seq'")
        .fetch_one(&mut *conn)
        .await?;
    Ok(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn schema_applies_twice_without_error() {
        let pool = connect("sqlite::memory:").await.expect("connect");
        apply_schema(&pool).await.expect("second application");
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic() {
        let pool = connect("sqlite::memory:").await.expect("connect");
        let mut conn = pool.acquire().await.expect("acquire");

        let first = next_seq(&mut conn).await.expect("first");
        let second = next_seq(&mut conn).await.expect("second");
        assert_eq!(second, first + 1);
    }

    #[tokio::test]
    async fn generated_state_is_persisted_and_reused() {
        let pool = connect("sqlite::memory:").await.expect("connect");
        let created = load_or_create_state(&pool, "x", || vec![1, 2, 3])
            .await
            .unwrap();
        let again = load_or_create_state(&pool, "x", || vec![9, 9])
            .await
            .unwrap();
        assert_eq!(created, vec![1, 2, 3]);
        assert_eq!(again, vec![1, 2, 3], "the generator must not run twice");
    }

    /// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists, so
    /// the column added with recovery credentials needs the explicit migration to
    /// reach a database written by an earlier build.
    #[tokio::test]
    async fn migration_adds_the_attempt_purpose_to_an_older_database() {
        let pool = connect("sqlite::memory:").await.expect("connect");

        // Recreate the table as an earlier build left it.
        sqlx::raw_sql("DROP TABLE login_attempts")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE login_attempts (
                 attempt_id TEXT PRIMARY KEY,
                 identifier TEXT NOT NULL,
                 state      BLOB NOT NULL,
                 expires_at INTEGER NOT NULL
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        migrate(&pool).await.expect("migrate");

        let rows = sqlx::query("PRAGMA table_info(login_attempts)")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(
            rows.iter()
                .any(|row| row.get::<String, _>("name") == "purpose"),
            "the migration must add the purpose column"
        );
    }
}
