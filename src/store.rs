use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct CredentialRecord {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_id_hash: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display: Option<String>,
    pub alg: i64,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub discoverable: bool,
    pub cred_prot: u8,
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid credential: {0}")]
    Invalid(String),
}

pub struct CredentialStore {
    conn: Connection,
}

const CREATE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credentials (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id         TEXT NOT NULL,
    rp_id_hash    BLOB NOT NULL,
    user_id       BLOB NOT NULL,
    user_name     TEXT,
    user_display  TEXT,
    alg           INTEGER NOT NULL,
    private_key   BLOB NOT NULL,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    discoverable  INTEGER NOT NULL DEFAULT 0,
    cred_prot     INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_rp_hash
    ON credentials(rp_id_hash);
";

impl CredentialStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(CREATE_SCHEMA)?;
        // Migration for databases created before resident-key support.
        let _ = conn.execute(
            "ALTER TABLE credentials ADD COLUMN cred_prot INTEGER NOT NULL DEFAULT 0",
            [],
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(Self { conn })
    }

    pub fn insert(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO credentials (
                credential_id, rp_id, rp_id_hash, user_id, user_name, user_display,
                alg, private_key, public_key, sign_count, discoverable, cred_prot, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.credential_id,
                record.rp_id,
                record.rp_id_hash,
                record.user_id,
                record.user_name,
                record.user_display,
                record.alg,
                record.private_key,
                record.public_key,
                record.sign_count as i64,
                record.discoverable as i64,
                record.cred_prot as i64,
                record.created_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_id(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        let record = self
            .conn
            .query_row(
                "SELECT credential_id, rp_id, rp_id_hash, user_id, user_name, user_display,
                        alg, private_key, public_key, sign_count, discoverable, cred_prot, created_at
                 FROM credentials WHERE credential_id = ?1",
                params![credential_id],
                row_to_record,
            )
            .optional()?;
        Ok(record)
    }

    pub fn get_by_rp_hash(&self, rp_id_hash: &[u8]) -> Result<Vec<CredentialRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT credential_id, rp_id, rp_id_hash, user_id, user_name, user_display,
                    alg, private_key, public_key, sign_count, discoverable, cred_prot, created_at
             FROM credentials
             WHERE rp_id_hash = ?1
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![rp_id_hash], row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn count_discoverable(&self) -> Result<u64, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM credentials WHERE discoverable = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    pub fn discoverable_rps(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT rp_id, rp_id_hash
             FROM credentials
             WHERE discoverable = 1
             ORDER BY rp_id",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut rps = Vec::new();
        for row in rows {
            rps.push(row?);
        }
        Ok(rps)
    }

    pub fn increment_sign_count(&mut self, credential_id: &[u8]) -> Result<u32, StoreError> {
        let tx = self.conn.transaction()?;
        let current: i64 = tx
            .query_row(
                "SELECT sign_count FROM credentials WHERE credential_id = ?1",
                params![credential_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::Invalid("credential not found".into()))?;
        let next = u32::try_from(current)
            .map_err(|_| StoreError::Invalid("invalid stored sign count".into()))?
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("sign count overflow".into()))?;
        tx.execute(
            "UPDATE credentials SET sign_count = ?1 WHERE credential_id = ?2",
            params![i64::from(next), credential_id],
        )?;
        tx.commit()?;
        Ok(next)
    }
}

fn row_to_record(row: &Row<'_>) -> rusqlite::Result<CredentialRecord> {
    Ok(CredentialRecord {
        credential_id: row.get(0)?,
        rp_id: row.get(1)?,
        rp_id_hash: row.get(2)?,
        user_id: row.get(3)?,
        user_name: row.get(4)?,
        user_display: row.get(5)?,
        alg: row.get(6)?,
        private_key: row.get(7)?,
        public_key: row.get(8)?,
        sign_count: row.get::<_, i64>(9)? as u32,
        discoverable: row.get::<_, i64>(10)? != 0,
        cred_prot: row.get::<_, i64>(11)? as u8,
        created_at: row.get::<_, i64>(12)? as u64,
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
