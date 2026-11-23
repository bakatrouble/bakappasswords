use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Mutex, RwLock};

use rusqlite::{Connection, params};
use serde::Serialize;

use crate::secrets::{hash_password, random_token, sha256_hex, verify_password};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL CHECK (kind IN ('basic', 'bearer')),
    label       TEXT NOT NULL,
    username    TEXT UNIQUE,
    secret_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Basic,
    Bearer,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Basic => "basic",
            Kind::Bearer => "bearer",
        }
    }
}

/// Credential as shown to the admin panel. The secret digest never leaves
/// the process.
#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub id: i64,
    pub kind: Kind,
    pub label: String,
    pub username: Option<String>,
    pub created_at: String,
    #[serde(skip)]
    secret_hash: String,
}

/// In-memory lookup tables, rebuilt from SQLite on start and kept in sync
/// by every write.
#[derive(Default)]
struct Index {
    by_id: BTreeMap<i64, Credential>,
    basic_by_user: HashMap<String, i64>,
    bearer_by_hash: HashMap<String, i64>,
}

impl Index {
    fn insert(&mut self, c: Credential) {
        match (c.kind, &c.username) {
            (Kind::Basic, Some(user)) => {
                self.basic_by_user.insert(user.clone(), c.id);
            }
            (Kind::Bearer, _) => {
                self.bearer_by_hash.insert(c.secret_hash.clone(), c.id);
            }
            (Kind::Basic, None) => {}
        }
        self.by_id.insert(c.id, c);
    }

    fn remove(&mut self, id: i64) {
        if let Some(c) = self.by_id.remove(&id) {
            match c.kind {
                Kind::Basic => {
                    if let Some(user) = &c.username {
                        self.basic_by_user.remove(user);
                    }
                }
                Kind::Bearer => {
                    self.bearer_by_hash.remove(&c.secret_hash);
                }
            }
        }
    }
}

pub struct Store {
    conn: Mutex<Connection>,
    index: RwLock<Index>,
    /// Verified against when the username is unknown, so both paths cost
    /// one Argon2 run.
    dummy_hash: String,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;

        let mut index = Index::default();
        let mut stmt = conn.prepare(
            "SELECT id, kind, label, username, secret_hash, created_at FROM credentials",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind: String = row.get(1)?;
            let kind = match kind.as_str() {
                "basic" => Kind::Basic,
                "bearer" => Kind::Bearer,
                other => {
                    return Err(rusqlite::Error::InvalidColumnType(
                        1,
                        other.to_owned(),
                        rusqlite::types::Type::Text,
                    ));
                }
            };
            Ok(Credential {
                id: row.get(0)?,
                kind,
                label: row.get(2)?,
                username: row.get(3)?,
                secret_hash: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        for row in rows {
            index.insert(row?);
        }
        drop(stmt);

        tracing::info!(count = index.by_id.len(), "credentials loaded into memory");

        Ok(Self {
            conn: Mutex::new(conn),
            index: RwLock::new(index),
            dummy_hash: hash_password("unused-dummy-secret")?,
        })
    }

    pub fn list(&self) -> Vec<Credential> {
        self.index
            .read()
            .expect("index lock poisoned")
            .by_id
            .values()
            .cloned()
            .collect()
    }

    pub fn create_basic(
        &self,
        label: &str,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Credential> {
        let hash = hash_password(password)?;
        self.insert(Kind::Basic, label, Some(username), &hash)
    }

    /// Returns the credential and the token. The token is not stored and
    /// cannot be shown again.
    pub fn create_bearer(&self, label: &str) -> anyhow::Result<(Credential, String)> {
        let token = random_token();
        let cred = self.insert(Kind::Bearer, label, None, &sha256_hex(&token))?;
        Ok((cred, token))
    }

    fn insert(
        &self,
        kind: Kind,
        label: &str,
        username: Option<&str>,
        secret_hash: &str,
    ) -> anyhow::Result<Credential> {
        let (id, created_at) = {
            let conn = self.conn.lock().expect("db lock poisoned");
            conn.execute(
                "INSERT INTO credentials (kind, label, username, secret_hash) VALUES (?1, ?2, ?3, ?4)",
                params![kind.as_str(), label, username, secret_hash],
            )?;
            let id = conn.last_insert_rowid();
            let created_at: String = conn.query_row(
                "SELECT created_at FROM credentials WHERE id = ?1",
                [id],
                |row| row.get(0),
            )?;
            (id, created_at)
        };

        let cred = Credential {
            id,
            kind,
            label: label.to_owned(),
            username: username.map(str::to_owned),
            created_at,
            secret_hash: secret_hash.to_owned(),
        };
        self.index
            .write()
            .expect("index lock poisoned")
            .insert(cred.clone());
        Ok(cred)
    }

    /// Returns false when no credential with that id exists.
    pub fn delete(&self, id: i64) -> anyhow::Result<bool> {
        let changed = self
            .conn
            .lock()
            .expect("db lock poisoned")
            .execute("DELETE FROM credentials WHERE id = ?1", [id])?;
        if changed == 0 {
            return Ok(false);
        }
        self.index.write().expect("index lock poisoned").remove(id);
        Ok(true)
    }

    /// Returns the matching credential id on success.
    pub async fn verify_basic(&self, username: &str, password: &str) -> Option<i64> {
        let found = {
            let index = self.index.read().expect("index lock poisoned");
            index
                .basic_by_user
                .get(username)
                .and_then(|id| index.by_id.get(id))
                .map(|c| (c.id, c.secret_hash.clone()))
        };
        let (id, hash) = match found {
            Some((id, hash)) => (Some(id), hash),
            None => (None, self.dummy_hash.clone()),
        };
        let password = password.to_owned();

        let matched = tokio::task::spawn_blocking(move || verify_password(&hash, &password))
            .await
            .unwrap_or(false);
        id.filter(|_| matched)
    }

    /// Returns the matching credential id on success.
    pub fn verify_bearer(&self, token: &str) -> Option<i64> {
        self.index
            .read()
            .expect("index lock poisoned")
            .bearer_by_hash
            .get(&sha256_hex(token))
            .copied()
    }

    /// Cheap round trip to SQLite, used by the health check.
    pub fn ping(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("db lock poisoned");
        conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
        Ok(())
    }
}
