use sqlite as sql;
use std::path::Path;
use std::str::FromStr;
use std::{fmt, io};
use thiserror::Error;
use time::OffsetDateTime;

use radicle::crypto::PublicKey;
use radicle::node::{Alias, AliasError};

use crate::api::auth::{AuthState, AuthStateError, Session};
use radicle::sql::transaction;
use serde::{Deserialize, Serialize};

pub const SESSIONS_DB_FILE: &str = "sessions.db";
pub const WEBHOOKS_DB_FILE: &str = "webhooks.db";

#[derive(Error, Debug)]
pub enum DbStoreError {
    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Alias error.
    #[error("alias error: {0}")]
    InvalidAlias(#[from] AliasError),

    /// Public Key error.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[from] radicle::crypto::PublicKeyError),

    /// Issue/expiration timestamp error
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(#[from] time::error::ComponentRange),

    #[error("invalid timestamp operation")]
    InvalidTimestampOperation,

    /// An Internal error.
    #[error("internal error: {0}")]
    Internal(#[from] sql::Error),

    /// AuthState error
    #[error(transparent)]
    InvalidAuthState(#[from] AuthStateError),
}

pub struct Db {
    pub con: sql::ConnectionThreadSafe,
}

/// A file-backed session storage

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbStore").finish()
    }
}

pub trait DbStoreTrait {
    /// get database initialization schema script
    fn get_init_schema() -> &'static str;

    fn new(db: Db) -> Self;

    /// migrate database to latest schema
    fn migrate(db: &sql::ConnectionThreadSafe) -> Result<(), DbStoreError> {
        db.execute(Self::get_init_schema())?;
        Ok(())
    }

    /// Open a session storage at the given path. Creates a new session storage if it doesn't exist.
    fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbStoreError>
    where
        Self: Sized,
    {
        let db = sql::Connection::open_thread_safe(path)?;
        Self::migrate(&db)?;

        Ok(Self::new(Db { con: db }))
    }

    /// Same as [`Self::open`], but in read-only mode. This is useful to have multiple
    /// open databases, as no locking is required.
    fn reader<P: AsRef<Path>>(path: P) -> Result<Self, DbStoreError>
    where
        Self: Sized,
    {
        let db = sql::Connection::open_thread_safe_with_flags(
            path,
            sqlite::OpenFlags::new().with_read_only(),
        )?;
        Self::migrate(&db)?;

        Ok(Self::new(Db { con: db }))
    }

    /// Create a new in-memory address book.
    fn memory() -> Result<Self, DbStoreError>
    where
        Self: Sized,
    {
        let db = sql::Connection::open_thread_safe(":memory:")?;
        Self::migrate(&db)?;

        Ok(Self::new(Db { con: db }))
    }
}

pub struct DbStore {
    pub db: Db,
}

impl fmt::Debug for DbStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbStore").field("db", &self.db).finish()
    }
}

impl DbStoreTrait for DbStore {
    fn get_init_schema() -> &'static str {
        Self::SCHEMA
    }

    fn new(db: Db) -> Self {
        DbStore { db }
    }
}

impl DbStore {
    const SCHEMA: &'static str = include_str!("store/schema.sql");
    pub fn get(&self, id: &str) -> Result<Option<Session>, DbStoreError> {
        let mut stmt = self.db.con.prepare(
            "SELECT status,alias,public_key,issued_at,expires_at
                 FROM sessions WHERE id = ?",
        )?;

        stmt.bind((1, id))?;

        if let Some(Ok(row)) = stmt.into_iter().next() {
            let status = row.read::<&str, _>("status");
            let session_status = AuthState::from_str(status)?;
            let alias = Alias::from_str(row.read::<&str, _>("alias"))?;
            let public_key = PublicKey::from_str(row.read::<&str, _>("public_key"))?;
            let issued_at = row.read::<i64, _>("issued_at");
            let expires_at = row.read::<i64, _>("expires_at");

            Ok(Some(Session {
                status: session_status,
                public_key,
                alias,
                issued_at: OffsetDateTime::from_unix_timestamp(issued_at)?,
                expires_at: OffsetDateTime::from_unix_timestamp(expires_at)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn insert(&mut self, id: &str, session: &Session) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut stmt = db.prepare(
                "INSERT INTO sessions (id, status, public_key, alias, issued_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;

            stmt.bind((1, id))?;
            stmt.bind((2, sql::Value::String(session.status.to_string())))?;
            stmt.bind((3, sql::Value::String(session.public_key.into())))?;
            stmt.bind((4, sql::Value::String(session.alias.clone().into())))?;
            stmt.bind((5, session.issued_at.unix_timestamp()))?;
            stmt.bind((6, session.expires_at.unix_timestamp()))?;
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }

    pub fn mark_authorized(
        &mut self,
        id: &str,
        expiry: i64,
        comment: &str,
    ) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut stmt = db.prepare(
                "UPDATE sessions SET
                   status=?1, expires_at=?2, comment=?3
                 WHERE id=?4",
            )?;

            stmt.bind((1, sql::Value::String(AuthState::Authorized.to_string())))?;
            stmt.bind((2, expiry))?;
            stmt.bind((3, comment))?;
            stmt.bind((4, id))?;
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut stmt = db.prepare("DELETE FROM sessions WHERE id = ?1")?;
            stmt.bind((1, id))?;
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }

    pub fn remove_expired(&mut self) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut stmt =
                db.prepare("DELETE FROM sessions WHERE expires_at > 0 AND expires_at < ?1")?;
            stmt.bind((1, OffsetDateTime::now_utc().unix_timestamp()))?;
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Webhook {
    pub repo_id: String,
    pub url: String,
    pub secret: String,
    pub content_type: String,
}

pub struct WebhookDb {
    pub db: Db,
}

impl fmt::Debug for WebhookDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDb").field("db", &self.db).finish()
    }
}

impl DbStoreTrait for WebhookDb {
    fn get_init_schema() -> &'static str {
        Self::SCHEMA
    }

    fn new(db: Db) -> Self {
        WebhookDb { db }
    }
}

impl WebhookDb {
    const SCHEMA: &'static str = include_str!("store/webhooks_schema.sql");

    pub fn insert(&mut self, webhook: &Webhook) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut stmt = db.prepare(
                "INSERT INTO webhooks (repo_id, url, secret, content_type, created_at) \
                VALUES (?1, ?2, ?3, ?4, ?5) \
                ON CONFLICT DO NOTHING",
            )?;

            stmt.bind((1, sql::Value::String(webhook.repo_id.to_owned())))?;
            stmt.bind((2, sql::Value::String(webhook.url.to_owned())))?;
            stmt.bind((3, sql::Value::String(webhook.secret.to_owned())))?;
            stmt.bind((4, sql::Value::String(webhook.content_type.to_owned())))?;
            stmt.bind((5, OffsetDateTime::now_utc().unix_timestamp()))?;
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }

    pub fn remove(&mut self, repo_id: String, url: Option<String>) -> Result<bool, DbStoreError> {
        transaction(&self.db.con, move |db| {
            let mut query = "DELETE FROM webhooks WHERE repo_id = ?1".to_owned();
            if url.is_some() {
                query.push_str(" AND url = ?2");
            }
            let mut stmt = db.prepare(query)?;
            stmt.bind((1, sql::Value::String(repo_id.to_owned())))?;
            if url.is_some() {
                stmt.bind((2, sql::Value::String(url.unwrap())))?;
            }
            stmt.next()?;

            Ok(db.change_count() > 0)
        })
    }

    pub fn get(&mut self, repo_id: String) -> Result<Vec<Webhook>, DbStoreError> {
        let mut stmt = self
            .db
            .con
            .prepare("SELECT repo_id,url,secret,content_type FROM webhooks WHERE repo_id = ?")?;

        stmt.bind((1, sql::Value::String(repo_id.to_owned())))?;
        let mut rows = stmt.into_iter();
        let mut webhooks: Vec<Webhook> = Vec::new();
        while let Some(Ok(row)) = rows.next() {
            let repo_id = row.read::<&str, _>("repo_id").to_owned();
            let url = row.read::<&str, _>("url").to_owned();
            let secret = row.read::<&str, _>("secret").to_owned();
            let content_type = row.read::<&str, _>("content_type").to_owned();
            let wh = Webhook {
                repo_id,
                url,
                secret,
                content_type,
            };
            webhooks.push(wh);
        }
        Ok(webhooks)
    }
}

#[cfg(test)]
mod store_tests {
    use std::ops::{Add, Sub};

    use time::Duration;

    use crate::api::auth::AuthState::Authorized;
    use radicle_crypto::KeyPair;

    use super::*;

    #[test]
    fn test_temp_db() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sessions_test");
        let mut sdb = DbStore::open(path).unwrap();
        let s = generate_sample_session();

        // insert it
        let sid = "my1";
        assert!(sdb.insert(sid, &s).unwrap());

        // find it
        assert!(sdb.get(sid).unwrap().is_some());

        // update it as authorized
        assert!(sdb.mark_authorized(sid, 0, "").unwrap());

        // find it again, it should contain new status and expiration
        let s2 = sdb.get(sid).unwrap().unwrap();
        assert_eq!(s2.issued_at.unix_timestamp(), s.issued_at.unix_timestamp());
        assert_eq!(s2.expires_at.unix_timestamp(), 0);
        assert_eq!(s2.status, Authorized);

        // delete it
        assert!(sdb.remove(sid).unwrap());
    }

    #[test]
    fn test_get_none() {
        let id = "asd";
        let db = DbStore::memory().unwrap();
        let result = db.get(id).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_remove_nothing() {
        let id = "myid";
        let mut db = DbStore::memory().unwrap();
        let removed = db.remove(id).unwrap();

        assert!(!removed);
    }

    #[test]
    fn test_duplicate_insert() {
        let id = "session_id";
        let mut db = DbStore::memory().unwrap();
        let s1 = generate_sample_session();

        assert!(db.insert(id, &s1).unwrap());

        let s2 = generate_sample_session();
        assert!(db.insert(id, &s2).err().is_some());

        // get it back, it should be s1
        let s3 = db.get(id).unwrap().unwrap();
        assert_eq!(s1.public_key, s3.public_key);
        assert_eq!(s1.issued_at.unix_timestamp(), s3.issued_at.unix_timestamp());
        assert_eq!(
            s1.expires_at.unix_timestamp(),
            s3.expires_at.unix_timestamp()
        );
    }

    #[test]
    fn test_remove() {
        let id = "myid";
        let mut db = DbStore::memory().unwrap();
        let removed = db.remove(id).unwrap();

        assert!(!removed);
    }

    #[test]
    fn test_remove_expired() {
        let mut db = DbStore::memory().unwrap();
        let mut s1 = generate_sample_session();
        s1.expires_at = OffsetDateTime::now_utc().sub(Duration::seconds(1));
        assert!(db.insert("id1", &s1).unwrap());

        let mut s2 = generate_sample_session();
        s2.expires_at = s1.expires_at;
        assert!(db.insert("id2", &s2).unwrap());

        let mut s3 = generate_sample_session();
        s3.expires_at = OffsetDateTime::now_utc().add(Duration::seconds(10));
        assert!(db.insert("id3", &s3).unwrap());

        let removed = db.remove_expired().unwrap();
        assert!(removed);

        // Try to get back id1 or id2 should return nothing
        let result = db.get("id1").unwrap();
        assert!(result.is_none());

        let result = db.get("id2").unwrap();
        assert!(result.is_none());

        let s3 = db.get("id3").unwrap();
        assert!(s3.is_some());
    }

    #[test]
    fn test_webhooks() {
        let mut db = WebhookDb::memory().unwrap();
        let wh = Webhook {
            repo_id: "test_repo".to_owned(),
            url: "test_repo_url".to_owned(),
            secret: "secret".to_owned(),
            content_type: "text".to_owned(),
        };

        let added = db.insert(&wh).unwrap();
        assert!(added);

        let whs = db.get(wh.repo_id.to_owned()).unwrap();
        assert_eq!(whs.len(), 1);
        assert_eq!(whs[0].repo_id, wh.repo_id);

        // delete
        db.remove(wh.repo_id.to_owned(), None).unwrap();
        let w2 = db.get(wh.repo_id.to_owned()).unwrap();
        assert!(w2.is_empty());
    }

    #[test]
    fn test_webhooks_ignore_same_repo_url() {
        let mut db = WebhookDb::memory().unwrap();
        let wh = Webhook {
            repo_id: "test_repo".to_owned(),
            url: "test_repo_url".to_owned(),
            secret: "secret".to_owned(),
            content_type: "text".to_owned(),
        };

        let added = db.insert(&wh).unwrap();
        assert!(added);

        // trying to add it again will ignore it
        let added2 = db.insert(&wh).unwrap();
        assert!(!added2);

        let whs = db.get(wh.repo_id.to_owned()).unwrap();
        assert_eq!(whs.len(), 1);
        assert_eq!(whs[0].repo_id, wh.repo_id);
    }

    #[test]
    fn test_webhooks_delete_repo_per_url() {
        let mut db = WebhookDb::memory().unwrap();
        let wh = Webhook {
            repo_id: "test_repo".to_owned(),
            url: "test_repo_url".to_owned(),
            secret: "secret".to_owned(),
            content_type: "text".to_owned(),
        };
        let added = db.insert(&wh).unwrap();
        assert!(added);

        let wh2 = Webhook {
            repo_id: wh.repo_id.clone(),
            url: wh.url.clone().add("_2"),
            secret: wh.secret.clone(),
            content_type: wh.content_type.clone(),
        };
        let wh2_added = db.insert(&wh2).unwrap();
        assert!(wh2_added);

        let whs = db.get(wh.repo_id.to_owned()).unwrap();
        assert_eq!(whs.len(), 2);
        assert_eq!(whs[0].repo_id, wh.repo_id);
        assert_eq!(whs[1].repo_id, wh.repo_id);

        let del = db.remove(wh.repo_id.to_owned(), Some(wh2.url)).unwrap();
        assert!(del);
        let whs = db.get(wh.repo_id.to_owned()).unwrap();
        assert_eq!(whs.len(), 1);
        assert_eq!(whs[0].url, wh.url);
    }

    fn generate_sample_session() -> Session {
        let kp = KeyPair::generate();
        Session {
            status: AuthState::Authorized,
            public_key: PublicKey::from(kp.pk),
            alias: Alias::from_str("alice").unwrap(),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc().add(Duration::days(1)),
        }
    }
}
