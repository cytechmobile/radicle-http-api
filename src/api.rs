pub mod auth;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::Method;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use radicle::issue::cache::Issues as _;
use radicle::patch::cache::Patches as _;
use radicle::storage::git::Repository;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::{self, CorsLayer};

use radicle::cob::{issue, patch, Author};
use radicle::identity::{DocAt, RepoId};
use radicle::node::policy::Scope;
use radicle::node::routing::Store;
use radicle::node::AliasStore;
use radicle::node::{Handle, NodeId};
use radicle::storage::{ReadRepository, ReadStorage};
use radicle::{Node, Profile};

mod error;
mod json;
mod v1;

use crate::api::error::Error;
use crate::cache::Cache;
use crate::store::{DbStore, DbStoreError, DbStoreTrait, WebhookDb};
use crate::Options;

pub const RADICLE_VERSION: &str = env!("RADICLE_VERSION");
// This version has to be updated on every breaking change to the radicle-http-api API.
pub const API_VERSION: &str = "1.0.0";

pub const HTTPD_DIR: &str = "httpd";

#[derive(Clone)]
pub struct Context {
    profile: Arc<Profile>,
    cache: Option<Cache>,
    pub session_expiry: time::Duration,
}

impl Context {
    pub fn new(profile: Arc<Profile>, options: &Options) -> Self {
        Self {
            profile,
            cache: options.cache.map(Cache::new),
            session_expiry: options.session_expiry,
        }
    }

    pub fn project_info<R: ReadRepository + radicle::cob::Store>(
        &self,
        repo: &R,
        doc: DocAt,
    ) -> Result<project::Info, error::Error> {
        let (_, head) = repo.head()?;
        let DocAt { doc, .. } = doc;
        let id = repo.id();

        let payload = doc.project()?;
        let aliases = self.profile.aliases();
        let delegates = doc
            .delegates
            .into_iter()
            .map(|did| json::author(&Author::new(did), aliases.alias(did.as_key())))
            .collect::<Vec<_>>();
        let issues = self.profile.issues(repo)?.counts()?;
        let patches = self.profile.patches(repo)?.counts()?;
        let db = &self.profile.database()?;
        let seeding = db.count(&id).unwrap_or_default();

        Ok(project::Info {
            payload,
            delegates,
            threshold: doc.threshold,
            visibility: doc.visibility,
            head,
            issues,
            patches,
            id,
            seeding,
        })
    }

    /// Get a repository by RID, checking to make sure we're allowed to view it.
    pub fn repo(&self, rid: RepoId) -> Result<(Repository, DocAt), Error> {
        let repo = self.profile.storage.repository(rid)?;
        let doc = repo.identity_doc()?;
        // Don't allow accessing private repos.
        if doc.visibility.is_private() {
            return Err(Error::NotFound);
        }
        Ok((repo, doc))
    }

    pub fn open_session_db(&self) -> Result<DbStore, Error> {
        Ok(DbStore::open(self.get_session_db_path()?)?)
    }

    pub fn read_session_db(&self) -> Result<DbStore, Error> {
        Ok(DbStore::reader(self.get_session_db_path()?)?)
    }

    fn get_session_db_path(&self) -> Result<std::path::PathBuf, DbStoreError> {
        let dir = self.profile.home.path().join(HTTPD_DIR);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(dir.join(crate::store::SESSIONS_DB_FILE))
    }

    pub fn open_webhooks_db(&self) -> Result<WebhookDb, Error> {
        Ok(WebhookDb::open(self.get_webhook_db_path()?)?)
    }

    fn get_webhook_db_path(&self) -> Result<std::path::PathBuf, DbStoreError> {
        let dir = self.profile.home.path().join(HTTPD_DIR);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(dir.join(crate::store::WEBHOOKS_DB_FILE))
    }

    #[cfg(test)]
    pub fn profile(&self) -> &Arc<Profile> {
        &self.profile
    }
}

pub fn router(ctx: Context) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .merge(v1::router(ctx))
        .layer(
            CorsLayer::new()
                .max_age(Duration::from_secs(86400))
                .allow_origin(cors::Any)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PATCH,
                    Method::PUT,
                    Method::DELETE,
                ])
                .allow_headers([CONTENT_TYPE, AUTHORIZATION]),
        )
}

async fn root_handler() -> impl IntoResponse {
    let response = json!({
        "path": "/api",
        "links": [
            {
                "href": "/v1",
                "rel": "v1",
                "type": "GET"
            }
        ]
    });

    Json(response)
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaginationQuery {
    #[serde(default)]
    pub show: ProjectQuery,
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub enum ProjectQuery {
    All,
    #[default]
    Pinned,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RawQuery {
    pub mime: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CobsQuery<T> {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub state: Option<T>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PoliciesQuery {
    /// The NID from which to fetch from after tracking a repo.
    pub from: Option<NodeId>,
    pub scope: Option<Scope>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum IssueState {
    Closed,
    #[default]
    Open,
}

impl IssueState {
    pub fn matches(&self, issue: &issue::State) -> bool {
        match self {
            Self::Open => matches!(issue, issue::State::Open),
            Self::Closed => matches!(issue, issue::State::Closed { .. }),
        }
    }
}

#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PatchState {
    #[default]
    Open,
    Draft,
    Archived,
    Merged,
}

impl PatchState {
    pub fn matches(&self, patch: &patch::State) -> bool {
        match self {
            Self::Open => matches!(patch, patch::State::Open { .. }),
            Self::Draft => matches!(patch, patch::State::Draft),
            Self::Archived => matches!(patch, patch::State::Archived),
            Self::Merged => matches!(patch, patch::State::Merged { .. }),
        }
    }
}

mod search {
    use std::cmp::Ordering;

    use nonempty::NonEmpty;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use radicle::crypto::Verified;
    use radicle::identity::{Project, RepoId};
    use radicle::node::routing::Store;
    use radicle::node::AliasStore;
    use radicle::node::Database;
    use radicle::profile::Aliases;
    use radicle::storage::RepositoryInfo;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SearchQueryString {
        pub q: Option<String>,
        pub page: Option<usize>,
        pub per_page: Option<usize>,
    }

    #[derive(Serialize, Deserialize, Eq, Debug)]
    pub struct SearchResult {
        pub rid: RepoId,
        #[serde(flatten)]
        pub payload: Project,
        pub delegates: NonEmpty<serde_json::Value>,
        pub seeds: usize,
        #[serde(skip)]
        pub index: usize,
    }

    impl SearchResult {
        pub fn new(
            q: &str,
            info: RepositoryInfo<Verified>,
            db: &Database,
            aliases: &Aliases,
        ) -> Option<Self> {
            if info.doc.visibility.is_private() {
                return None;
            }
            let payload = info.doc.project().ok()?;
            let index = payload.name().find(q)?;
            let seeds = db.count(&info.rid).unwrap_or_default();
            let delegates = info.doc.delegates.map(|did| match aliases.alias(&did) {
                Some(alias) => json!({
                    "id": did,
                    "alias": alias,
                }),
                None => json!({
                    "id": did,
                }),
            });

            Some(SearchResult {
                rid: info.rid,
                payload,
                delegates,
                seeds,
                index,
            })
        }
    }

    impl Ord for SearchResult {
        fn cmp(&self, other: &Self) -> Ordering {
            match (self.index, other.index) {
                (0, 0) => self.seeds.cmp(&other.seeds),
                (0, _) => std::cmp::Ordering::Less,
                (_, 0) => std::cmp::Ordering::Greater,
                (ai, bi) if ai == bi => self.seeds.cmp(&other.seeds),
                (_, _) => self.seeds.cmp(&other.seeds),
            }
        }
    }

    impl PartialOrd for SearchResult {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl PartialEq for SearchResult {
        fn eq(&self, other: &Self) -> bool {
            self.rid == other.rid
        }
    }
}

mod project {
    use serde::Serialize;
    use serde_json::Value;

    use radicle::cob;
    use radicle::git::Oid;
    use radicle::identity::project::Project;
    use radicle::identity::{RepoId, Visibility};

    /// Project info.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Info {
        /// Project metadata.
        #[serde(flatten)]
        pub payload: Project,
        pub delegates: Vec<Value>,
        pub threshold: usize,
        pub visibility: Visibility,
        pub head: Oid,
        pub patches: cob::patch::PatchCounts,
        pub issues: cob::issue::IssueCounts,
        pub id: RepoId,
        pub seeding: usize,
    }
}

/// Announce refs to the network for the given RID.
pub fn announce_refs(mut node: Node, rid: RepoId) -> Result<(), Error> {
    match node.announce_refs(rid) {
        Ok(_) => Ok(()),
        Err(e) if e.is_connection_err() => Ok(()),
        Err(e) => Err(e.into()),
    }
}
