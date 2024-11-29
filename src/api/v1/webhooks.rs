use crate::api;
use crate::api::error::Error;
use crate::api::Context;
use crate::axum_extra::{Path, Query};
use crate::store::Webhook;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use axum_auth::AuthBearer;
use radicle::identity::RepoId;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub fn router(ctx: Context) -> Router {
    Router::new()
        .route(
            "/projects/:repo_id/webhooks",
            post(webhooks_post_handler)
                .delete(webhooks_delete_handler)
                .get(webhooks_get_handler),
        )
        .with_state(ctx)
}

/// Return the webhooks for the repo.
/// `GET /projects/:repo_id/webhooks`
async fn webhooks_get_handler(
    State(ctx): State<Context>,
    AuthBearer(token): AuthBearer,
    Path(repo_id): Path<RepoId>,
) -> impl IntoResponse {
    api::auth::validate(&ctx, &token).await?;
    let (_, _) = ctx.repo(repo_id)?;
    let mut db = ctx.open_webhooks_db()?;
    let webhooks = db.get(repo_id.to_string())?;
    Ok::<_, Error>(Json(json!(webhooks)))
}

/// Creates a webhook for the repo.
/// `POST /projects/:repo_id/webhooks`
async fn webhooks_post_handler(
    State(ctx): State<Context>,
    AuthBearer(token): AuthBearer,
    Path(repo_id): Path<RepoId>,
    Json(mut webhook): Json<Webhook>,
) -> impl IntoResponse {
    api::auth::validate(&ctx, &token).await?;
    let (repo, _) = ctx.repo(repo_id)?;
    webhook.repo_id = repo.id.to_string();
    let mut db = ctx.open_webhooks_db()?;
    db.insert(&webhook)?;
    Ok::<_, Error>(Json(json!(webhook)))
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QueryUrl {
    pub url: Option<String>,
}

/// Deletes the webhooks for the repo, or the webhook with the specific url, if-provided
/// `DELETE /projects/:repo_id/webhooks`
async fn webhooks_delete_handler(
    State(ctx): State<Context>,
    AuthBearer(token): AuthBearer,
    Path(repo_id): Path<RepoId>,
    Query(qs): Query<QueryUrl>,
) -> impl IntoResponse {
    api::auth::validate(&ctx, &token).await?;
    let (_, _) = ctx.repo(repo_id)?;
    let mut db = ctx.open_webhooks_db()?;
    db.remove(repo_id.to_string(), qs.url)?;
    // returning OK without checking if we actually deleted anything

    Ok::<_, Error>(Json(json!({"repo_id": repo_id})))
}

#[cfg(test)]
mod webhooks_api_tests {
    use crate::store::Webhook;
    use crate::test::{create_session, delete, get_auth, post, seed, Response, RID, SESSION_ID};
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::Router;
    use serde_json::json;

    #[tokio::test]
    async fn test_webhooks() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = seed(tmp.path());
        let app = super::router(ctx.to_owned());

        create_session(ctx).await;

        let webhook = gen_webhook(1);

        let response = create_webhook(&app, &webhook).await;
        assert_eq!(response.status(), StatusCode::OK);

        // get webhooks, we should find the one created
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 1);
        assert_eq!(get_whs.as_array_mut().unwrap()[0], json!(webhook));

        // delete all under repo
        let del_resp = delete(
            &app,
            format!("/projects/{RID}/webhooks"),
            None,
            Some(SESSION_ID.to_string()),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::OK);

        // get should return empty array now
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_multiple_webhooks() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = seed(tmp.path());
        let app = super::router(ctx.to_owned());

        create_session(ctx).await;

        let webhook1 = gen_webhook(1);
        let response = create_webhook(&app, &webhook1).await;
        assert_eq!(response.status(), StatusCode::OK);

        let webhook2 = gen_webhook(2);
        let response = create_webhook(&app, &webhook2).await;
        assert_eq!(response.status(), StatusCode::OK);

        // get webhooks, we should find both created
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 2);

        // add webhook with same url as webhook1 again, it should be "ignored"
        let response = create_webhook(&app, &webhook1).await;
        assert_eq!(response.status(), StatusCode::OK);

        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 2);

        // delete by url
        let url1 = webhook1.url;
        let del_resp = delete(
            &app,
            format!("/projects/{RID}/webhooks?url={url1}"),
            None,
            Some(SESSION_ID.to_string()),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::OK);

        //verify we only have webhook2 now
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 1);
        assert_eq!(get_whs.as_array_mut().unwrap()[0], json!(webhook2));

        // add multiple other webhooks again
        for i in 0..5 {
            let wh = gen_webhook(10 + i);
            create_webhook(&app, &wh).await;
        }

        // we should have webhook2 + the 5 new ones
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 1 + 5);

        // delete all webhooks in repo
        let del_resp = delete(
            &app,
            format!("/projects/{RID}/webhooks"),
            None,
            Some(SESSION_ID.to_string()),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::OK);

        // verify we have 0 webhooks now
        let mut get_whs = get_webhooks(&app).await;
        assert_eq!(get_whs.as_array_mut().unwrap().len(), 0);
    }

    fn gen_webhook(id: u64) -> Webhook {
        Webhook {
            repo_id: RID.to_string(),
            url: format!("test_url_{id}"),
            secret: "test_secret".to_string(),
            content_type: "content type".to_string(),
        }
    }

    async fn create_webhook(app: &Router, webhook: &Webhook) -> Response {
        let body = Some(Body::from(json!(webhook).to_string()));
        let s = Some(SESSION_ID.to_string());
        post(app, format!("/projects/{RID}/webhooks"), body, s).await
    }

    async fn get_webhooks(app: &Router) -> serde_json::Value {
        let s = Some(SESSION_ID.to_string());
        let get_resp = get_auth(app, format!("/projects/{RID}/webhooks"), s).await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        get_resp.json().await
    }
}
