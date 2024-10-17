use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::{Form, Router};
use radicle::crypto::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::api::Context;
use crate::axum_extra::Query;

pub fn router(ctx: Context) -> Router {
    Router::new()
        .route("/oauth", get(oauth_page_handler).post(oauth_submit_handler))
        .with_state(ctx)
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthChallenge {
    sig: Signature,
    pk: PublicKey,
    #[serde(default)]
    comment: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OauthPageParams {
    #[serde(default)]
    callback_url: Option<String>,
}

/// Show oauth page html
/// `GET /oauth`
async fn oauth_page_handler(
    State(ctx): State<Context>,
    Query(prms): Query<OauthPageParams>,
) -> impl IntoResponse {
    let alias = &ctx.profile.config.node.alias.to_string();
    let nid = &ctx.profile.public_key.to_string();
    if prms.callback_url.is_none() {
        return Html(String::from("Invalid callback URL"));
    }
    let cb = prms.callback_url.unwrap_or_default();
    Html(String::from(
    "<!DOCTYPE html><html lang=\"en\">
    <head>
        <title>$alias Radicle HTTP API OAuth Page</title>
    </head>
    <body style=\"background-color:#0a0d10;margin:0;\">
        <form method=\"POST\">
            <div style=\"background-image:url('https://app.radicle.xyz/images/default-seed-header.png');border-bottom:1px solid;height:18rem;background-position:center;background-size:cover;\"></div>
            <div style=\"max-width:500px;margin-left:auto;margin-right:auto;margin-top:25px;\">
                <div style=\"height:12rem;border:1px solid #2e2f38;border-radius:4px;background-color:#14151a;padding:.75rem 1rem;position:relative;display:flex;flex-direction:column;justify-content:space-between;overflow:hidden;\">
                    <div class=\"title\" style=\"display:flex;flex-direction:column;gap:.125rem;position:relative;\">
                        <div class=\"headline-and-badges\" style=\"display:flex;justify-content:space-between;gap:.5rem;\">
                            <h4 style=\"margin:0;color:rgb(249,249,251);line-clamp:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;\">Radicle HTTP API</h4>
                            <img width=\"24\" height=\"24\" class=\"logo\" alt=\"Radicle logo\" src=\"https://app.radicle.xyz/radicle.svg\" style=\"margin:0px 0.5rem;\">
                        </div>
                        <p class=\"txt-small\" style=\"margin:0;color:#9b9bb1;\">Running on $alias</p>
                        <p class=\"txt-small\" style=\"margin:0;color:#9b9bb1;\">$nid</p>
                    </div>
                    <div class=\"wrapper\" style=\"display:flex;flex-direction:column;margin:25px 0 0 0;position:relative;flex:1;align-items:start;height:2.5rem;\">
                        <label for=\"session_id\" class=\"txt-small\" style=\"margin:0;color:#9b9bb1;\">Fill in your session ID</label>
                        <input type=\"text\" id=\"session_id\" name=\"session_id\" placeholder=\"Your session ID...\" autocomplete=\"off\" required spellcheck=\"false\" style=\"background:#000;font-family:inherit;font-size:0.857rem;color:#f9f9fb;border:1px solid #24252d;border-radius:2px;line-height:1.6;outline:none;text-overflow:ellipsis;width:95%;height:auto;margin:10px 0 0 0;padding:0 10px;\" />
                        <input type=\"hidden\" id=\"callback_url\" name=\"callback_url\" value=\"$cb\" />
                        <input type=\"submit\" value=\"Submit\" style=\"margin-top:10px;\" />
                    </div>
                </div>
            </div>
        </form>
    </body>
    </html>").replace("$alias", alias).replace("$nid", nid).replace("$cb", &cb))
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct OauthSubmitParams {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    callback_url: String,
}

/// Submit oauth page and redirect back to original
/// `POST /oauth`
async fn oauth_submit_handler(Form(form): Form<OauthSubmitParams>) -> impl IntoResponse {
    let mut redir_url = form.callback_url;
    if redir_url.contains("?") {
        redir_url.push('^');
    } else {
        redir_url.push('?');
    }
    redir_url.push_str("session_id=");
    redir_url.push_str(&form.session_id);
    Redirect::temporary(&redir_url)
}

#[cfg(test)]
mod oauth_tests {
    use crate::test::{self, get};
    use axum::http::{Request, StatusCode};
    use hyper::Method;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_html_page() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test::seed(tmp.path());
        let app = super::router(ctx.to_owned());

        // Request to get the html page
        let response = get(&app, "/oauth?callback_url=https://abc.def").await;
        let status = response.status();
        let html_bytes = response.body().await;
        let html: String = String::from_utf8(html_bytes.to_vec()).unwrap();

        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(ctx.profile.config.node.alias.as_str()));
        assert!(html.contains(ctx.profile.public_key.to_string().as_str()));
        assert!(html.contains(ctx.profile.public_key.to_string().as_str()));
        assert!(html.contains("callback_url"));
        assert!(html.contains("https://abc.def"));
    }

    #[tokio::test]
    async fn test_html_page_without_cb() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test::seed(tmp.path());
        let app = super::router(ctx.to_owned());

        // Request to get the html page
        let response = get(&app, "/oauth").await;
        let status = response.status();
        let html_bytes = response.body().await;
        let html: String = String::from_utf8(html_bytes.to_vec()).unwrap();

        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"Invalid"#));
    }

    #[tokio::test]
    async fn test_submit_html_page() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test::seed(tmp.path());
        let app = super::router(ctx.to_owned());

        // Request to get the html page
        let form_body = "session_id=testSessionId&callback_url=https://radicle.xyz".to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/oauth")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        //let response = post(&app, , Some(Body::from(form_body)), None).await;
        let status = response.status();
        let redir_url = response.headers()["Location"].to_str().unwrap();
        //let html: String = String::from_utf8(html_bytes.to_vec()).unwrap();

        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(redir_url, "https://radicle.xyz?session_id=testSessionId");
    }
}
