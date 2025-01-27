use anyhow::Error;
use std::iter::repeat_with;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::{collections::HashMap, process};
use time::{Duration, OffsetDateTime};

use radicle::prelude::RepoId;
use radicle::version::Version;
use radicle::Profile;
use radicle_http_api as httpd;
use radicle_http_api::api;
use radicle_http_api::api::auth::{AuthState, Session};

pub const VERSION: Version = Version {
    name: "radicle-http-api",
    commit: env!("GIT_HEAD"),
    version: env!("RADICLE_VERSION"),
    timestamp: env!("SOURCE_DATE_EPOCH"),
};

pub const HELP_MSG: &str = r#"
Usage

   radicle-http-api [<option>...]
   
Options

    --listen       <address>         Address to listen on (default: 0.0.0.0:8080)
    --alias, -a    <alias> <rid>     Provide alias and RID pairs to shorten git clone commands for repositories,
                                     e.g. heartwood and rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5 to produce https://seed.radicle.xyz/heartwood.git
    --cache        <number>          Max amount of items in cache for /tree endpoints (default: 100)
    --session-expiry, -e <duration>  Configure (authorized) session expiration in seconds. 0 means indefinitely (default 1 week)
    --generate-api-key, -g           Generate a new api key
    --version, -v                    Print program version
    --help, -h                       Print help
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = parse_options()?;

    // SAFETY: The logger is only initialized once.
    httpd::logger::init()?;
    tracing::info!("starting http daemon..");
    tracing::info!("version {} ({})", env!("RADICLE_VERSION"), env!("GIT_HEAD"));

    match httpd::run(options).await {
        Ok(()) => {}
        Err(err) => {
            tracing::error!("Fatal: {:#}", err);
            process::exit(1);
        }
    }
    Ok(())
}

/// Parse command-line arguments into HTTP options.
fn parse_options() -> Result<httpd::Options, Error> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    let mut listen = None;
    let mut aliases = HashMap::new();
    let mut cache = Some(httpd::DEFAULT_CACHE_SIZE);
    let mut session_expiry = api::auth::DEFAULT_AUTHORIZED_SESSIONS_EXPIRATION;
    let mut gen_api_key = false;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("listen") => {
                let addr = parser.value()?.parse()?;
                listen = Some(addr);
            }
            Long("alias") | Short('a') => {
                let alias: String = parser.value()?.parse()?;
                let id: RepoId = parser.value()?.parse()?;

                aliases.insert(alias, id);
            }
            Long("version") | Short('v') => {
                if let Err(e) = VERSION.write(std::io::stdout()) {
                    eprintln!("error: {e}");
                    process::exit(1);
                };
                process::exit(0);
            }
            Long("cache") => {
                let size = parser.value()?.parse()?;
                cache = NonZeroUsize::new(size);
            }
            Long("session-expiry") | Short('e') => {
                let expiry_seconds: i64 = parser.value()?.parse()?;
                session_expiry = Duration::seconds(expiry_seconds);
            }
            Long("generate-api-key") | Short('g') => {
                gen_api_key = true;
            }
            Long("help") | Short('h') => {
                println!("{HELP_MSG}");
                process::exit(0);
            }
            _ => return Err(arg.unexpected().into()),
        }
    }
    let options = httpd::Options {
        aliases,
        listen: listen.unwrap_or_else(|| ([0, 0, 0, 0], 8080).into()),
        cache,
        session_expiry,
    };
    if gen_api_key {
        let profile = Profile::load()?;
        let ctx = api::Context::new(Arc::new(profile.clone()), &options);
        let mut rng = fastrand::Rng::new();
        let session_id = repeat_with(|| rng.alphanumeric())
            .take(api::auth::DEFAULT_SESSION_ID_CUSTOM_EXPIRATION_LENGTH)
            .collect::<String>();
        let signer = profile.signer().map_err(Error::from)?;
        let session = Session {
            status: AuthState::Authorized,
            public_key: *signer.public_key(),
            alias: profile.config.node.alias.clone(),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc()
                .checked_add(options.session_expiry)
                .unwrap(),
        };
        let encrypted_session_id = signer.try_sign(session_id.as_bytes())?.to_string();
        let mut sessions = ctx.open_session_db()?;
        let ok = sessions
            .insert(&encrypted_session_id, &session)
            .map_err(Error::from)?;
        if !ok {
            eprintln!("error inserting api key to db!");
            process::exit(1);
        }
        println!("{session_id}");
        process::exit(0);
    }
    Ok(options)
}
