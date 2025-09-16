use std::env;

use actix_web::{
    http::header::HeaderMap,
    middleware::Logger,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use anyhow::Context;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug)]
struct Config {
    addr: String,
    port: u16,
    secret: String,
}

impl Config {
    fn try_load() -> anyhow::Result<Self> {
        let addr = env::var("GH_ARTIFACT_SYNC_ADDR")
            .context("secret must be set through GH_ARTIFACT_SYNC_ADDR")?;

        let port: u16 = env::var("GH_ARTIFACT_SYNC_PORT")
            .context("secret must be set through GH_ARTIFACT_SYNC_PORT")?
            .parse()
            .context("port must be a valid unix port")?;

        let secret = env::var("GH_ARTIFACT_SYNC_SECRET")
            .context("secret must be set through GH_ARTIFACT_SYNC_SECRET")?;

        Ok(Self { addr, port, secret })
    }
}

fn verify_github_signature(payload: &[u8], secret: &[u8], signature: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(payload);
    mac.verify_slice(signature).is_ok()
}

fn extract_github_signature(headers: &HeaderMap) -> Option<Vec<u8>> {
    let signature_str = headers
        .get("X-Hub-Signature-256")?
        .to_str()
        .ok()?
        .strip_prefix("sha256=")?;

    hex::decode(signature_str).ok()
}

fn extract_github_event(headers: &HeaderMap) -> Option<&str> {
    headers.get("X-GitHub-Event")?.to_str().ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayload {
    action: String,
    workflow_job: GithubWorkflowPayloadWorkflowJob,
    repository: GithubWorkflowPayloadRepository,
    organization: GithubWorkflowPayloadOrganization,
    sender: GithubWorkflowPayloadSender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadWorkflowJob {
    id: u64,
    run_id: u64,
    head_branch: String,
    head_sha: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadRepository {
    id: u64,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadOrganization {
    id: u64,
    login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadSender {
    id: u64,
    login: String,
}

#[actix_web::post("/api/github/workflow")]
async fn post_github_workflow(
    data: Data<Config>,
    req_body: web::Bytes,
    req: actix_web::HttpRequest,
) -> impl Responder {
    match extract_github_signature(&req.headers()) {
        Some(signature) if verify_github_signature(&req_body, data.secret.as_ref(), &signature) => {
        }
        _ => return HttpResponse::BadRequest(),
    };

    match extract_github_event(&req.headers()) {
        Some(event) if event == "workflow_job" => {}
        _ => return HttpResponse::BadRequest(),
    };

    let payload: GithubWorkflowPayload = match serde_json::from_slice(&req_body) {
        Ok(x) => x,
        _ => return HttpResponse::BadRequest(),
    };

    dbg!(&payload);

    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_custom_env("GH_ARTIFACT_SYNC_LOG");

    let app_data = Data::new(Config::try_load()?);

    let app_factory = {
        let app_data = app_data.clone();

        move || {
            App::new()
                .wrap(Logger::default())
                .app_data(app_data.clone())
                .service(post_github_workflow)
        }
    };

    Ok(HttpServer::new(app_factory)
        .bind((app_data.addr.as_ref(), app_data.port))?
        .run()
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_github_signature_test() {
        let secret: &[u8] = "It's a Secret to Everybody".as_ref();
        let payload: &[u8] = "Hello, World!".as_ref();

        let signature =
            hex::decode("757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
                .unwrap();
        let signature: &[u8] = signature.as_ref();

        assert!(verify_github_signature(payload, secret, signature))
    }
}
