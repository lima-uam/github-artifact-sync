use std::env;

use actix_web::{
    http::header as actix_web_header,
    middleware::Logger,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use anyhow::Context;
use hmac::{Hmac, Mac};
use reqwest::{header::HeaderValue, Client};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug)]
struct Config {
    addr: String,
    port: u16,
    secret: String,
    token: String,
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

        let token = env::var("GH_ARTIFACT_SYNC_TOKEN")
            .context("secret must be set through GH_ARTIFACT_SYNC_TOKEN")?;

        Ok(Self {
            addr,
            port,
            secret,
            token,
        })
    }
}

fn verify_github_signature(payload: &[u8], secret: &[u8], signature: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(payload);
    mac.verify_slice(signature).is_ok()
}

fn extract_github_signature(headers: &actix_web_header::HeaderMap) -> Option<Vec<u8>> {
    let signature_str = headers
        .get("X-Hub-Signature-256")?
        .to_str()
        .ok()?
        .strip_prefix("sha256=")?;

    hex::decode(signature_str).ok()
}

fn extract_github_event(headers: &actix_web_header::HeaderMap) -> Option<&str> {
    headers.get("X-GitHub-Event")?.to_str().ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayload {
    workflow_job: GithubWorkflowPayloadWorkflowJob,
    repository: GithubWorkflowPayloadRepository,
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
    owner: GithubWorkflowPayloadRepositoryOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadRepositoryOwner {
    id: u64,
    login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GithubWorkflowPayloadSender {
    id: u64,
    login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Artifact {
    id: u64,
    name: String,
    archive_download_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowArtifactsResponse {
    artifacts: Vec<Artifact>,
}

async fn get_workflow_artifacts(
    repo_owner: &str,
    repo_name: &str,
    run_id: u64,
    headers: reqwest::header::HeaderMap,
    client: &Client,
) -> Option<WorkflowArtifactsResponse> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/actions/runs/{}/artifacts",
        repo_owner, repo_name, run_id
    );

    let response = client.get(&url).headers(headers).send().await.ok()?;
    let response_text = response.text().await.ok()?;

    serde_json::from_str(&response_text).ok()
}

#[actix_web::post("/api/github/workflow")]
async fn post_github_workflow(
    data: Data<Config>,
    req_body: web::Bytes,
    req: actix_web::HttpRequest,
) -> impl Responder {
    log::info!("processing webhook event");

    match extract_github_signature(&req.headers()) {
        Some(signature) if verify_github_signature(&req_body, data.secret.as_ref(), &signature) => {
            log::info!("the signature is valid");
        }
        _ => {
            log::warn!("the signature is invalid or missing, ignoring it");
            return HttpResponse::BadRequest();
        }
    };

    match extract_github_event(&req.headers()) {
        Some(event) if event == "workflow_job" => {
            log::info!("the event is from a workflow");
        }
        _ => {
            log::info!("the event is not coming from a workflow, ignoring it");
            return HttpResponse::BadRequest();
        }
    };

    let payload: GithubWorkflowPayload = match serde_json::from_slice(&req_body) {
        Ok(val) => val,
        _ => {
            log::warn!("unintelligible event payload, ignoring it");
            return HttpResponse::BadRequest();
        }
    };

    log::debug!("{:?}", &payload);

    if payload.workflow_job.status != "completed" {
        log::info!("the workflow isn't completed yet, ignoring it");
        return HttpResponse::NoContent();
    }

    log::info!("the workflow has been completed, querying for run artifacts");

    let client = reqwest::Client::new();

    let headers = {
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            "Accept",
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        headers.insert(
            "User-Agent",
            HeaderValue::from_static("GithubArtifactSync/0.1.0"),
        );
        headers.insert(
            "Authorization",
            format!("Bearer {}", &data.token).parse().unwrap(),
        );

        headers
    };

    let artifacts = match get_workflow_artifacts(
        &payload.repository.owner.login,
        &payload.repository.name,
        payload.workflow_job.run_id,
        headers.clone(),
        &client,
    )
    .await
    {
        Some(response) => response.artifacts,
        None => {
            log::warn!("unintelligible workflow artifacts response, ignoring event");
            return HttpResponse::InternalServerError();
        }
    };

    log::debug!("{:?}", &artifacts);

    if artifacts.len() == 0 {
        log::info!("No artifacts found, finishing event");
        return HttpResponse::NoContent();
    }

    log::info!("Found {} artifacts, downloading them", artifacts.len());

    for artifact in artifacts {
        dbg!(artifact.archive_download_url);
    }

    HttpResponse::NoContent()
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
