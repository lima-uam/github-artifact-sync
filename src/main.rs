use std::{env, io::Cursor, os::unix::fs, path::PathBuf};

use actix_web::{
    http::header as actix_web_header,
    middleware::Logger,
    web::{self, Bytes, Data},
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
    branch: String,
    artifact: String,
    output: String,
    symlink: Option<String>,
}

impl Config {
    fn try_load() -> anyhow::Result<Self> {
        let addr = env::var("GH_ARTIFACT_SYNC_ADDR")
            .context("listen address must be set through GH_ARTIFACT_SYNC_ADDR")?;

        let port: u16 = env::var("GH_ARTIFACT_SYNC_PORT")
            .context("secret must be set through GH_ARTIFACT_SYNC_PORT")?
            .parse()
            .context("listen port must be a valid unix port")?;

        let secret = env::var("GH_ARTIFACT_SYNC_SECRET")
            .context("webhook secret must be set through GH_ARTIFACT_SYNC_SECRET")?;

        let token = env::var("GH_ARTIFACT_SYNC_TOKEN")
            .context("github token must be set through GH_ARTIFACT_SYNC_TOKEN")?;

        let branch = env::var("GH_ARTIFACT_SYNC_BRANCH")
            .context("branch name must be set through GH_ARTIFACT_SYNC_BRANCH")?;

        let artifact = env::var("GH_ARTIFACT_SYNC_ARTIFACT")
            .context("artifact name must be set through GH_ARTIFACT_SYNC_ARTIFACT")?;

        let output = env::var("GH_ARTIFACT_SYNC_OUTPUT")
            .context("output location must be set through GH_ARTIFACT_SYNC_OUTPUT")?;

        let symlink = env::var("GH_ARTIFACT_SYNC_SYMLINK").ok();

        Ok(Self {
            addr,
            port,
            secret,
            token,
            branch,
            artifact,
            output,
            symlink,
        })
    }

    fn parse_artifact_value(value: &str, head_sha: &str) -> anyhow::Result<PathBuf> {
        let parsed_str = value.replace("{HEAD_SHA}", head_sha);
        PathBuf::try_from(parsed_str).context("invalid output path")
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

fn build_github_client_and_headers(token: &str) -> Option<(Client, reqwest::header::HeaderMap)> {
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
        headers.insert("Authorization", format!("Bearer {}", token).parse().ok()?);

        headers
    };

    Some((client, headers))
}

async fn get_workflow_artifacts(
    repo_owner: &str,
    repo_name: &str,
    run_id: u64,
    client: &Client,
    headers: reqwest::header::HeaderMap,
) -> Option<WorkflowArtifactsResponse> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/actions/runs/{}/artifacts",
        repo_owner, repo_name, run_id
    );

    let response = client.get(&url).headers(headers).send().await.ok()?;
    let response_text = response.text().await.ok()?;

    serde_json::from_str(&response_text).ok()
}

async fn download_github_artifact(
    artifact: &Artifact,
    client: &Client,
    headers: reqwest::header::HeaderMap,
) -> Option<(reqwest::header::HeaderMap, Bytes)> {
    let response = client
        .get(&artifact.archive_download_url)
        .headers(headers)
        .send()
        .await
        .ok()?;

    let response_headers = response.headers().clone();
    let response_bytes = response.bytes().await.ok()?;

    Some((response_headers, response_bytes))
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

    if payload.workflow_job.status != "completed" {
        log::info!("the workflow isn't completed yet, ignoring it");
        return HttpResponse::NoContent();
    }

    if payload.workflow_job.head_branch != data.branch {
        log::info!("the workflow is for another branch");
        return HttpResponse::NoContent();
    }

    log::info!("the workflow has been completed, querying for run artifacts");

    let (client, headers) = match build_github_client_and_headers(&data.token) {
        Some(x) => x,
        None => {
            return HttpResponse::InternalServerError();
        }
    };

    let artifacts = match get_workflow_artifacts(
        &payload.repository.owner.login,
        &payload.repository.name,
        payload.workflow_job.run_id,
        &client,
        headers.clone(),
    )
    .await
    {
        Some(response) => response.artifacts,
        None => {
            log::warn!("unintelligible workflow artifacts response, ignoring event");
            return HttpResponse::InternalServerError();
        }
    };

    let artifact = match artifacts
        .iter()
        .find(|&artifact| artifact.name == data.artifact)
    {
        Some(x) => {
            log::info!("found an artifact with a matching name, downloading it");
            x
        }
        None => {
            log::info!("found no artifacts with the corrent name, finishing event");
            return HttpResponse::NoContent();
        }
    };

    let (artifact_headers, artifact_bytes) =
        match download_github_artifact(artifact, &client, headers).await {
            Some(x) => x,
            None => {
                log::warn!("cannot download artifact from github");
                return HttpResponse::InternalServerError();
            }
        };

    match artifact_headers.get("Content-Type") {
        Some(x) if x == "zip" => {
            log::info!("downloaded artifact zip archive");
        }
        _ => {
            log::warn!("response didn't wasn't a zip, cannot extract artifact");
            return HttpResponse::InternalServerError();
        }
    };

    let artifact_bytes = Cursor::new(artifact_bytes);

    let mut artifact = match zip::ZipArchive::new(artifact_bytes) {
        Ok(x) => x,
        Err(err) => {
            log::warn!("cannot decode downloaded archive: {}", err);
            return HttpResponse::InternalServerError();
        }
    };

    let output = match Config::parse_artifact_value(&data.output, &payload.workflow_job.head_sha) {
        Ok(output) => {
            log::info!("artifact output location is: {}", &output.to_string_lossy());
            output
        }
        Err(err) => {
            log::warn!("cannot parse artifact output location: {}", err);
            return HttpResponse::InternalServerError();
        }
    };

    match artifact.extract(&output) {
        Ok(_) => {
            log::info!("extracted zip file contents");
        }
        Err(err) => {
            log::warn!("cannot extract archive contets: {}", err);
            return HttpResponse::InternalServerError();
        }
    };

    if let Some(symlink) = &data.symlink {
        let symlink = match Config::parse_artifact_value(&symlink, &payload.workflow_job.head_sha) {
            Ok(output) => {
                log::info!("trying to create symlink to artifact");
                output
            }
            Err(err) => {
                log::warn!("cannot parse artifact symlink location: {}", err);
                return HttpResponse::InternalServerError();
            }
        };

        match fs::symlink(&output, &symlink) {
            Ok(_) => {
                log::info!(
                    "symlinked artifact output {} as {}",
                    &output.to_string_lossy(),
                    &symlink.to_string_lossy()
                );
            }
            Err(err) => {
                log::warn!("cannot create artifact symlink: {}", err);
                return HttpResponse::InternalServerError();
            }
        }
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
