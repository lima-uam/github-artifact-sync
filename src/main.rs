use std::env;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Context;

#[actix_web::post("/api/github/workflow")]
async fn github_webhook(req_body: web::Bytes, req: actix_web::HttpRequest) -> impl Responder {
    dbg!(req_body);
    dbg!(req);

    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let addr = env::var("LISTEN_ADDRESS").unwrap_or("localhost".into());

    let port: u16 = match env::var("LISTEN_PORT") {
        Ok(port_str) => port_str.parse().context("port must be a valid unix port")?,
        Err(_) => 5001,
    };

    Ok(HttpServer::new(|| App::new().service(github_webhook))
        .bind((addr, port))?
        .run()
        .await?)
}
