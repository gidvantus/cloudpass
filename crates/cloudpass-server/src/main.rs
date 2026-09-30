//! Server entry point.

use std::process::ExitCode;

use cloudpass_server::{app, state};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "server stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("CLOUDPASS_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://cloudpass.db".to_owned());
    let bind_address =
        std::env::var("CLOUDPASS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    let shared = state::init(&database_url).await?;
    let router = app(shared);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    tracing::info!(
        address = %listener.local_addr()?,
        database = %database_url,
        "cloudpass-server listening"
    );

    axum::serve(listener, router).await?;
    Ok(())
}
