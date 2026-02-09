//! memoxide: Pure Rust memory forensics MCP server.
//!
//! This binary serves as an MCP (Model Context Protocol) server that provides
//! memory forensics analysis capabilities. It communicates via stdio transport.

mod analyzers;
mod memory;
mod plugins;
mod profile;
mod registry;
mod rules;
mod server;

use rmcp::ServiceExt;
use rmcp::transport::stdio;
use server::tools::MemoxideServer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (logs to stderr so stdout stays clean for MCP)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("memoxide MCP server starting...");

    let service = MemoxideServer::new()
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("Server error: {}", e))?;

    tracing::info!("memoxide MCP server running on stdio");
    service.waiting().await?;

    tracing::info!("memoxide MCP server shutting down");
    Ok(())
}
