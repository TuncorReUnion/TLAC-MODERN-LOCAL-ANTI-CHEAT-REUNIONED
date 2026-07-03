use anti_cheat::server::{run_server, ServerState};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let state = Arc::new(ServerState::new());
    run_server("/tmp/anti-cheat.sock", state).await
}
