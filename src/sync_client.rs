use reqwest;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
pub struct SyncResponse {
    pub bans: Vec<BanEntry>,
}

#[derive(Deserialize)]
pub struct BanEntry {
    pub hwid: String,
    pub reason: String,
    pub banned_at: String,
}

pub struct SyncClient {
    client: reqwest::Client,
    base_url: String,
}

impl SyncClient {
    pub fn new(url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        SyncClient {
            client,
            base_url: url.to_string(),
        }
    }

    pub async fn sync_bans(&self, hwid: &str, local_count: u32) -> Result<SyncResponse, reqwest::Error> {
        let url = format!("{}/sync?hwid={}&local_count={}", self.base_url, hwid, local_count);
        self.client.get(&url).send().await?.json().await
    }
}
