use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
pub struct SyncRequest {
    pub hwid: String,
    pub client_version: String,
    pub local_ban_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BanEntry {
    pub hwid: String,
    pub reason: String,
    pub banned_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyncResponse {
    pub bans: Vec<BanEntry>,
    pub config_updates: Option<serde_json::Value>,
}

pub struct SyncClient {
    http: Client,
    base_url: String,
}

impl SyncClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP client oluşturulamadı"),
            base_url: base_url.to_string(),
        }
    }

    pub async fn sync_bans(&self, hwid: &str, local_count: u32) -> Result<SyncResponse, Box<dyn std::error::Error>> {
        let req = SyncRequest {
            hwid: hwid.to_string(),
            client_version: "1.0.0".into(),
            local_ban_count: local_count,
        };

        let res = self.http
            .get(format!("{}/api/v1/sync", self.base_url))
            .json(&req)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(format!("Server hatası: {}", res.status()).into());
        }

        let data: SyncResponse = res.json().await?;
        Ok(data)
    }

    pub async fn report_cheat(&self, hwid: &str, reason: &str, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct ReportPayload {
            hwid: String,
            reason: String,
            pid: u32,
            timestamp: String,
        }

        let payload = ReportPayload {
            hwid: hwid.to_string(),
            reason: reason.to_string(),
            pid,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let res = self.http
            .post(format!("{}/api/v1/report", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if res.status().is_success() { Ok(()) } 
        else { Err(format!("Rapor gönderimi başarısız: {}", res.status()).into()) }
    }
}
