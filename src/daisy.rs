use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const BASE_DAISY_URL: &str = "https://daisysms.com/stubs/handler_api.php";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RETRIES: u32 = 20;

pub struct DaisySMSClient {
    api_key: String,
    service: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    price: f64,
    count: i32,
    #[serde(rename = "multipleCode")]
    multiple_code: bool,
    #[serde(rename = "ltrPrice")]
    ltr_price: Option<f64>,
    #[serde(rename = "ltrAvailable")]
    ltr_available: Option<bool>,
    #[serde(rename = "countryNumber")]
    country_number: i32,
}

impl DaisySMSClient {
    pub fn new(api_key: &str, service: &str) -> Self {
        DaisySMSClient {
            api_key: api_key.to_string(),
            service: service.to_string(),
            client: Client::new(),
        }
    }

    pub async fn rent_number(
        &self,
        options: Option<HashMap<String, String>>,
    ) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
        let mut url = Url::parse(BASE_DAISY_URL)?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("api_key", &self.api_key);
            query_pairs.append_pair("action", "getNumber");
            query_pairs.append_pair("service", &self.service);

            if let Some(opts) = options {
                for (key, value) in opts {
                    query_pairs.append_pair(&key, &value);
                }
            }
        }

        let response = self.client.get(url).send().await?.text().await?;

        match response.as_str() {
            "NO_NUMBERS" => return Err("No numbers available".into()),
            "NO_MONEY" => return Err("Not enough balance".into()),
            "MAX_PRICE_EXCEEDED" => return Err("Max price exceeded".into()),
            "TOO_MANY_ACTIVE_RENTALS" => return Err("Too many active rentals".into()),
            "BAD_KEY" => return Err("API key invalid".into()),
            _ => {}
        }

        if !response.starts_with("ACCESS_NUMBER:") {
            return Err(format!("Unexpected response format: {}", response).into());
        }

        let parts: Vec<&str> = response.trim_start_matches("ACCESS_NUMBER:").split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Unexpected response format: {}", response).into());
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    pub async fn poll_for_code(
        &self,
        id: &str,
        timeout_secs: u64,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let mut retry = 0;

        while Instant::now() < deadline {
            if retry >= MAX_RETRIES {
                return Err("Reached maximum retries waiting for SMS code".into());
            }

            let (code, status) = self.get_activation_status(id).await?;

            match status.as_str() {
                "STATUS_OK" => return Ok(code),
                "STATUS_WAIT_CODE" => {
                    sleep(POLL_INTERVAL).await;
                    retry += 1;
                }
                "STATUS_CANCEL" => return Err("Rental was cancelled".into()),
                _ => return Err(format!("Unexpected status: {}", status).into()),
            }
        }

        Err("Timed out waiting for SMS code".into())
    }

    pub async fn get_activation_status(
        &self,
        id: &str,
    ) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
        let mut url = Url::parse(BASE_DAISY_URL)?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("api_key", &self.api_key);
            query_pairs.append_pair("action", "getStatus");
            query_pairs.append_pair("id", id);
        }

        let response = self.client.get(url).send().await?.text().await?;

        if response == "NO_ACTIVATION" {
            return Err("Activation not found".into());
        }

        if response.starts_with("STATUS_OK:") {
            let code = response.trim_start_matches("STATUS_OK:").to_string();
            return Ok((code, "STATUS_OK".to_string()));
        } else if response == "STATUS_WAIT_CODE" {
            return Ok(("".to_string(), "STATUS_WAIT_CODE".to_string()));
        } else if response == "STATUS_CANCEL" {
            return Ok(("".to_string(), "STATUS_CANCEL".to_string()));
        }

        Err(format!("Unexpected response format: {}", response).into())
    }

    pub async fn cancel_rental(&self, id: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut url = Url::parse(BASE_DAISY_URL)?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("api_key", &self.api_key);
            query_pairs.append_pair("action", "setStatus");
            query_pairs.append_pair("id", id);
            query_pairs.append_pair("status", "8"); // cancel
        }

        let response = self.client.get(url).send().await?.text().await?;

        match response.as_str() {
            "ACCESS_ACTIVATION" | "ACCESS_CANCEL" => Ok(()),
            "NO_ACTIVATION" => Err("Activation not found".into()),
            "ACCESS_READY" => Err("Already received the code or rental missing".into()),
            _ => Err(format!("Unexpected response: {}", response).into()),
        }
    }
}
