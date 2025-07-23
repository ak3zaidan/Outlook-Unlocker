use crate::country::get_country_code;
use crate::unlock::UnlockStatus;
use rquest::redirect::Policy;
use rquest::{
    cookie::{CookieStore, Jar},
    Client,
};
use rquest::Proxy;
use rquest::header::HeaderName;
use serde_json::{json, Value};
use std::sync::Arc;
use url::form_urlencoded;
use url::Url;

pub fn encode_uri_component(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
}

#[allow(dead_code)]
fn decode_unicode_escapes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'u') {
            chars.next(); // 跳过 'u'
            let hex: String = chars.by_ref().take(4).collect();
            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                if let Some(decoded) = std::char::from_u32(code) {
                    result.push(decoded);
                    continue;
                }
            }
        }
        result.push(c);
    }
    result
}

fn extract_between(s: &str, start_str: &str, stop_str: &str) -> Option<String> {
    let start_pos = s.find(start_str)?;
    let start_pos = start_pos + start_str.len();
    let stop_pos = s[start_pos..].find(stop_str)?;
    Some(s[start_pos..start_pos + stop_pos].to_string())
}

type ErrorCodeMapping = (&'static str, &'static str);
static HEADER_ORDER_CHROME133_REAL_UNLOCK: [HeaderName; 18] = [
    HeaderName::from_static("content-length"),
    HeaderName::from_static("sec-ch-ua-platform"),
    HeaderName::from_static("x-ark-esync-value"),
    HeaderName::from_static("user-agent"),
    HeaderName::from_static("sec-ch-ua"),
    HeaderName::from_static("content-type"),
    HeaderName::from_static("sec-ch-ua-mobile"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("origin"),
    HeaderName::from_static("sec-fetch-site"),
    HeaderName::from_static("sec-fetch-mode"),
    HeaderName::from_static("sec-fetch-dest"),
    HeaderName::from_static("sec-fetch-storage-access"),
    HeaderName::from_static("referer"),
    HeaderName::from_static("accept-encoding"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("cookie"),
    HeaderName::from_static("priority"),
];

pub struct PanelClient {
    client: Client,
    cookie_jar: Arc<Jar>,
    use_logger: bool,
    account: String,
    password: String,
    url_post_msa: String,
    ppft: String,
    pprid: String,
    ipt: String,
    uaid: String,
    fmhf: String,
    canary: String,
    error_codes: [ErrorCodeMapping; 24],
    pub blob_data: String,
    pub risk_score: String,
    pub hfid: String,
    pub url_dfp: String,
    pub user_agent: String,
    pub opid: String,
    pub bk: String,
    pub accept_language: String,
}

impl PanelClient {
    pub fn new(proxy_url: String, account: String, password: String) -> anyhow::Result<Self> {
        let cookie_jar = Arc::new(Jar::default());

        let client_builder = Client::builder()
            .headers_order(&HEADER_ORDER_CHROME133_REAL_UNLOCK)
            .cookie_store(true)
            .cookie_provider(cookie_jar.clone());

        let client = if !proxy_url.is_empty() {
            let proxy = Proxy::all(&proxy_url)?;
            client_builder.proxy(proxy).build()?
        } else {
            client_builder.build()?
        };

        let error_codes = [
            ("450", "DailyLimitIDsReached"),
            ("1204", "MaximumOTTDailyError"),
            ("1208", "SmsNumberFormatInvalid"),
            ("6001", "ExpiredCredentials"),
            ("1062", "InvalidEmailFormat"),
            ("1063", "InvalidPhoneFormat"),
            ("1211", "CodeAlreadyConsumed"),
            ("1086", "Error_1086"),
            ("1346", "FraudBlocked"),
            ("1040", "HIPNeeded"),
            ("1041", "HIPEnforcementNeeded"),
            ("1042", "HIPSMSNeeded"),
            ("1043", "HIPValidationError"),
            ("1326", "HIPValidationActionBlockedError"),
            ("1339", "HipCaptchaNeededOnSendOTT"),
            ("1340", "HipEnforcementNeededOnSendOTT"),
            ("500", "InternalServerError"),
            ("1203", "IncorrectVerificationCode"),
            ("6002", "InvalidArguments"),
            ("1043", "InvalidCode"),
            ("1215", "InvalidVerificationCode"),
            ("1078", "SessionTimedOut"),
            ("1221", "TooManyCodesRequested"),
            ("1067", "SmsCountryBlocked"),
        ];
        Ok(Self {
            client,
            cookie_jar,
            use_logger: false,
            account,
            password,
            url_post_msa: String::new(),
            ppft: String::new(),
            pprid: String::new(),
            ipt: String::new(),
            uaid: String::new(),
            fmhf: String::new(),
            canary: String::new(),
            error_codes,
            blob_data: String::new(),
            risk_score: String::new(),
            hfid: String::new(),
            url_dfp: String::new(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36".to_string(),
            opid: String::new(),
            bk: String::new(),
            accept_language: "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7".to_string(),
        })
    }

    pub async fn login_initial_request(&mut self) -> Result<String, anyhow::Error> {
        let response = self.client
            .get("https://login.live.com/")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", &self.accept_language)
            .header("Priority", "u=0, i")
            .header("Connection", "keep-alive")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Upgrade-Insecure-Requests", "1")
            .header("User-Agent", &self.user_agent)
            .send()
            .await?;

        let text = response.text().await?;

        self.url_post_msa = extract_between(&text, "urlPostMsa:'", "',").unwrap_or_default();
        self.ppft = extract_between(
            &text,
            "'<input type=\"hidden\" name=\"PPFT\" id=\"i0327\" value=\"",
            "\"/>'",
        )
        .unwrap_or_default();

        self.url_dfp = extract_between(&text, "\"urlDfp\":\"", "\",\"").unwrap_or_default();
        if self.use_logger {
            println!("url_dfp: {}", self.url_dfp);
            println!("urlPostMsa: {}", self.url_post_msa);
            println!("PPFT: {}", self.ppft);
        }
        if !self.url_post_msa.is_empty() {
            //https://login.live.com/ppsecure/post.srf?contextid=7A0A32658A436C45&opid=460E2B3D5872F6C7&bk=1741903808&uaid=7205c9e1c840459ba8354ac020d697e1&pid=0
            self.opid = extract_between(&self.url_post_msa, "opid=", "&").unwrap_or_default();
            self.bk = extract_between(&self.url_post_msa, "bk=", "&").unwrap_or_default();
            self.uaid = extract_between(&self.url_post_msa, "uaid=", "&").unwrap_or_default();
        }

        if self.ppft.is_empty() {
            return Err(anyhow::anyhow!(format!(
                "初始登录请求: {}",
                UnlockStatus::UnlockEmptyParameter.to_string()
            )));
        }
        if let Some(_cookies) = self.get_cookies("https://login.live.com/") {
            // println!("INIT cookies: {}", cookies);
        }
        Ok("√√".to_string())
    }

    fn get_cookies(&self, url: &str) -> Option<String> {
        let url = Url::parse(url).ok()?;
        // 直接从 cookie_jar 获取 cookies
        self.cookie_jar
            .cookies(&url)
            .and_then(|c| c.to_str().ok().map(|s| s.to_string()))
    }

    pub async fn login_post_request(&mut self, mode: &str) -> Result<String, anyhow::Error> {
        let body = format!(
            "ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={}&PPSX=Pas&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i13=0&login={}&loginfmt={}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={}",
            encode_uri_component(&self.ppft), encode_uri_component(&self.account), encode_uri_component(&self.account), &self.password
        );

        let response = self.client
            .post(&self.url_post_msa)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", &self.accept_language)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Origin", "https://login.live.com")
            .header("Host", "login.live.com")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Upgrade-Insecure-Requests", "1")
            .header("User-Agent", &self.user_agent)
            .redirect(Policy::default())
            .body(body)
            .send()
            .await?;

        let text = response.text().await?;
        if self.use_logger {
            println!("login post request response text: {:?}", text);
        }
        match text {
            ref text if text.contains("&route=") => {
                if mode == "unlock" {
                    if self.use_logger {
                        println!("login success");
                    }
                    return Err(anyhow::anyhow!(format!(
                        "开始登录: {}",
                        UnlockStatus::LoginSuccess.to_string()
                    )));
                } else {
                    if self.use_logger {
                        println!("login success");
                    }
                    return Ok("√√".to_string());
                }
            }
            ref text if text.contains("proofs/Add") => {
                if mode == "unlock" {
                    if self.use_logger {
                        println!("Show skip 7 days button");
                    }
                    return Err(anyhow::anyhow!(format!(
                        "开始登录: {}",
                        UnlockStatus::UnlockShowSkip7DaysButton.to_string()
                    )));
                } else {
                    if self.use_logger {
                        println!("Show skip 7 days button");
                    }
                    return Ok("√√".to_string());
                }
            }
            ref text if text.contains("tou/accrue?") => {
                if mode == "unlock" {
                    if self.use_logger {
                        println!("Show accapt new terms button");
                    }
                    return Err(anyhow::anyhow!(format!(
                        "开始登录: {}",
                        UnlockStatus::UnlockShowAcceptNewTermsButton.to_string()
                    )));
                } else {
                    if self.use_logger {
                        println!("Show accapt new terms button");
                    }
                    return Ok("√√".to_string());
                }
            }
            ref text if text.contains("Abuse?mkt=") => {
                if mode == "unlock" {
                    if self.use_logger {
                        println!("Show account locked button");
                    }

                    self.pprid = extract_between(
                        &text,
                        r#"hidden" name="pprid" id="pprid" value=""#,
                        r#""><input type="hidden" name="#,
                    )
                    .unwrap_or_default();
                    self.ipt = extract_between(
                        &text,
                        r#"hidden" name="ipt" id="ipt" value=""#,
                        r#""><input type="hidden" name="#,
                    )
                    .unwrap_or_default();
                    self.uaid = extract_between(
                        &text,
                        r#"hidden" name="uaid" id="uaid" value=""#,
                        r#""><"#,
                    )
                    .unwrap_or_default();
                    self.fmhf = extract_between(
                        &text,
                        r#"form name="fmHF" id="fmHF" action=""#,
                        r#"" method="post""#,
                    )
                    .unwrap_or_default();
                    if self.use_logger {
                        println!("pprid: {}", self.pprid);
                        println!("ipt: {}", self.ipt);
                        println!("uaid: {}", self.uaid);
                        println!("fmhf: {}", self.fmhf);
                    }
                    if self.fmhf.is_empty()
                        || self.pprid.is_empty()
                        || self.ipt.is_empty()
                        || self.uaid.is_empty()
                    {
                        return Err(anyhow::anyhow!(format!(
                            "开始登录: {}",
                            UnlockStatus::UnlockEmptyParameter.to_string()
                        )));
                    }
                    return Ok("√√".to_string());
                } else {
                    if self.use_logger {
                        println!("Show account locked button");
                    }
                    return Err(anyhow::anyhow!(format!(
                        "开始登录: {}",
                        UnlockStatus::UnlockShowAccountLockedButton.to_string()
                    )));
                }
            }
            ref text if text.contains("https://privacynotice.account.microsoft.com/notice") => {
                if mode == "unlock" {
                    if self.use_logger {
                        println!("Show account privacy notice button");
                    }
                    return Err(anyhow::anyhow!(format!(
                        "开始登录: {}",
                        UnlockStatus::UnlockShowAccountPrivacyNoticeButton.to_string()
                    )));
                } else {
                    if self.use_logger {
                        println!("Show account privacy notice button");
                    }
                    return Ok("√√".to_string());
                }
            }
            ref text if text.is_empty() => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockEmptyParameter.to_string()
                )));
            }
            ref text if text.contains("Too Many Requests") => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockTooManyRequest.to_string()
                )));
            }
            //https://privacynotice.account.microsoft.com/notice?
            ref text if text.contains("https://privacynotice.account.microsoft.com/notice?") => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::AlreadyUnlocked.to_string()
                )));
            }
            ref text if text.contains("sErrTxt:'帐户或密码不正确。请重试") => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockAccountOrPasswordIncorrect.to_string()
                )));
            }
            ref text if text.contains("帐户或密码尝试登录的次数过多") => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockAccountOrPasswordIncorrect.to_string()
                )));
            }
            ref text if text.contains(r#"><form name=\"fmHF\" id=\"fmHF\" action=\"https://account.live.com/recover?mkt="#) => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockProtected.to_string()
                )));
            }
            //https://account.live.com/recover?
            ref text if text.contains("action=\"https://account.live.com/recover?") => {
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockProtected.to_string()
                )));
            }
            _ => {
                println!("text: {:?}", text);
                return Err(anyhow::anyhow!(format!(
                    "开始登录: {}",
                    UnlockStatus::UnlockUnknownError.to_string()
                )));
            }
        }
    }

    pub async fn unlock_request(&mut self) -> Result<String, anyhow::Error> {
        let body = format!(
            "pprid={}&ipt={}&uaid={}",
            self.pprid,
            encode_uri_component(&self.ipt),
            self.uaid
        );

        let response = self.client
            .post(&self.fmhf)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", &self.accept_language)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Priority", "u=0, i")
            .header("Origin", "https://login.live.com")
            .header("Upgrade-Insecure-Requests", "1")
            .header("User-Agent", &self.user_agent)
            .header("Referer", "https://login.live.com/")
            .body(body)
            .send()
            .await?;
        
        let text = response.text().await?;
        let decoded_text = decode_unicode_escapes(&text);

        self.canary =
            extract_between(&decoded_text, "\"apiCanary\":\"", "\",\"").unwrap_or_default();

        //"sHipFid":"
        self.hfid = extract_between(&decoded_text, "\"sHipFid\":\"", "\",\"").unwrap_or_default();
        if self.canary.is_empty() {
            return Err(anyhow::anyhow!(format!(
                "确认解锁: {}",
                UnlockStatus::UnlockEmptyParameter.to_string()
            )));
        }
        if self.use_logger {
            println!("canary: {}", self.canary);
            println!("hfid: {}", self.hfid);
        }
        if let Some(_cookies) = self.get_cookies(&self.fmhf) {
            // println!("INIT cookies: {}", cookies);
        }
        Ok("√√".to_string())
    }

    pub async fn send_ott_request(
        &mut self,
        country: &str,
        phone: &str,
    ) -> Result<String, anyhow::Error> {
        let body = json!({
            "action": "TierRestore",
            "proofCountryIso": country,
            "channel": "SMS",
            "proofId": phone,
            "uiflvr": 1001,
            "scid": 100121,
            "uaid": self.uaid,
            "hpgid": 200252
        });

        let response = self
            .client
            .post(&self.fmhf.replace(
                "https://account.live.com/Abuse?",
                "https://account.live.com/API/Proofs/SendOtt?",
            ))
            .header("Accept", "application/json")
            .header("Accept-Language", &self.accept_language)
            .header("Canary", &self.canary)
            .header("Client-Request-Id", &self.uaid)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Correlationid", &self.uaid)
            .header("Hpgact", "0")
            .header("Hpgid", "200252")
            .header("Priority", "u=1, i")
            .header("Origin", "https://account.live.com")
            .header("User-Agent", &self.user_agent)
            .header("Referer", &self.fmhf)
            .json(&body)
            .send()
            .await?;

        let text = response.text().await?;

        let json: Value = serde_json::from_str(&text)?;

        if let Some(_formatted_phone) = json
            .get("formattedInternationalPhoneNumber")
            .and_then(Value::as_str)
        {
            if self.use_logger {
                println!("send code √√ for account: {}", self.account);
            }
            return Ok("√√".to_string());
        } else {
            if self.use_logger {
                println!("account: {} 发送短信 ×× Error: {}", self.account, text);
            }

            if let Some(error) = json.get("error") {
                if let Some(code) = error.get("code").and_then(Value::as_str) {
                    if let Some(&(_, error_message)) = self
                        .error_codes
                        .iter()
                        .find(|&&(code_entry, _)| code_entry == code)
                    {
                        if code == "1340" && error_message.contains("HipEnforcementNeededOnSendOTT")
                        {
                            self.blob_data = error
                                .get("data")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();

                            self.risk_score = error
                                .get("recommendedChallengeRiskScore")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            if self.use_logger {
                                println!("blob_data: {}", self.blob_data);
                                println!("risk_score: {}", self.risk_score);
                            }
                            return Ok("√√".to_string());
                        }

                        return Err(anyhow::anyhow!(
                            "发送短信 ×× Error: code: {}, Details: {}",
                            code,
                            error_message
                        ));
                    } else {
                        if self.use_logger {
                            println!("Error: {}", text);
                        }
                        return Err(anyhow::anyhow!(format!(
                            "发送短信 ×× Error: {}",
                            UnlockStatus::UnlockUnknownError.to_string()
                        )));
                    }
                }
            }
            if self.use_logger {
                println!("account: {} 发送短信 ×× Error: {}", self.account, text);
            }
            return Err(anyhow::anyhow!(format!(
                "发送短信 ×× Error: {}",
                UnlockStatus::UnlockEmptyParameter.to_string()
            )));
        }
    }
    
    pub async fn send_ott_request_hip_enforcement_needed(
        &mut self,
        country: &str,
        phone: &str,
        funcaptcha_token: &str,
    ) -> Result<String, anyhow::Error> {
        let body = json!({
            "action": "TierRestore",
            "proofCountryIso": country,
            "channel": "SMS",
            "proofId": phone,
            "HFId": self.hfid,
            "HPId": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
            "HSol": funcaptcha_token,
            "HType": "enforcement",
            "HId": funcaptcha_token,
            "RecommendedChallengeRiskScore": self.risk_score,
            "uiflvr": 1001,
            "scid": 100121,
            "uaid": self.uaid,
            "hpgid": 200252
        });

        let response = self
            .client
            .post(&self.fmhf.replace(
                "https://account.live.com/Abuse?",
                "https://account.live.com/API/Proofs/SendOtt?",
            ))
            .header("accept", "application/json")
            .header("accept-language", &self.accept_language)
            .header("canary", &self.canary)
            .header("client-request-id", &self.uaid)
            .header("content-type", "application/json; charset=utf-8")
            .header("correlationid", &self.uaid)
            .header("hpgact", "0")
            .header("hpgid", "200252")
            .header("priority", "u=1, i")
            .header(
                "sec-ch-ua",
                "\"Chromium\";v=\"133\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"133\"",
            )
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("user-agent", &self.user_agent)
            .header("referer", &self.fmhf)
            .json(&body)
            .send()
            .await?;

        let text = response.text().await?;

        let json: Value = serde_json::from_str(&text)?;

        if let Some(_formatted_phone) = json
            .get("formattedInternationalPhoneNumber")
            .and_then(Value::as_str)
        {
            if self.use_logger {
                println!("send code √√ for account: {}", self.account);
            }

            return Ok("√√".to_string());
        } else {
            if self.use_logger {
                println!("account: {} 打码短信 ×× Error: {}", self.account, text);
            }
            
            if let Some(error) = json.get("error") {
                if let Some(code) = error.get("code").and_then(Value::as_str) {
                    if let Some(&(_, error_message)) = self
                        .error_codes
                        .iter()
                        .find(|&&(code_entry, _)| code_entry == code)
                    {
                        if code == "1340"
                        {
                            self.blob_data = error
                                .get("data")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();

                            self.risk_score = error
                                .get("recommendedChallengeRiskScore")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            if self.use_logger {
                                println!("blob_data: {}", self.blob_data);
                                println!("risk_score: {}", self.risk_score);
                            }
                            // println!("发送短信 ×× Error: code: {}, Details: {}", code, error_message);
                            return Err(anyhow::anyhow!(
                                "发送短信 ×× Error: code: {}, Details: {}",
                                code,
                                error_message
                            ));
                            // return Ok("√√".to_string());
                        }

                        return Err(anyhow::anyhow!(
                            "发送短信 ×× Error: code: {}, Details: {}",
                            code,
                            error_message
                        ));
                    } else {
                        if self.use_logger {
                            println!("Error: {}", text);
                        }
                        return Err(anyhow::anyhow!(format!(
                            "发送短信 ×× Error: {}",
                            UnlockStatus::UnlockUnknownError.to_string()
                        )));
                    }
                }
            }
            if self.use_logger {
                println!("account: {} 打码短信 ×× Error: {}", self.account, text);
            }
            return Err(anyhow::anyhow!(format!(
                "打码短信 ×× Error: {}",
                UnlockStatus::UnlockEmptyParameter.to_string()
            )));
        }
    }

    pub async fn consume_ott_request(
        &self,
        country: &str,
        phone: &str,
        code: &str,
    ) -> Result<String, anyhow::Error> {
        let country_code = get_country_code(country);
        let body = json!({
            "ottPurpose": "TierRestore",
            "ott": code,
            "channelType": "SMS",
            "destinationPii": format!("+{}{}", country_code, phone),
            "uiflvr": 1001,
            "scid": 100121,
            "uaid": self.uaid,
            "hpgid": 200252
        });

        let response = self.client
            .post("https://account.live.com/API/ConsumeOneTimeToken?mkt=ZH-CN&uiflavor=web&id=38936&lmif=40&abr=1&ru=https://login.live.com/login.srf%3fid%3d38936%26opid%3d8B3A9262050F578D%26opidt%3d1741885211")
            .header("accept", "application/json")
            .header("accept-language", &self.accept_language)
            .header("canary", &self.canary)
            .header("client-request-id", &self.uaid)
            .header("content-type", "application/json; charset=utf-8")
            .header("correlationid", &self.uaid)
            .header("hpgact", "0")
            .header("hpgid", "200252")
            .header("priority", "u=1, i")
            .header("sec-ch-ua", "\"Chromium\";v=\"133\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"133\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("user-agent", &self.user_agent)
            .header("referer", &self.fmhf)
            .json(&body)
            .send()
            .await?;

        let text = response.text().await?;
        let json: Value = serde_json::from_str(&text)?;

        if !json.get("error").is_some()
            && json.get("apiCanary").and_then(Value::as_str).is_some()
            && json
                .get("telemetryContext")
                .and_then(Value::as_str)
                .is_some()
        {
            // println!("****************************************************");
            // println!("****************************************************");
            // println!("Success: verify code √√√ for account: {}", self.account);
            // println!("****************************************************");
            // println!("****************************************************");
            return Ok(format!(
                "{} √√√√√",
                UnlockStatus::UnlockSuccess.to_string()
            ));
        }

        if let Some(error) = json.get("error") {
            if let Some(code) = error.get("code").and_then(Value::as_str) {
                if let Some(&(_, error_message)) = self
                    .error_codes
                    .iter()
                    .find(|&&(code_entry, _)| code_entry == code)
                {
                    return Err(anyhow::anyhow!(format!(
                        "验证短信 ×× Error: code: {}, Details: {}",
                        code, error_message
                    )));
                } else {
                    if self.use_logger {
                        println!("consume ott request error: {}", text);
                    }
                    return Err(anyhow::anyhow!(format!(
                        "验证短信 ×× Error: {}",
                        UnlockStatus::UnlockUnknownError.to_string()
                    )));
                }
            }
        }
        if self.use_logger {
            println!("Error: {}", text);
        }
        return Err(anyhow::anyhow!(format!(
            "验证短信 ×× Error: {}",
            UnlockStatus::UnlockUnknownError.to_string()
        )));
    }
}
