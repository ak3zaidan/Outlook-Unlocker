use lazy_static::lazy_static;
use log::info;
use rquest::Client;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::time::sleep;
use std::collections::HashMap;
use crate::daisy::DaisySMSClient;
use crate::panel;
use crate::country::get_country_code;

static PROGRESS_ID: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref IS_ENGLISH: AtomicBool = AtomicBool::new(false);
}

pub fn is_english_mode() -> bool {
    IS_ENGLISH.load(Ordering::Relaxed)
}

pub fn convert_proxy_format(proxy_url: &str) -> String {
    // 尝试解析URL
    if let Ok(url) = url::Url::parse(proxy_url) {
        // 获取主机和端口
        if let (Some(host), Some(port)) = (url.host_str(), url.port()) {
            // 获取用户名
            let username = url.username();
            if !username.is_empty() {
                // 获取用户名和密码部分
                let user_info = if let Some(password) = url.password() {
                    format!("{}:{}", username, password)
                } else {
                    username.to_string()
                };

                // 返回自定义格式
                return format!(
                    "http:{}:{}:{}",
                    host,
                    port,
                    user_info.replace('@', "") // 移除可能的@符号
                );
            }

            // 如果没有用户信息，只返回主机和端口
            return format!("http:{}:{}", host, port);
        }
    }

    // 如果解析失败，返回原始URL
    proxy_url.to_string()
}

pub enum UnlockStatus {
    UnlockSuccess,
    UnlockShowSkip7DaysButton,
    UnlockShowAccountLockedButton,
    UnlockShowAcceptNewTermsButton,
    UnlockShowAccountPrivacyNoticeButton,
    UnlockUnknownError,
    UnlockEmptyParameter,
    UnlockTooManyRequest,
    UnlockAccountOrPasswordIncorrect,
    LoginSuccess,
    AlreadyUnlocked,
    UnlockProtected,
}

impl ToString for UnlockStatus {
    fn to_string(&self) -> String {
        let is_english = is_english_mode();
        match self {
            UnlockStatus::UnlockSuccess => {
                if is_english {
                    "Success".to_string()
                } else {
                    "成功".to_string()
                }
            }
            UnlockStatus::UnlockShowSkip7DaysButton => {
                if is_english {
                    "ShowSkip7DaysButton".to_string()
                } else {
                    "显示跳过7天按钮".to_string()
                }
            }
            UnlockStatus::UnlockShowAccountLockedButton => {
                if is_english {
                    "ShowAccountLockedButton".to_string()
                } else {
                    "显示账户锁定按钮".to_string()
                }
            }
            UnlockStatus::UnlockShowAccountPrivacyNoticeButton => {
                if is_english {
                    "ShowAccountPrivacyNoticeButton".to_string()
                } else {
                    "显示账户隐私通知按钮".to_string()
                }
            }
            UnlockStatus::UnlockShowAcceptNewTermsButton => {
                if is_english {
                    "ShowAcceptNewTermsButton".to_string()
                } else {
                    "显示接受新条款按钮".to_string()
                }
            }
            UnlockStatus::UnlockUnknownError => {
                if is_english {
                    "UnknownError".to_string()
                } else {
                    "未知错误".to_string()
                }
            }
            UnlockStatus::UnlockEmptyParameter => {
                if is_english {
                    "EmptyParameter".to_string()
                } else {
                    "参数为空".to_string()
                }
            }
            UnlockStatus::UnlockTooManyRequest => {
                if is_english {
                    "TooManyRequest".to_string()
                } else {
                    "请求过多".to_string()
                }
            }
            UnlockStatus::LoginSuccess => {
                if is_english {
                    "LoginSuccess".to_string()
                } else {
                    "登录成功".to_string()
                }
            }
            UnlockStatus::UnlockAccountOrPasswordIncorrect => {
                if is_english {
                    "AccountOrPasswordIncorrect".to_string()
                } else {
                    "账号或密码错误".to_string()
                }
            }
            UnlockStatus::AlreadyUnlocked => {
                if is_english {
                    "AlreadyUnlocked".to_string()
                } else {
                    "已经解锁".to_string()
                }
            }
            UnlockStatus::UnlockProtected => {
                if is_english {
                    "UnlockProtected".to_string()
                } else {
                    "解锁保护".to_string()
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct TaskResult {
    pub error: Option<anyhow::Error>,
    pub message: String,
    pub success: bool,
    pub retry: bool,
}

impl TaskResult {
    fn new() -> Self {
        Self {
            error: None,
            message: String::new(),
            success: false,
            retry: false,
        }
    }
}

struct CaptchaSolver {
    client: Client,
    client_key: String,
    proxy: Option<String>,
    china: bool,
}

impl CaptchaSolver {
    async fn new(client_key: &str, proxy: Option<String>, china: bool) -> anyhow::Result<Self> {
        let client_builder = rquest::Client::builder();

        Ok(Self {
            client: client_builder.build()?,
            client_key: client_key.to_string(),
            proxy,
            china,
        })
    }

    async fn create_task(&self, arkose_blob: &str) -> anyhow::Result<String> {
        let mut task = serde_json::json!({
            "clientKey": self.client_key,
            "task": {
                "websiteURL": "https://account.live.com",
                "websiteKey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "type": "FuncaptchaTaskProxyless",
                "proxy": "",
                "cn": self.china,
                "data": serde_json::to_string(&serde_json::json!({
                    "blob": arkose_blob
                }))?
            }
        });

        match self.proxy.clone() {
            Some(proxy) => {
                task["task"]["proxy"] = proxy.into();
            }
            None => {}
        }

        let response = self.client
            .post("https://kocaptcha.com/api/task/create")
            .header("Content-Type", "application/json")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .body(serde_json::to_string(&task)?)
            .send()
            .await?;

        let response_json = response.json::<serde_json::Value>().await?;

        if let Some(task_id) = response_json.get("taskId") {
            Ok(task_id.as_str().unwrap_or("").to_string())
        } else {
            Err(anyhow::anyhow!("Failed to get taskId from response"))
        }
    }

    async fn get_result(&self, task_id: &str) -> anyhow::Result<String> {
        let max_attempts = 600;
        let mut attempts = 0;

        loop {
            if attempts >= max_attempts {
                return Err(anyhow::anyhow!(
                    "Max attempts reached while waiting for captcha result"
                ));
            }

            let body = serde_json::json!({
                "clientKey": self.client_key,
                "taskId": task_id
            });

            let response = self.client
                .post("https://kocaptcha.com/api/task/result")
                .header("Content-Type", "application/json")
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
                .body(serde_json::to_string(&body)?)
                .send()
                .await?;

            let response_json = response.json::<serde_json::Value>().await?;

            // 检查 errorId
            let error_id = response_json
                .get("errorId")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            if error_id != 0 {
                let error_description = response_json
                    .get("errorDescription")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                return Err(anyhow::anyhow!("API Error: {}", error_description));
            }

            // 获取 token
            if let Some(token) = response_json
                .get("solution")
                .and_then(|s| s.get("token"))
                .and_then(|t| t.as_str())
            {
                if !token.is_empty() {
                    // println!("Captcha pass success");
                    let current_timestamp_ms: u128 = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_millis();
                    let error_description = response_json
                        .get("errorDescription")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");

                    let error_description_int = error_description.parse::<u128>().unwrap_or(0);

                    let _time_diff = if error_description_int > current_timestamp_ms {
                        error_description_int - current_timestamp_ms
                    } else {
                        current_timestamp_ms - error_description_int
                    };

                    return Ok(token.to_string());
                }
            }

            attempts += 1;
            sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    async fn solve_captcha(&self, arkose_blob: &str) -> anyhow::Result<String> {
        let task_id: String = self.create_task(arkose_blob).await?;

        sleep(std::time::Duration::from_millis(1000)).await;

        self.get_result(&task_id).await
    }
}

const TASK_PROXY: bool = true;

pub async fn main_unlocker(
    input_account: Option<String>,
    input_password: Option<String>,
    input_country: Option<String>,
    input_proxy: Option<String>,
    funcap_key: String,
    sms_key: String,
) -> Result<TaskResult, anyhow::Error> {

    // 1. Setup
    let account = input_account.unwrap_or("".to_owned());
    let password = input_password.unwrap_or("".to_owned());
    let country = input_country.unwrap_or("US".to_owned());
    let proxy = input_proxy.unwrap_or("".to_owned());

    let mut task_result = TaskResult::new();

    let progress_id = PROGRESS_ID.fetch_add(1, Ordering::SeqCst) % 100;

    let mode = "unlock";
    let is_english = is_english_mode();
    let country_code = get_country_code(&country);

    // 2. Build Panel
    let panel_result = panel::PanelClient::new(proxy.to_string(), account.clone(), password.clone());
    let mut panel = match panel_result {
        Ok(panel) => panel,
        Err(err) => {
            let _error_msg = if is_english {
                format!(
                    "[{:02}][{}] Connection failed: {}",
                    progress_id, account, err
                )
            } else {
                format!("[{:02}][{}] 连接失败: {}", progress_id, account, err)
            };

            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;

            return Ok(task_result);
        }
    };

    // 3. Initial Login
    println!("1. Initial login for: {}", account);
    for i in 0..3 {
        let result = panel.login_initial_request().await;
        if result.is_ok() {
            break;
        }

        if i == 2 && result.is_err() {
            let err = result.unwrap_err();
            let _error_msg = if is_english {
                format!(
                    "[{:02}][{}] Initial login failed: {}",
                    progress_id, account, err
                )
            } else {
                format!("[{:02}][{}] 初始登录失败: {}", progress_id, account, err)
            };

            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    }

    // 4. Login
    println!("2. Second login for: {}", account);
    sleep(std::time::Duration::from_millis(7500)).await;
    for i in 0..1 {
        let result = panel.login_post_request(mode).await;

        if result.is_err() {
            let err = result.unwrap_err();
            if err.to_string().contains("ShowAccountPrivacyNoticeButton") {

                task_result.success = true;
                task_result.message = if is_english {
                    "Account unlocked".to_string()
                } else {
                    "账号已解锁".to_string()
                };
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english { "Unlocked" } else { "已解锁" }
                );
                return Ok(task_result);
            }
            if err.to_string().contains("ShowSkip7DaysButton") {

                task_result.success = true;
                task_result.message = if is_english {
                    "Account unlocked".to_string()
                } else {
                    "账号已解锁".to_string()
                };
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english { "Unlocked" } else { "已解锁" }
                );
                return Ok(task_result);
            }
            if err.to_string().contains("ShowAcceptNewTermsButton") {

                task_result.success = true;
                task_result.message = if is_english {
                    "Account unlocked".to_string()
                } else {
                    "账号已解锁".to_string()
                };
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english { "Unlocked" } else { "已解锁" }
                );
                return Ok(task_result);
            }
            if err.to_string().contains("LoginSuccess") {
                task_result.success = true;
                task_result.message = if is_english {
                    "Account unlocked".to_string()
                } else {
                    "账号已解锁".to_string()
                };
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english { "Unlocked" } else { "已解锁" }
                );
                return Ok(task_result);
            }
            if err.to_string().contains("AccountOrPasswordIncorrect") {

                task_result.success = false;
                task_result.retry = false;
                task_result.message = if is_english {
                    "Account or password incorrect".to_string()
                } else {
                    "账号或密码错误".to_string()
                };
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english {
                        "Account or password incorrect"
                    } else {
                        "账号或密码错误"
                    }
                );
                return Ok(task_result);
            }
            if err.to_string().contains("TooManyRequest") {

                if i == 2 {

                    task_result.message = err.to_string();
                    task_result.error = Some(err);
                    task_result.success = false;
                    task_result.retry = true;
                    return Ok(task_result);
                }
                continue;
            }
            if err.to_string().contains("error sending") {

                if i == 2 {

                    task_result.message = err.to_string();
                    task_result.error = Some(err);
                    task_result.success = false;
                    task_result.retry = true;
                    return Ok(task_result);
                }
                continue;
            }

            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }

        if result.is_ok() {
            break;
        }

        if i == 2 && result.is_err() {
            let err = result.unwrap_err();
            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    }

    // 5. Short delay
    sleep(std::time::Duration::from_millis(5000)).await;

    // 6. Unlock Request
    println!("3. Unlock request for: {}", account);
    for i in 0..1 {
        let result = panel.unlock_request().await;

        if result.is_ok() {
            break;
        }

        if i == 2 && result.is_err() {
            let err = result.unwrap_err();
            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    }

    // 7. Rent Number from daisy sms
    let client_sms = DaisySMSClient::new(&sms_key, "mm");

    let mut options = HashMap::new();
    options.insert("maxPrice".to_string(), "0.5".to_string());
    
    println!("4. Renting a phone number...");
    let (rental_id, mut phone) = match client_sms.rent_number(Some(options)).await {
        Ok(result) => result,
        Err(e) => {
            println!("Failed to rent number: {}", e);

            task_result.message = e.to_string();
            task_result.error = Some(anyhow::anyhow!("Failed to rent number: {}", e));
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    };
    println!("5. Successfully rented number: {}", phone);

    if phone.starts_with(&country_code) {
        phone = phone[country_code.len()..].to_owned();
    }

    // 8. Send OTP request for phone number and solve captcha
    sleep(std::time::Duration::from_millis(5000)).await;

    let mut funcaptcha_token: String = String::new();

    for i in 0..1 {

        let result = panel.send_ott_request(&country, &phone).await;

        if result.is_err() {
            let err = result.unwrap_err();
            let message = err.to_string();

            let _ = client_sms.cancel_rental(&rental_id).await;

            if message.contains("1346, Details: FraudBlocked") {

                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english {
                        "Phone number abuse, cannot continue"
                    } else {
                        "手机号码滥用，无法继续"
                    }
                );
                task_result.message = err.to_string();
                task_result.error = Some(err);
                task_result.success = false;
                task_result.retry = false;
                return Ok(task_result);
            }

            info!("[{:02}][{}] {}", progress_id, account, message);
            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = false;
            return Ok(task_result);
        }

        if panel.blob_data.is_empty() || panel.risk_score.is_empty() {
            info!(
                "[{:02}][{}] {}",
                progress_id,
                account,
                if is_english {
                    format!("No verification data received, retrying {}/10...", i + 1)
                } else {
                    format!("未获取到验证数据, 重试中 {}/10...", i + 1)
                }
            );

            continue;
        }

        let blob = panel.blob_data.as_str();

        let proxy_string = if TASK_PROXY {
            convert_proxy_format(&proxy)
        } else {
            "".to_string()
        };

        let solver = match CaptchaSolver::new(
            funcap_key.clone().as_str(),
            Some(proxy_string.clone()),
            false,
        )
        .await
        {
            Ok(solver) => solver,
            Err(_e) => {
                let _ = client_sms.cancel_rental(&rental_id).await;

                return Err(anyhow::anyhow!(if is_english {
                    "Failed to create captcha solver"
                } else {
                    "创建验证码解析器失败"
                }));
            }
        };

        funcaptcha_token = match solver.solve_captcha(&blob).await {
            Ok(funcaptcha_token) => funcaptcha_token,
            Err(e) => {
                let _ = client_sms.cancel_rental(&rental_id).await;

                return Err(anyhow::anyhow!(if is_english {
                    format!("Failed to solve captcha: {}", e)
                } else {
                    format!("验证码解析失败: {}", e)
                }));
            }
        };

        if !funcaptcha_token.is_empty() {

            let result = panel
                .send_ott_request_hip_enforcement_needed(&country, &phone, &funcaptcha_token)
                .await;

            if result.is_ok() {
                break;
            } else {
                let err = result.unwrap_err();
                let msg = err.to_string();
                info!("[{:02}][{}] {}", progress_id, account, msg);

                if !msg.contains("1340") {
                    let _ = client_sms.cancel_rental(&rental_id).await;

                    task_result.message = msg;
                    task_result.error = Some(err);
                    task_result.success = false;
                    task_result.retry = false;

                    return Ok(task_result);
                }

                if msg.contains("1208") {
                    let _ = client_sms.cancel_rental(&rental_id).await;

                    task_result.message = msg;
                    task_result.error = Some(err);
                    task_result.success = false;
                    task_result.retry = false;

                    return Ok(task_result);
                }

                funcaptcha_token = "".to_owned();
                continue;
            }
        }
    }

    // 9. Validate solve
    if funcaptcha_token.is_empty() {
        let _ = client_sms.cancel_rental(&rental_id).await;

        let err = anyhow::anyhow!(if is_english {
            "Captcha solving failed"
        } else {
            "打码失败"
        });

        task_result.message = err.to_string();
        task_result.error = Some(err);
        task_result.success = false;
        task_result.retry = true;
        return Ok(task_result);
    }

    // 10. Get SMS code
    println!("6. Getting sms for: {}", account);
    let code = match client_sms.poll_for_code(&rental_id, 120).await {
        Ok(code) => {
            println!("Received SMS code: {}", code);
            code
        }
        Err(e) => {
            println!("Failed to get SMS code: {}", e);
            let _ = client_sms.cancel_rental(&rental_id).await;

            task_result.message = e.to_string();
            task_result.error = Some(anyhow::anyhow!("Failed to get sms: {}", e));
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    };

    // Get rid of rental
    let _ = client_sms.cancel_rental(&rental_id).await;

    // 11. Validate code
    if code.len() != 4 {
        info!(
            "[{:02}][{}] {}",
            progress_id,
            account,
            if is_english {
                format!("Invalid verification code format: {}", code)
            } else {
                format!("获取的验证码格式不正确: {}", code)
            }
        );

        let err = anyhow::anyhow!(if is_english {
            "No SMS received"
        } else {
            "未获取到短信"
        });

        task_result.message = err.to_string();
        task_result.error = Some(err);
        task_result.success = false;
        task_result.retry = true;
        return Ok(task_result);
    }

    // 12. Log status
    info!(
        "[{:02}][{}] {}",
        progress_id,
        account,
        if is_english {
            format!("Verifying SMS...{}", code)
        } else {
            format!("验证短信...{}", code)
        }
    );

    // 13. Submit code
    println!("7. Submitting SMS for: {}", account);
    let consume_result = panel.consume_ott_request(&country, &phone, &code).await;
    match consume_result {
        Ok(result) => {
            if result.contains("IncorrectVerificationCode") {
                info!(
                    "[{:02}][{}] {}",
                    progress_id,
                    account,
                    if is_english {
                        format!("Incorrect verification code: {}", code)
                    } else {
                        format!("短信验证码错误: {}", code)
                    }
                );

                let err = anyhow::anyhow!(if is_english {
                    "Incorrect verification code"
                } else {
                    "短信验证码错误"
                });
                
                task_result.message = err.to_string();
                task_result.error = Some(err);
                task_result.success = false;
                task_result.retry = true;
                return Ok(task_result);
            }

            info!(
                "[{:02}][{}] {}",
                progress_id,
                account,
                if is_english {
                    "Unlock process completed!"
                } else {
                    "解锁流程完成！"
                }
            );

            task_result.success = true;
            task_result.message = if is_english {
                "Unlock process completed!".to_string()
            } else {
                "解锁流程完成！".to_string()
            };

            Ok(task_result)
        }
        Err(err) => {
            info!("[{:02}][{}] {}", progress_id, account, err);
            task_result.message = err.to_string();
            task_result.error = Some(err);
            task_result.success = false;
            task_result.retry = true;
            return Ok(task_result);
        }
    }
}
