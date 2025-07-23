use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Account {
    pub id: u32,
    pub account: String,
    pub password: String,
    pub status: u8, // 0: 未运行, 1: 运行中, 2: 已完成, 3: 已失败
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct TaskProgress {
    pub total: u32,
    pub current: u32,
    pub success: u32,
    pub failed: u32,
    pub speed: f64,                                // 添加时速字段 (每小时完成数)
    pub start_time: Option<std::time::SystemTime>, // 添加开始时间
}
