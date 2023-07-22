use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Default)]
pub struct FilterOptions {
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Deserialize, Debug)]
pub struct ParamOptions {
    pub id: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct CreateCaseSchema {
    pub user_id: Option<String>, // 新增字段
    pub title: String,
    pub host: String,
    pub uri: String,
    pub method: String,
    pub request_body: String,
    pub expected_result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateCaseSchema {
    pub user_id: Option<String>, // 新增字段
    pub title: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub method: Option<String>,
    pub request_body: Option<String>,
    pub expected_result: Option<String>,
    pub category: Option<String>,
    pub response_code: Option<String>,
    pub response_body: Option<String>,
    pub used: Option<bool>,
}
