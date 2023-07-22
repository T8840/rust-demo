use chrono::prelude::*;
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String,
    pub photo: String,
    pub verified: i8,
    // pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    // pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}


pub struct CaseModel {
    pub id: String,
    pub user_id: String,  // 新增字段
    pub title: String,
    pub host: String,
    pub uri: String,
    pub method: Option<String>,
    pub request_body:  Option<String>,
    pub expected_result:  Option<String>,
    pub category: Option<String>,
    pub response_code:  Option<String>,
    pub response_body:  Option<String>,
    pub used: i8,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct CaseModelResponse {
    pub id: String,
    pub user_id: String,  // 新增字段
    pub title: String,
    pub host: String,
    pub uri: String,
    pub method: String,
    pub request_body: String,
    pub expected_result: String,
    pub category: String,
    // pub response_code: String,
    // pub response_body: String,
    pub used: bool,
    pub createdAt: chrono::DateTime<chrono::Utc>,
    pub updatedAt: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct CaseModelAllResponse {
    pub id: String,
    pub user_id: String,  // 新增字段
    pub title: String,
    pub host: String,
    pub uri: String,
    pub method: String,
    pub request_body: String,
    pub expected_result: String,
    pub category: String,
    pub response_code: String,
    pub response_body: String,
    pub used: bool,
    pub createdAt: chrono::DateTime<chrono::Utc>,
    pub updatedAt: chrono::DateTime<chrono::Utc>,
}