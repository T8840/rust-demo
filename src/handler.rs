use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Path, Query, State},
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng;
use serde_json::json;

use crate::{
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
    AppState,
};

use crate::{
    model::{CaseModel, CaseModelResponse, CaseModelAllResponse},
    schema::{CreateCaseSchema, FilterOptions, UpdateCaseSchema},
};

pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str = "Rust Project using Axum, MySQl, and SQLX";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
            .bind(body.email.to_owned().to_ascii_lowercase())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "User with that email already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let user= sqlx::query_as!(
        User,
        r#"INSERT INTO users (name,email,password) VALUES (?, ?, ?)"#,
        body.name.to_string(),
        body.email.to_string().to_ascii_lowercase(),
        hashed_password
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let user = sqlx::query_as!(User, 
        "SELECT * FROM users WHERE email = ?", 
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    // let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
    //     "user": filter_user_record(&user)
    // })});
    // Ok(Json(user_response))

    if let Some(user) = user {
        let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
            "user": filter_user_record(&user)
        })});
    
        Ok(Json(user_response))
    } else {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "User not found",
        });
        Err((StatusCode::NOT_FOUND, Json(error_response)))
    }

}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user = sqlx::query_as!(User, 
        "SELECT * FROM users WHERE email = ?", 
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password",
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    if !is_valid {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password"
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build("token", token.to_owned())
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success", "token": token}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn get_me_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(Json(json_response))
}

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified!=0,
        // createdAt: user.created_at.unwrap(),
        // updatedAt: user.updated_at.unwrap(),
        createdAt: user.created_at,
        updatedAt: user.updated_at,
    }
}

// -----------------------------------------------------------//
// ------------------------- Case-----------------------------//
// -----------------------------------------------------------//

pub async fn case_list_handler(
    Extension(user): Extension<User>,
    opts: Option<Query<FilterOptions>>,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let Query(opts) = opts.unwrap_or_default();

    let limit = opts.limit.unwrap_or(10);
    let offset = (opts.page.unwrap_or(1) - 1) * limit;

    let cases = sqlx::query_as!(
        CaseModel,
        // r#"SELECT * FROM cases ORDER by id LIMIT ? OFFSET ?"#,
        // limit as i32,
        // offset as i32
        r#"SELECT * FROM cases WHERE user_id = ? ORDER by id LIMIT ? OFFSET ?"#,
        user.id,
        limit as i32,
        offset as i32
        
    )
    .fetch_all(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let case_responses = cases
        .iter()
        .map(|case| filter_db_record(&case))
        .collect::<Vec<CaseModelResponse>>();

    let json_response = serde_json::json!({
        "status": "success",
        "results": case_responses.len(),
        "cases": case_responses
    });

    Ok(Json(json_response))
}

pub async fn create_case_handler(
    Extension(user): Extension<User>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<CreateCaseSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("[create_case_handler]Get User From Header: {:?}", user);
    let case_id = uuid::Uuid::new_v4().to_string();
    let query_result =
        sqlx::query(r#"INSERT INTO cases (id,user_id,title,host,uri,method,request_body,expected_result,category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#)
            .bind(case_id.clone())
            .bind(user.id.to_string()) // 使用User中的id   
            .bind(body.title.to_string())
            .bind(body.host.to_string())
            .bind(body.uri.to_string())
            .bind(body.method.to_owned().to_string())
            .bind(body.request_body.to_string())
            .bind(body.expected_result.to_string())
            .bind(body.category.to_owned().unwrap_or_default())
            .execute(&data.db)
            .await
            .map_err(|err: sqlx::Error| err.to_string());

    if let Err(err) = query_result {
        if err.contains("Duplicate entry") {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Case with that title already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("{:?}", err)})),
        ));
    }

    // let case = sqlx::query_as!(CaseModel, r#"SELECT * FROM cases WHERE id = ?"#, user_id)
    let case = sqlx::query_as!(CaseModel, r#"SELECT * FROM cases WHERE id = ?"#, case_id)
        .fetch_one(&data.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            )
        })?;

    let case_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "case": filter_db_record(&case)
    })});

    Ok(Json(case_response))
}

pub async fn get_case_handler(
    Path(id): Path<uuid::Uuid>,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query_result = sqlx::query_as!(
        CaseModel,
        r#"SELECT * FROM cases WHERE id = ?"#,
        id.to_string()
    )
    .fetch_one(&data.db)
    .await;

    match query_result {
        Ok(case) => {
            let case_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "case": filter_db_record(&case)
            })});

            return Ok(Json(case_response));
        }
        Err(sqlx::Error::RowNotFound) => {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Case with ID: {} not found", id)
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            ));
        }
    };
}

pub async fn edit_case_handler(
    Path(id): Path<uuid::Uuid>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<UpdateCaseSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query_result = sqlx::query_as!(
        CaseModel,
        r#"SELECT * FROM cases WHERE id = ?"#,
        id.to_string()
    )
    .fetch_one(&data.db)
    .await;

    let case = match query_result {
        Ok(case) => case,
        Err(sqlx::Error::RowNotFound) => {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Case with ID: {} not found", id)
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            ));
        }
    };

    let used = body.used.unwrap_or(case.used != 0);
    let i8_used = used as i8;

    let update_result = sqlx::query(
        r#"UPDATE cases SET user_id = ?,title = ?, host = ?, uri = ?, method = ? , request_body = ?, expected_result = ?, category = ?, response_code = ?, response_body = ?, used = ? WHERE id = ?"#,
    )
    .bind(body.user_id.to_owned().unwrap_or_else(|| case.user_id.clone())) // 使用body中的user_id

    .bind(body.title.to_owned().unwrap_or_else(|| case.title.clone()))
    .bind(
        body.host
            .to_owned()
            .unwrap_or_else(|| case.host.clone()),
    )
    .bind(
        body.uri
            .to_owned()
            .unwrap_or_else(|| case.uri.clone()),
    )
    .bind(
        body.method
            .to_owned()
            .unwrap_or_else(|| case.method.clone().unwrap()),
    )
    .bind(
        body.request_body
            .to_owned()
            .unwrap_or_else(|| case.request_body.clone().unwrap()),
    )
    .bind(
        body.expected_result
            .to_owned()
            .unwrap_or_else(|| case.expected_result.clone().unwrap()),
    )
    .bind(
        body.category
            .to_owned()
            .unwrap_or_else(|| case.category.clone().unwrap()),
    )
    .bind(
        body.response_code
            .to_owned()
            .unwrap_or_else(|| case.response_code.clone().unwrap()),
    )
    .bind(
        body.response_body
            .to_owned()
            .unwrap_or_else(|| case.response_body.clone().unwrap()),
    )
    .bind(i8_used)
    .bind(id.to_string())
    .execute(&data.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("{:?}", e)})),
        )
    })?;

    if update_result.rows_affected() == 0 {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Case with ID: {} not found", id)
        });
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }

    let updated_case = sqlx::query_as!(
        CaseModel,
        r#"SELECT * FROM cases WHERE id = ?"#,
        id.to_string()
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("{:?}", e)})),
        )
    })?;

    let case_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "case": filter_db_record(&updated_case)
    })});

    Ok(Json(case_response))
}

pub async fn delete_case_handler(
    Path(id): Path<uuid::Uuid>,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query_result = sqlx::query!(r#"DELETE FROM cases WHERE id = ?"#, id.to_string())
        .execute(&data.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            )
        })?;

    if query_result.rows_affected() == 0 {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Case with ID: {} not found", id)
        });
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }

    Ok(StatusCode::NO_CONTENT)
}

fn filter_db_record(case: &CaseModel) -> CaseModelResponse {
    CaseModelResponse {
        id: case.id.to_owned(),
        user_id: case.user_id.to_owned(),
        title: case.title.to_owned(),
        host: case.host.to_owned(),
        uri: case.uri.to_owned(),
        method: case.method.to_owned().unwrap(),
        request_body: case.request_body.to_owned().unwrap(),
        expected_result: case.expected_result.to_owned().unwrap(),
        category: case.category.to_owned().unwrap(),
        // response_code: case.response_code.to_owned().unwrap(),
        // response_body: case.response_body.to_owned().unwrap(),
        used: case.used != 0,
        createdAt: case.created_at.unwrap(),
        updatedAt: case.updated_at.unwrap(),
    }
}

fn filter_db_all_record(case: &CaseModel) -> CaseModelAllResponse {
    CaseModelAllResponse {
        id: case.id.to_owned(),
        user_id: case.user_id.to_owned(),
        title: case.title.to_owned(),
        host: case.host.to_owned(),
        uri: case.uri.to_owned(),
        method: case.method.to_owned().unwrap(),
        request_body: case.request_body.to_owned().unwrap(),
        expected_result: case.expected_result.to_owned().unwrap(),
        category: case.category.to_owned().unwrap(),
        response_code: case.response_code.to_owned().unwrap(),
        response_body: case.response_body.to_owned().unwrap(),
        used: case.used != 0,
        createdAt: case.created_at.unwrap(),
        updatedAt: case.updated_at.unwrap(),
    }
}


// use std::error::Error;
// pub async fn send_request(case: &mut CaseModel) -> Result<(), Box<dyn Error>> {
//     let url = format!("{}{}", case.host, case.uri);
//     // 发送 GET 请求
//     let response = reqwest::get(&url).await?;
//     // 将响应结果存储到 model 中
//     case.response_code = Some(response.status().to_string());
//     if let Ok(body) = response.text().await {
//         case.response_body = Some(body);
//     }
//     Ok(())
// }

// pub async fn test_case_handler(
//     Path(id): Path<uuid::Uuid>,
//     State(data): State<Arc<AppState>>,
// ) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
//     let query_result = sqlx::query_as!(
//         CaseModel,
//         r#"SELECT * FROM cases WHERE id = ?"#,
//         id.to_string()
//     )
//     .fetch_one(&data.db)
//     .await;

//     match query_result {
//         Ok(case) => {

//             let case_response = serde_json::json!({"status": "success","data": serde_json::json!({
//                 "case": filter_db_record(&case)
//             })});

//             return Ok(Json(case_response));
//         }
//         Err(sqlx::Error::RowNotFound) => {
//             let error_response = serde_json::json!({
//                 "status": "fail",
//                 "message": format!("Case with ID: {} not found", id)
//             });
//             return Err((StatusCode::NOT_FOUND, Json(error_response)));
//         }
//         Err(e) => {
//             return Err((
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 Json(json!({"status": "error","message": format!("{:?}", e)})),
//             ));
//         }
//     };
// }



pub async fn test_case_handler(
    Path(id): Path<uuid::Uuid>,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let query_result = sqlx::query_as!(
        CaseModel,
        r#"SELECT * FROM cases WHERE id = ?"#,
        id.to_string()
    )
    .fetch_one(&data.db)
    .await;

    match query_result {
        Ok(mut case) => {

            // 构建请求
            let client = reqwest::Client::new();
            let url = format!("{}{}", case.host, case.uri);
            let method = case.method.unwrap_or_else(|| "GET".to_string()).to_uppercase();
    
            // 构建请求体，如果没有提供，则默认为空
            let body = case.request_body.clone().unwrap_or_default();
    
            let response = match method.as_str() {
                "GET" => client.get(&url).send().await,
                "POST" => client.post(&url).body(body).send().await,
                _ => {
                    return Err((
                        StatusCode::METHOD_NOT_ALLOWED,
                        Json(json!({"status": "error","message": format!("Method: {} is not supported", method)})),
                    ))
                }
            };
    
            // 检查请求是否成功
            match response {
                Ok(mut res) => {
                    case.response_code = Some(res.status().to_string());
                    case.response_body = Some(res.text().await.unwrap_or_default());
                    
                    // 将更新后的模型保存回数据库
                    sqlx::query!(
                        "UPDATE cases SET response_code = ?, response_body = ? WHERE id = ?",
                        case.response_code, case.response_body, id.to_string()
                    )
                    .execute(&data.db)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"status": "error","message": format!("{:?}", e)})),
                        )
                    })?;
                    
                    let updated_case = sqlx::query_as!(
                        CaseModel,
                        r#"SELECT * FROM cases WHERE id = ?"#,
                        id.to_string()
                    )
                    .fetch_one(&data.db)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"status": "error","message": format!("{:?}", e)})),
                        )
                    })?;

                    let case_response = serde_json::json!({"status": "success","data": serde_json::json!({
                        "case": filter_db_all_record(&updated_case)
                    })});
    
                    return Ok(Json(case_response));
                }
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": "error","message": format!("Request failed: {:?}", e)})),
                    ))
                }
            }
        }
        Err(sqlx::Error::RowNotFound) => {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Case with ID: {} not found", id)
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            ));
        }
    };
    
} 