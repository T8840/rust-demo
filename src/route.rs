use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    handler::{
        get_me_handler, health_checker_handler, login_user_handler, logout_handler,
        register_user_handler,
        create_case_handler, delete_case_handler, edit_case_handler, get_case_handler,
        case_list_handler,test_case_handler,

    },
    jwt_auth::auth,
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/healthchecker", get(health_checker_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route(
            "/api/auth/logout",
            get(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/users/me",
            get(get_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route("/api/cases/", post(create_case_handler)
            .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
        )
        .route("/api/cases", get(case_list_handler)
            .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
        )
        .route(
            "/api/cases/:id",
            get(get_case_handler)
                .patch(edit_case_handler)
                .delete(delete_case_handler),
        )
        .route("/api/cases/:id/test", get(test_case_handler))
        .with_state(app_state)
}
