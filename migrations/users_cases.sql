CREATE TABLE `users` (
    `id` char(36) NOT NULL PRIMARY KEY DEFAULT (UUID()),
    `name` varchar(100) NOT NULL,
    `email` varchar(255) NOT NULL UNIQUE,
    `photo` varchar(255) NOT NULL DEFAULT 'default.png',
    `verified` tinyint(1) NOT NULL DEFAULT 0,
    `password` varchar(100) NOT NULL,
    `role` varchar(50) NOT NULL DEFAULT 'user',
    `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE INDEX users_email_idx ON users (email);


CREATE TABLE
    IF NOT EXISTS cases (
        id CHAR(36) PRIMARY KEY NOT NULL,
        user_id CHAR(36) NOT NULL,  -- 新增字段
        title VARCHAR(255) NOT NULL UNIQUE,
        host VARCHAR(100) NOT NULL,
        uri VARCHAR(200) NOT NULL,
        method VARCHAR(100),
        request_body TEXT,
        expected_result TEXT ,
        category VARCHAR(100),
        response_code  TEXT ,
        response_body TEXT ,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)  -- 新增外键关联
    );

