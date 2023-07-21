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
