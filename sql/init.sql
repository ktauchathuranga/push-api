-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `push_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

-- Use the database
USE `push_db`;

-- Drop and create the fcm_tokens table
DROP TABLE IF EXISTS `fcm_tokens`;
CREATE TABLE `fcm_tokens` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `token` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `token` (`token`)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- Drop and create the users table
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(50) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- Optional: Insert sample data (uncomment if needed)
-- INSERT INTO `fcm_tokens` (`token`) VALUES ('sample_fcm_token_replace_me');
-- INSERT INTO `users` (`username`, `password_hash`) 
-- VALUES ('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');