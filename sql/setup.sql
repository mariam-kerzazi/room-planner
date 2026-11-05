CREATE DATABASE IF NOT EXISTS roomplanner;
USE roomplanner;
 
CREATE TABLE IF NOT EXISTS users (
	user_id INT AUTO_INCREMENT PRIMARY KEY,
	username VARCHAR(50) NOT NULL UNIQUE,
	email VARCHAR(100) NOT NULL UNIQUE,
	password CHAR(128) NOT NULL,   -- 64-byte hash stored as hex = 128 characters
	salt CHAR(32) NOT NULL,        -- 16 random bytes stored as hex = 32 characters
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
