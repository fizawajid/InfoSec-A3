
-- Create the database
CREATE DATABASE IF NOT EXISTS securechat;
USE securechat;

-- Users table for storing credentials
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample data (for testing only - passwords are: "TestPassword123")
-- Salt: b'1234567890abcdef' (hex: 31323334353637383930616263646566)
-- Hash of salt||password
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('test@example.com', 'testuser', 
 UNHEX('31323334353637383930616263646566'),
 'a8c6e8c2e5b3c4a8c6e8c2e5b3c4a8c6e8c2e5b3c4a8c6e8c2e5b3c4a8c6e8c2')
ON DUPLICATE KEY UPDATE email=email;

-- Display users for verification
SELECT id, email, username, HEX(salt) as salt_hex, pwd_hash, created_at FROM users;
