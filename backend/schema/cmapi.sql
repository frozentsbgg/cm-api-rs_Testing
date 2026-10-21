-- Schema for the cmapi database
-- Used by cm-api-rs for storing Steam authentication tokens and SS14 login sessions

CREATE DATABASE IF NOT EXISTS cmapi;
USE cmapi;

CREATE TABLE steam_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    steam_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_steam_id (steam_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE ban_appeals (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ckey VARCHAR(64) NOT NULL,
    ban_type VARCHAR(32) NOT NULL,
    ban_reference_id VARCHAR(128) NOT NULL,
    discourse_topic_id BIGINT NOT NULL,
    discourse_topic_url VARCHAR(512) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ckey_status (ckey, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Short-lived records of CM-account logins to Space Station 14 servers (see src/ss14auth.rs).
-- A row is written when the game client registers a connection and deleted when the game
-- server confirms it; rows older than a few minutes are purged.
CREATE TABLE ss14_sessions (
    hash VARCHAR(64) NOT NULL PRIMARY KEY,
    ss14_user_id VARCHAR(64) NOT NULL,
    user_name VARCHAR(32) NOT NULL,
    ckey VARCHAR(64) NOT NULL,
    hwid VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Which SS14 identity each CM account plays CMU-14 as. Written on first join, then fixed.
-- source: 'wizden' = the Space Wizards account linked in the CM portal; 'cm' = an id minted
-- from the ckey (uuid5 in the cm-ss13.com namespace) for accounts with nothing linked.
CREATE TABLE ss14_identities (
    ckey VARCHAR(64) NOT NULL PRIMARY KEY,
    ss14_user_id VARCHAR(36) NOT NULL UNIQUE,
    source ENUM('wizden', 'cm') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
