-- OAuth2 客户端表
CREATE TABLE oauth_clients (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_client_id (client_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- OAuth2 客户端重定向 URI
CREATE TABLE oauth_client_redirect_uris (
    client_id BIGINT NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- OAuth2 客户端授权类型
CREATE TABLE oauth_client_grant_types (
    client_id BIGINT NOT NULL,
    grant_type VARCHAR(50) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- OAuth2 客户端权限范围
CREATE TABLE oauth_client_scopes (
    client_id BIGINT NOT NULL,
    scope VARCHAR(50) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- OAuth2 授权码表
CREATE TABLE oauth_authorization_codes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(100) NOT NULL UNIQUE,
    client_id VARCHAR(100) NOT NULL,
    user_id BIGINT NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scope VARCHAR(500),
    state VARCHAR(255),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_code (code),
    INDEX idx_client_user (client_id, user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- OAuth2 Token 表
CREATE TABLE oauth_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    access_token VARCHAR(1000) NOT NULL,
    refresh_token VARCHAR(1000),
    token_type VARCHAR(20) NOT NULL DEFAULT 'Bearer',
    client_id VARCHAR(100) NOT NULL,
    user_id BIGINT NOT NULL,
    scope VARCHAR(500),
    access_token_expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_access_token (access_token (255)),
    UNIQUE INDEX idx_refresh_token (refresh_token (255)),
    INDEX idx_client_user (client_id, user_id),
    INDEX idx_access_expires (access_token_expires_at),
    INDEX idx_refresh_expires (refresh_token_expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;