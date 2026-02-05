-- 添加客户端类型字段
ALTER TABLE oauth_clients
ADD COLUMN client_type VARCHAR(20) NOT NULL DEFAULT 'CONFIDENTIAL' COMMENT '客户端类型: PUBLIC(公开客户端,必须PKCE) 或 CONFIDENTIAL(机密客户端,PKCE可选)';

-- 为现有客户端设置默认类型为 CONFIDENTIAL
UPDATE oauth_clients
SET
    client_type = 'CONFIDENTIAL'
WHERE
    client_type IS NULL;