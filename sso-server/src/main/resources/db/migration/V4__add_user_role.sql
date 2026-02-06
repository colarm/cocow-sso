-- 添加用户角色字段
ALTER TABLE users
ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'USER';

-- 创建角色索引
CREATE INDEX idx_users_role ON users (role);

-- 添加客户端所有者字段
ALTER TABLE oauth_clients ADD COLUMN owner_id BIGINT NULL;

-- 创建所有者索引
CREATE INDEX idx_clients_owner ON oauth_clients (owner_id);

-- 更新第一个用户为系统管理员（如果存在）
UPDATE users SET role = 'ADMIN' WHERE id = 1;