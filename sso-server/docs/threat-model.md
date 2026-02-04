# 威胁建模与安全设计

## 威胁模型

### 1. 密码攻击

| 威胁     | 防护措施                          |
| -------- | --------------------------------- |
| 暴力破解 | 登录限流、账户锁定、验证码        |
| 字典攻击 | 强密码策略、密码复杂度检查        |
| 彩虹表   | Argon2id + 唯一 Salt              |
| 密码泄露 | Argon2id 高内存参数，减缓破解速度 |

### 2. Token 攻击

| 威胁               | 防护措施                    |
| ------------------ | --------------------------- |
| Token 窃取         | HTTPS Only、HttpOnly Cookie |
| Token 重放         | 短生命周期 Access Token     |
| Token 伪造         | Ed25519 签名验证            |
| Refresh Token 泄露 | 单次使用 + 自动轮换         |

### 3. 会话攻击

| 威胁     | 防护措施                                 |
| -------- | ---------------------------------------- |
| 会话固定 | 登录后重新生成 Session ID                |
| 会话劫持 | TLS 1.3、Secure Cookie、SameSite         |
| CSRF     | SameSite=Strict、CSRF Token              |
| XSS      | HttpOnly Cookie、Content Security Policy |

### 4. 基础设施攻击

| 威胁       | 防护措施                   |
| ---------- | -------------------------- |
| 中间人攻击 | 强制 TLS 1.3、HSTS         |
| DDoS       | 限流、CDN、防火墙          |
| SQL 注入   | 参数化查询、ORM            |
| NoSQL 注入 | 输入验证、Redis 命令白名单 |

---

## 安全设计原则

### 1. 最小权限原则

- 服务账户仅授予必要权限
- 数据库用户仅限必要操作
- API 权限细粒度控制

### 2. 纵深防御

- 网络层：防火墙 + TLS
- 应用层：认证 + 授权 + 输入验证
- 数据层：加密存储 + 访问控制

### 3. 失败安全

- 认证失败不泄露信息
- 异常不暴露系统细节
- 默认拒绝访问

### 4. 审计与监控

- 记录所有认证操作
- 监控异常登录行为
- 定期安全审计

---

## 密钥管理

### 私钥存储

```bash
# 生成 Ed25519 密钥对
openssl genpkey -algorithm ed25519 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

### 密钥注入

- **开发环境**：本地文件 + .gitignore
- **生产环境**：环境变量 / AWS Secrets Manager / HashiCorp Vault

### 密钥轮换

- 每 3–6 个月轮换一次
- 使用 `kid` 支持多密钥并存
- 旧密钥在过渡期内保留用于验证

---

## 合规性

- GDPR：用户数据加密、删除权利
- OWASP Top 10：覆盖主要漏洞防护
- OAuth2 / OIDC 规范遵循
