# SSO Server API 文档

## 📋 目录

- [已实现接口](#已实现接口)
- [待实现接口（OAuth2标准）](#待实现接口oauth2标准)
- [认证机制说明](#认证机制说明)

---

## ✅ 已实现接口

### 1. 健康检查

#### `GET /api/v1/health`

检查服务运行状态

**请求示例：**

```bash
curl http://localhost:8848/api/v1/health
```

**响应：**

```
SSO Server is running
```

**状态码：** `200 OK`

---

### 2. 用户注册

#### `POST /api/v1/auth/register`

注册新用户并自动登录

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | ✅ | 用户名 |
| email | string | ✅ | 邮箱地址 |
| password | string | ✅ | 密码 |
| rememberMe | boolean | ❌ | 记住登录（默认 false） |

**请求示例：**

```bash
curl -X POST http://localhost:8848/api/v1/auth/register?rememberMe=true \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123456"
  }'
```

**响应：**

```json
{
  "username": "testuser",
  "message": "Registration successful",
  "rememberMe": true
}
```

**状态码：**

- `200 OK` - 注册成功
- `400 Bad Request` - 参数错误或用户已存在

**Session：**

- 自动创建登录 Session
- `rememberMe=true`: Session 有效期 30 天
- `rememberMe=false`: Session 有效期 30 分钟

---

### 3. 用户登录

#### `POST /api/v1/auth/login`

用户登录

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | ✅ | 用户名 |
| password | string | ✅ | 密码 |
| rememberMe | boolean | ❌ | 记住登录（默认 false） |

**请求示例：**

```bash
curl -X POST http://localhost:8848/api/v1/auth/login?rememberMe=true \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123456"
  }' \
  -c cookies.txt
```

**响应：**

```json
{
  "username": "testuser",
  "message": "Login successful",
  "rememberMe": true
}
```

**状态码：**

- `200 OK` - 登录成功
- `401 Unauthorized` - 用户名或密码错误

**Cookie：**

- 返回 `JSESSIONID` Cookie（HttpOnly）
- 后续请求需携带此 Cookie

---

### 4. 用户登出

#### `POST /api/v1/auth/logout`

用户登出

**请求示例：**

```bash
curl -X POST http://localhost:8848/api/v1/auth/logout \
  -b cookies.txt
```

**响应：**

```json
{
  "message": "Logout successful"
}
```

**状态码：**

- `200 OK` - 登出成功
- `400 Bad Request` - 登出失败

---

### 5. 获取用户信息

#### `GET /api/v1/user/info`

获取当前登录用户的详细信息

**认证：** 🔒 需要登录

**请求示例：**

```bash
curl http://localhost:8848/api/v1/user/info \
  -b cookies.txt
```

**响应：**

```json
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "enabled": true,
  "locked": false,
  "createdAt": "2026-02-04T10:30:00"
}
```

**状态码：**

- `200 OK` - 成功获取用户信息
- `401 Unauthorized` - 未登录
- `404 Not Found` - 用户不存在

---

## 🚧 待实现接口（OAuth2标准）

### OAuth2 核心端点

#### `GET /oauth/authorize`

**授权端点** - 用户授权页面

**参数：**

- `response_type`: 固定为 `code`
- `client_id`: 客户端 ID
- `redirect_uri`: 回调地址
- `scope`: 权限范围（如 `read write`）
- `state`: 防 CSRF 攻击的随机字符串

**流程：**

1. 用户访问此端点
2. 如未登录，跳转登录页
3. 显示授权同意页面
4. 用户同意后，生成授权码
5. 重定向到 `redirect_uri?code=xxx&state=xxx`

---

#### `POST /oauth/token`

**Token 端点** - 换取访问令牌

**授权码模式参数：**

```json
{
  "grant_type": "authorization_code",
  "code": "授权码",
  "redirect_uri": "回调地址",
  "client_id": "客户端ID",
  "client_secret": "客户端密钥"
}
```

**刷新令牌参数：**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "刷新令牌",
  "client_id": "客户端ID",
  "client_secret": "客户端密钥"
}
```

**响应：**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "read write"
}
```

---

#### `POST /oauth/revoke`

**Token 撤销端点**

**参数：**

```json
{
  "token": "要撤销的 Token",
  "token_type_hint": "access_token 或 refresh_token"
}
```

---

#### `POST /oauth/introspect`

**Token 自省端点** - 验证 Token 有效性

**参数：**

```json
{
  "token": "要验证的 Token"
}
```

**响应：**

```json
{
  "active": true,
  "client_id": "client123",
  "username": "testuser",
  "scope": "read write",
  "exp": 1735996800
}
```

---

#### `GET /oauth/userinfo`

**用户信息端点** - OAuth2 标准用户信息接口

**认证：** Bearer Token

**请求示例：**

```bash
curl http://localhost:8848/oauth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**响应：**

```json
{
  "sub": "1",
  "name": "testuser",
  "email": "test@example.com",
  "email_verified": true
}
```

---

### 客户端管理

#### `POST /api/v1/clients`

**注册客户端应用**

**参数：**

```json
{
  "clientName": "My Application",
  "redirectUris": ["https://myapp.com/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"]
}
```

**响应：**

```json
{
  "clientId": "client_abc123",
  "clientSecret": "secret_xyz789",
  "clientName": "My Application",
  "redirectUris": ["https://myapp.com/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"],
  "createdAt": "2026-02-04T10:30:00"
}
```

---

#### `GET /api/v1/clients/{clientId}`

**获取客户端信息**

#### `PUT /api/v1/clients/{clientId}`

**更新客户端信息**

#### `DELETE /api/v1/clients/{clientId}`

**删除客户端**

#### `GET /api/v1/clients`

**获取客户端列表**

---

### 授权管理

#### `GET /api/v1/user/authorizations`

**获取用户授权记录**

**响应：**

```json
[
  {
    "clientId": "client_abc123",
    "clientName": "My Application",
    "scopes": ["read", "write"],
    "authorizedAt": "2026-02-04T10:30:00"
  }
]
```

---

#### `DELETE /api/v1/user/authorizations/{clientId}`

**撤销对特定客户端的授权**

---

### OIDC 端点（OpenID Connect）

#### `GET /.well-known/openid-configuration`

**OIDC 发现端点**

**响应：**

```json
{
  "issuer": "http://localhost:8848",
  "authorization_endpoint": "http://localhost:8848/oauth/authorize",
  "token_endpoint": "http://localhost:8848/oauth/token",
  "userinfo_endpoint": "http://localhost:8848/oauth/userinfo",
  "jwks_uri": "http://localhost:8848/.well-known/jwks.json",
  "response_types_supported": ["code", "id_token", "token id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

---

#### `GET /.well-known/jwks.json`

**公钥发布端点**

---

### 管理后台

#### `GET /api/v1/admin/stats`

**系统统计数据**

#### `GET /api/v1/admin/audit-logs`

**审计日志查询**

#### `GET /api/v1/admin/users`

**用户管理**

---

## 🔐 认证机制说明

### 当前实现（Session-based）

**流程：**

1. 用户通过 `/api/v1/auth/login` 登录
2. 服务器创建 Session，返回 `JSESSIONID` Cookie
3. 客户端携带 Cookie 访问受保护接口
4. 服务器通过 `AuthenticationInterceptor` 验证 Session

**特点：**

- ✅ 简单易用
- ✅ 服务端控制（可随时撤销）
- ❌ 不支持跨域
- ❌ 不符合 OAuth2 标准

---

### 待实现（OAuth2 / JWT）

**流程：**

1. 客户端引导用户到 `/oauth/authorize`
2. 用户登录并授权
3. 服务器生成授权码，重定向回客户端
4. 客户端用授权码换取 Access Token
5. 客户端携带 `Authorization: Bearer <token>` 访问资源

**特点：**

- ✅ 符合 OAuth2 标准
- ✅ 支持跨域
- ✅ 无状态（JWT）
- ✅ 适合第三方应用集成

---

## 📊 接口类型分类

### 公开接口（无需认证）

- `GET /api/v1/health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`

### 必须认证接口

- `GET /api/v1/user/info`
- 所有 `/api/v1/user/**` 接口

### 可选认证接口（暂无）

配置位置：`SecurityConstants.OPTIONAL_AUTH_ENDPOINTS`

示例场景：

- 首页内容（登录用户看个性化，未登录看通用）
- 公开文章列表（登录用户可看点赞状态）

---

## 🚀 实现路线图

### Phase 1: OAuth2 基础（优先级最高）

- [ ] 客户端注册和管理
- [ ] 授权码模式
- [ ] Access Token / Refresh Token
- [ ] `/oauth/authorize` 和 `/oauth/token` 端点
- [ ] `/oauth/userinfo` 标准端点

### Phase 2: 安全增强

- [ ] State 参数（防 CSRF）
- [ ] PKCE 支持
- [ ] Rate Limiting
- [ ] Token 撤销和自省

### Phase 3: 管理功能

- [ ] 管理后台
- [ ] 审计日志
- [ ] 用户授权管理

### Phase 4: 高级功能

- [ ] OIDC 完整支持
- [ ] 多因素认证（MFA）
- [ ] 社交登录集成

---

## 📝 错误码说明

| 状态码 | 说明             |
| ------ | ---------------- |
| 200    | 请求成功         |
| 400    | 请求参数错误     |
| 401    | 未认证或认证失败 |
| 403    | 无权限访问       |
| 404    | 资源不存在       |
| 500    | 服务器内部错误   |

---

## 🔧 开发环境

- **服务地址：** http://localhost:8848
- **Session 超时：**
  - 默认：30 分钟
  - rememberMe=true：30 天
- **数据库：** MySQL 8.0.45
- **缓存：** Redis

---

## 📞 联系方式

如有问题或建议，请提交 Issue 或 Pull Request。
