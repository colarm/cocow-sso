# API 文档

## 认证接口

### 健康检查

```http
GET /api/auth/health
```

**响应**

```text
SSO Server is running
```

### 用户登录

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}
```

**响应**

```json
{
  "accessToken": "string",
  "refreshToken": "string",
  "expiresIn": 900
}
```

### 用户注册

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**响应**

```json
{
  "id": 1,
  "username": "string",
  "email": "string"
}
```

### 退出登录

```http
POST /api/auth/logout
Authorization: Bearer {accessToken}
```

**响应**

```json
{
  "message": "Logged out successfully"
}
```

## OAuth2 / OIDC 接口

### 授权端点

```http
GET /oauth2/authorize?client_id=xxx&redirect_uri=xxx&response_type=code&scope=openid
```

### Token 端点

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=xxx&redirect_uri=xxx&client_id=xxx&client_secret=xxx
```

### UserInfo 端点

```http
GET /oauth2/userinfo
Authorization: Bearer {accessToken}
```

### JWKS 端点

```http
GET /.well-known/jwks.json
```

**响应**

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "ed25519-2026-01",
      "x": "base64url-encoded-public-key"
    }
  ]
}
```

---

## 错误响应格式

```json
{
  "error": "error_code",
  "message": "Error description",
  "timestamp": "2026-02-04T12:00:00Z"
}
```
