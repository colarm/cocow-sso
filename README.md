# SSO Server

统一身份认证中心（Single Sign-On / OAuth2 / OpenID Connect），基于 **Java 25 + Spring Boot** 构建，采用分层架构与领域驱动设计（DDD），为多个内部业务系统提供统一登录、授权与身份管理能力。

**服务地址**：https://sso.cocow.site

> ⚠️ 本项目为 **闭源内部系统**，代码、设计与配置均属于公司内部资产，未经授权禁止传播、复制或用于任何外部用途。

---

## 🌟 项目目标

- 提供统一、可靠的身份认证与授权能力
- 作为公司级 **认证与安全中枢**
- 支持多系统、多客户端接入
- 长期可维护、可扩展、可审计

---

## 🧱 技术栈

| 分类       | 选型                    |
| ---------- | ----------------------- |
| JDK        | **JDK 25**              |
| 构建工具   | **Maven**               |
| Web 框架   | Spring Boot             |
| 安全框架   | Spring Security         |
| Token      | JWT                     |
| Token 签名 | **Ed25519 (EdDSA)**     |
| 密码哈希   | **Argon2id**            |
| 数据库     | MySQL 8.x               |
| 缓存       | Redis                   |
| 数据迁移   | Flyway / Liquibase      |
| 容器化     | Docker / Docker Compose |
| 网关       | Nginx                   |
| TLS        | TLS 1.3                 |

---

## 📦 功能模块

| 模块          | 说明                            |
| ------------- | ------------------------------- |
| Auth          | 登录、登出、会话管理            |
| OAuth2 / OIDC | 授权码、Token、UserInfo         |
| Client        | OAuth2 客户端管理               |
| User          | 用户模型与用户服务              |
| Session       | 登录态 / 会话管理               |
| Token         | Access / Refresh Token 生命周期 |
| Admin         | 后台管理（可选）                |
| Security      | 加密、签名、防护策略            |

---

## 📂 项目结构

```text
sso-server/
├── src/
│   ├── main/
│   │   ├── java/site/cocow/sso/
│   │   │   ├── application/      # 应用层（Controller / Service / DTO）
│   │   │   ├── domain/           # 核心领域模型（最稳定）
│   │   │   ├── infrastructure/   # 技术实现（DB / Redis / Security / Web）
│   │   │   └── config/           # Spring 配置
│   │   └── resources/
│   │       ├── application.yaml
│   │       └── db/migration/
│   └── test/
│       └── java/
├── scripts/                       # 初始化 & 运维脚本
├── docs/                          # 架构与安全文档
├── docker/                        # 容器部署
└── README.md
```

---

## 🔐 安全与密码学设计

### 1) Token 签名（JWT）

- **算法**：Ed25519（EdDSA）
- **特点**：
  - 高安全性
  - 确定性签名（避免随机数问题）
  - 签名短、验证快
- JWT Header 示例：

```json
{
  "alg": "EdDSA",
  "kid": "ed25519-2026-01"
}
```

- 支持 `kid`，允许多密钥并存与平滑轮换
- 公钥通过 JWKS Endpoint 对外暴露

### 2) 密码存储（Password Hashing）

**使用算法**

- Argon2id（推荐）
- BCrypt（兼容或历史迁移）

**密码加密流程**

1. 明文密码
2. 随机唯一 Salt（每个用户）
3. Argon2id（高内存参数）
4. 存储：hash + salt + 参数

**登录校验流程**

1. 用户输入密码
2. 读取 salt 与参数
3. Argon2id 重新计算
4. 常量时间比较
5. 认证通过 / 失败

> ❌ 严禁使用 MD5、SHA-1、SHA-256 直接哈希密码

### 3) Token 策略

**Access Token**

- JWT
- Ed25519 签名
- 短生命周期（5–15 分钟）
- 不包含敏感信息

**Refresh Token**

- 高熵随机值
- 哈希存储
- 单次使用 + 自动轮换
- 可绑定用户 / 客户端 / 设备

### 4) 传输与接口安全

- 强制 TLS 1.3
- 禁止明文 HTTP
- HSTS 启用
- Cookie 设置：
  - HttpOnly
  - Secure
  - SameSite=Strict

### 5) 密钥管理与轮换

| 类型                 | 轮换周期 |
| -------------------- | -------- |
| Ed25519 私钥         | 3–6 个月 |
| Refresh Token Secret | 1–3 个月 |

- 私钥不入库、不提交仓库
- 通过环境变量 / KMS 注入
- 旧密钥在过渡期内可验证

---

## ⚙️ 构建与运行

### 环境要求

- JDK 25
- Maven 3.9+
- MySQL 8.x
- Redis 6.x+

### 本地构建

```bash
mvn clean package
```

### 运行

```bash
java -jar target/sso-server-<version>.jar
```

### Docker（可选）

```bash
docker-compose up -d
```

---

## 🧪 测试

```bash
mvn test
```

- 测试按模块划分：auth / oauth / token
- 关键认证流程必须覆盖测试

---

## 📄 文档

- API 文档：docs/api.md
- 认证流程时序图：docs/sequence.md
- 威胁建模与安全设计：docs/threat-model.md

---

## 🛠 开发规范

- 严格遵循分层架构（Application / Domain / Infrastructure）
- 应用层不包含核心业务规则
- 领域层不依赖外部技术细节
- 所有安全相关变更必须代码审查
- 禁止在代码中硬编码任何密钥或密码

---

## 📌 项目声明

本项目为公司内部闭源系统。未经授权：

- ❌ 禁止复制、分发、泄露代码
- ❌ 禁止公开接口细节与安全实现
- ❌ 禁止用于任何外部或商业用途

如需接入或变更，请联系项目维护团队。
