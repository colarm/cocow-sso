# SSO Server - 快速开始

## 项目结构

```
sso-server/
├── src/
│   ├── main/
│   │   ├── java/site/cocow/sso/
│   │   │   ├── SsoServerApplication.java       # 主应用类
│   │   │   ├── application/                    # 应用层
│   │   │   │   └── auth/
│   │   │   │       ├── AuthController.java     # 认证控制器
│   │   │   │       └── AuthService.java        # 认证服务
│   │   │   ├── domain/                         # 领域层
│   │   │   │   └── user/
│   │   │   │       ├── User.java               # 用户实体
│   │   │   │       └── UserRepository.java     # 用户仓储
│   │   │   ├── infrastructure/                 # 基础设施层
│   │   │   │   ├── security/
│   │   │   │   │   └── SecurityConfig.java     # 安全配置
│   │   │   │   └── jwt/
│   │   │   │       └── JwtProperties.java      # JWT 配置
│   │   │   └── config/
│   │   │       └── AppConfig.java              # 应用配置
│   │   └── resources/
│   │       ├── application.yaml                # 配置文件
│   │       └── db/migration/
│   │           └── V1__init_schema.sql         # 数据库迁移
│   └── test/
├── docker/
│   └── Dockerfile                              # Docker 镜像
├── docs/
│   ├── api.md                                  # API 文档
│   ├── sequence.md                             # 时序图
│   └── threat-model.md                         # 威胁模型
├── scripts/
│   ├── build.sh                                # 构建脚本
│   └── run.sh                                  # 运行脚本
├── .env.example                                # 环境变量示例
├── .gitignore
├── docker-compose.yml                          # Docker Compose
└── pom.xml                                     # Maven 配置
```

## 快速启动

### 1. 环境准备

- JDK 25
- Maven 3.9+
- MySQL 8.x
- Redis 6.x+

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入实际配置
```

### 3. 启动依赖服务

```bash
# 使用 Docker Compose 启动 MySQL 和 Redis
docker-compose up -d mysql redis
```

### 4. 构建项目

```bash
./scripts/build.sh
```

### 5. 运行应用

```bash
./scripts/run.sh
```

应用将在 http://localhost:8080 启动

### 6. 测试健康检查

```bash
curl http://localhost:8080/api/auth/health
```

## 使用 Docker 运行完整服务

```bash
docker-compose up -d
```

## 下一步

- 阅读 [API 文档](docs/api.md)
- 查看 [认证流程](docs/sequence.md)
- 了解 [安全设计](docs/threat-model.md)

---

**注意**：这是一个基础框架，需要继续完善：

- 实现完整的认证逻辑（登录、注册、登出）
- 实现 JWT 生成和验证
- 实现 Argon2 密码哈希
- 实现 OAuth2 / OIDC 协议
- 添加单元测试和集成测试
- 配置生产环境 TLS
