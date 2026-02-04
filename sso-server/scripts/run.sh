#!/bin/bash

# SSO Server 启动脚本

set -e

JAR_FILE="target/sso-server-0.0.1-SNAPSHOT.jar"

if [ ! -f "$JAR_FILE" ]; then
    echo "错误: 未找到 JAR 文件，请先运行 build.sh 构建项目"
    exit 1
fi

echo "启动 SSO Server..."

# 加载环境变量（如果存在 .env 文件）
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

# 启动应用
java -jar "$JAR_FILE"
