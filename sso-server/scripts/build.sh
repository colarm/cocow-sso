#!/bin/bash

# SSO Server 构建脚本

set -e

echo "开始构建 SSO Server..."

# 检查 JDK
if ! command -v java &> /dev/null; then
    echo "错误: 未找到 Java 25，请先安装 JDK 25"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | cut -d'.' -f1)
if [ "$JAVA_VERSION" != "25" ]; then
    echo "警告: 当前 Java 版本为 $JAVA_VERSION，推荐使用 Java 25"
fi

# Maven 构建
echo "执行 Maven 构建..."
mvn clean package -DskipTests

echo "构建完成！JAR 文件位于 target/ 目录"
