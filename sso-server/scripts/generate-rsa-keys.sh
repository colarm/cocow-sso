#!/bin/bash

# 生成 RSA 密钥对用于 JWT 签名
# 使用方法: ./scripts/generate-rsa-keys.sh

set -e

KEYS_DIR="./keys"
PRIVATE_KEY_FILE="$KEYS_DIR/jwt-private-key.pem"
PUBLIC_KEY_FILE="$KEYS_DIR/jwt-public-key.pem"
ENV_FILE=".env.jwt"

# 创建密钥目录
mkdir -p "$KEYS_DIR"

echo "🔐 Generating RSA 2048-bit key pair..."

# 生成私钥 (PKCS#8 格式)
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY_FILE" -pkeyopt rsa_keygen_bits:2048

# 从私钥导出公钥
openssl rsa -pubout -in "$PRIVATE_KEY_FILE" -out "$PUBLIC_KEY_FILE"

echo "✅ Keys generated successfully!"
echo ""
echo "📁 Files created:"
echo "  - Private key: $PRIVATE_KEY_FILE"
echo "  - Public key:  $PUBLIC_KEY_FILE"
echo ""

# 生成环境变量文件
echo "📝 Generating environment variables file..."

PRIVATE_KEY_CONTENT=$(cat "$PRIVATE_KEY_FILE" | tr -d '\n')
PUBLIC_KEY_CONTENT=$(cat "$PUBLIC_KEY_FILE" | tr -d '\n')

cat > "$ENV_FILE" << EOF
# JWT RSA Keys (generated $(date))
# Copy these to your .env file or set as environment variables

JWT_PRIVATE_KEY=$PRIVATE_KEY_CONTENT
JWT_PUBLIC_KEY=$PUBLIC_KEY_CONTENT
JWT_KID=rsa-key-$(date +%Y%m%d)
JWT_ISSUER=https://sso.cocow.site

# For Docker Compose, use these in your .env file
# For Kubernetes, create a secret:
# kubectl create secret generic jwt-keys \\
#   --from-literal=private-key="\$JWT_PRIVATE_KEY" \\
#   --from-literal=public-key="\$JWT_PUBLIC_KEY"
EOF

echo "✅ Environment file created: $ENV_FILE"
echo ""
echo "🚀 Usage:"
echo "  1. Copy the keys to your .env file:"
echo "     cat $ENV_FILE >> .env"
echo ""
echo "  2. Or export as environment variables:"
echo "     export \$(cat $ENV_FILE | grep -v '^#' | xargs)"
echo ""
echo "  3. For Docker Compose, add to docker-compose.yaml:"
echo "     environment:"
echo "       - JWT_PRIVATE_KEY=\${JWT_PRIVATE_KEY}"
echo "       - JWT_PUBLIC_KEY=\${JWT_PUBLIC_KEY}"
echo ""
echo "⚠️  IMPORTANT: Keep the private key secret! Add $KEYS_DIR/ to .gitignore"
echo ""

# 添加到 .gitignore（如果不存在）
if [ -f ".gitignore" ]; then
    if ! grep -q "^keys/" .gitignore; then
        echo "keys/" >> .gitignore
        echo "✅ Added keys/ to .gitignore"
    fi
    if ! grep -q "^.env.jwt" .gitignore; then
        echo ".env.jwt" >> .gitignore
        echo "✅ Added .env.jwt to .gitignore"
    fi
fi

echo "✨ Done! Your JWT keys are ready to use."
