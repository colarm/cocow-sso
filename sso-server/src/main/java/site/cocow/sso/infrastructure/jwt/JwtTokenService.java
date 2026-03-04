package site.cocow.sso.infrastructure.jwt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;
import site.cocow.sso.infrastructure.exception.BusinessException;

/**
 * JWT Token 服务 使用 RS256 算法生成和验证 JWT
 */
@Service
public class JwtTokenService {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);

    @Value("${jwt.private-key:}")
    private String privateKeyPem;

    @Value("${jwt.public-key:}")
    private String publicKeyPem;

    @Value("${jwt.kid:rsa-key-1}")
    private String keyId;

    @Value("${jwt.issuer:http://localhost:8848}")
    private String issuer;

    @Value("${spring.profiles.active:local}")
    private String activeProfile;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private JWSSigner signer;
    private JWSVerifier verifier;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 检查是否配置了密钥
        boolean keysConfigured = privateKeyPem != null && !privateKeyPem.isBlank()
                && publicKeyPem != null && !publicKeyPem.isBlank();

        if (!keysConfigured) {
            // 开发环境自动生成临时密钥
            if ("local".equals(activeProfile) || "dev".equals(activeProfile)) {
                log.warn("⚠️  JWT keys not configured. Generating temporary keys for development.");
                log.warn("⚠️  For production, please set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY environment variables.");
                log.warn("⚠️  Run './scripts/generate-rsa-keys.sh' to generate keys.");
                generateTemporaryKeys();
            } else {
                // 生产环境必须配置密钥
                throw new IllegalStateException(
                        "JWT keys not configured. Please set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY environment variables. "
                        + "Run './scripts/generate-rsa-keys.sh' to generate keys.");
            }
        } else {
            // 从环境变量加载密钥
            loadKeysFromConfig();
        }

        this.signer = new RSASSASigner(privateKey);
        this.verifier = new RSASSAVerifier(publicKey);

        log.info("✅ JWT Token Service initialized successfully (kid: {})", keyId);
    }

    /**
     * 从配置加载密钥
     */
    private void loadKeysFromConfig() throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // 从 PEM 格式加载私钥
            String privateKeyContent = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            // 从 PEM 格式加载公钥
            String publicKeyContent = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            log.info("✅ JWT keys loaded from environment variables");
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to load JWT keys from configuration. Please check the key format.", e);
        }
    }

    /**
     * 生成临时密钥（仅用于开发环境）
     */
    private void generateTemporaryKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.verifier = new RSASSAVerifier(publicKey);
    }

    /**
     * 生成 Access Token (JWT)
     *
     * @param userId 用户 ID
     * @param clientId 客户端 ID
     * @param scope 权限范围
     * @param expiresInSeconds 过期时间（秒）
     * @return JWT Token 字符串
     */
    public String generateAccessToken(Long userId, String clientId, String scope, long expiresInSeconds) {
        try {
            Instant now = Instant.now();
            Instant expiration = now.plusSeconds(expiresInSeconds);

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .subject(String.valueOf(userId))
                    .issuer(issuer)
                    .audience(clientId)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .claim("scope", scope)
                    .claim("client_id", clientId)
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                    claimsSet
            );

            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new TokenGenerationException("Failed to generate access token", e);
        }
    }

    /**
     * 验证并解析 Access Token
     *
     * @param token JWT Token 字符串
     * @return Token Claims（包含用户信息）
     */
    public Map<String, Object> verifyAndParseToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 验证签名
            if (!signedJWT.verify(verifier)) {
                throw new InvalidTokenException("Invalid token signature");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // 验证过期时间
            if (claimsSet.getExpirationTime().before(new Date())) {
                throw new InvalidTokenException("Token has expired");
            }

            return claimsSet.getClaims();
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage(), e);
        }
    }

    /**
     * 检查 Token 是否有效（未过期）
     */
    public boolean isTokenValid(String token) {
        try {
            verifyAndParseToken(token);
            return true;
        } catch (InvalidTokenException e) {
            return false;
        }
    }

    /**
     * 从 Token 中提取用户 ID
     */
    public Long getUserIdFromToken(String token) {
        Map<String, Object> claims = verifyAndParseToken(token);
        return Long.valueOf((String) claims.get("sub"));
    }

    /**
     * 从 Token 中提取客户端 ID
     */
    public String getClientIdFromToken(String token) {
        Map<String, Object> claims = verifyAndParseToken(token);
        return (String) claims.get("client_id");
    }

    /**
     * 从 Token 中提取 Scope
     */
    public String getScopeFromToken(String token) {
        Map<String, Object> claims = verifyAndParseToken(token);
        return (String) claims.get("scope");
    }

    /**
     * 获取公钥（用于 JWKS 端点）
     */
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 获取 JWKS (JSON Web Key Set) 格式的公钥
     */
    public Map<String, Object> getJwksKey() {
        return Map.of(
                "kty", "RSA",
                "use", "sig",
                "kid", keyId,
                "alg", "RS256",
                "n", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray()),
                "e", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray())
        );
    }

    /**
     * Token生成异常
     */
    public static class TokenGenerationException extends BusinessException {

        public TokenGenerationException(String message, Throwable cause) {
            super("jwt.token_generation", message, cause);
        }
    }

    /**
     * 无效Token异常
     */
    public static class InvalidTokenException extends BusinessException {

        public InvalidTokenException(String message) {
            super("jwt.invalid_token", message);
        }

        public InvalidTokenException(String message, Throwable cause) {
            super("jwt.invalid_token", message, cause);
        }
    }
}
