package site.cocow.sso.infrastructure.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

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

/**
 * JWT Token 服务 使用 RS256 算法生成和验证 JWT
 */
@Service
public class JwtTokenService {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private JWSSigner signer;
    private JWSVerifier verifier;

    @PostConstruct
    public void init() throws Exception {
        // 生成 RSA 密钥对（生产环境应从配置文件或密钥管理系统加载）
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.signer = new RSASSASigner(privateKey);
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
                    .issuer("http://localhost:8848") // TODO: 从配置读取
                    .audience(clientId)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .claim("scope", scope)
                    .claim("client_id", clientId)
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(UUID.randomUUID().toString()).build(),
                    claimsSet
            );

            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate access token", e);
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
                throw new RuntimeException("Invalid token signature");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // 验证过期时间
            if (claimsSet.getExpirationTime().before(new Date())) {
                throw new RuntimeException("Token has expired");
            }

            return claimsSet.getClaims();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    /**
     * 检查 Token 是否有效（未过期）
     */
    public boolean isTokenValid(String token) {
        try {
            verifyAndParseToken(token);
            return true;
        } catch (Exception e) {
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
}
