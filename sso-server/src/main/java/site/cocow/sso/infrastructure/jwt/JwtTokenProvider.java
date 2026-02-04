package site.cocow.sso.infrastructure.jwt;

import java.util.Date;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * JWT Token 工具类（简化版本，后续实现 Ed25519 签名）
 */
@Component
public class JwtTokenProvider {

    private final JwtProperties jwtProperties;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    /**
     * 生成 Access Token（临时实现，后续使用 Ed25519 签名）
     */
    public String generateAccessToken(String username, Long userId) {
        // TODO: 实现真正的 JWT Ed25519 签名
        // 临时返回简单的 token
        return "temp_token_" + UUID.randomUUID().toString() + "_" + username;
    }

    /**
     * 获取 Token 有效期（秒）
     */
    public Long getAccessTokenValidity() {
        return jwtProperties.getAccessTokenValidity();
    }

    /**
     * 解析 Token（临时实现）
     */
    public JWTClaimsSet parseToken(String token) throws Exception {
        // TODO: 实现真正的 JWT 解析
        // 临时实现：构造一个简单的 ClaimsSet
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getAccessTokenValidity() * 1000);

        return new JWTClaimsSet.Builder()
                .expirationTime(expiration)
                .build();
    }
}
