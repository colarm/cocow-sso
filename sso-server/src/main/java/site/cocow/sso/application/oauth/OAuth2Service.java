package site.cocow.sso.application.oauth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import site.cocow.sso.domain.oauth.AuthorizationCode;
import site.cocow.sso.domain.oauth.AuthorizationCodeRepository;
import site.cocow.sso.domain.oauth.Client;
import site.cocow.sso.domain.oauth.ClientRepository;
import site.cocow.sso.domain.oauth.OAuthToken;
import site.cocow.sso.domain.oauth.OAuthTokenRepository;
import site.cocow.sso.infrastructure.jwt.JwtTokenService;

/**
 * OAuth2 核心服务
 */
@Service
@Transactional
public class OAuth2Service {

    private final ClientRepository clientRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final OAuthTokenRepository tokenRepository;
    private final JwtTokenService jwtTokenService;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Argon2 argon2 = Argon2Factory.create();

    public OAuth2Service(
            ClientRepository clientRepository,
            AuthorizationCodeRepository authorizationCodeRepository,
            OAuthTokenRepository tokenRepository,
            JwtTokenService jwtTokenService) {
        this.clientRepository = clientRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.tokenRepository = tokenRepository;
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * 验证客户端凭证
     */
    public Client validateClient(String clientId, String clientSecret) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("Invalid client_id"));

        if (!client.getEnabled()) {
            throw new RuntimeException("Client is disabled");
        }

        // 验证 clientSecret（使用 Argon2 哈希验证）
        if (!argon2.verify(client.getClientSecret(), clientSecret.toCharArray())) {
            throw new RuntimeException("Invalid client_secret");
        }

        return client;
    }

    /**
     * 验证 Redirect URI
     */
    public void validateRedirectUri(Client client, String redirectUri) {
        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new RuntimeException("Invalid redirect_uri");
        }
    }

    /**
     * 生成授权码
     */
    public AuthorizationCode generateAuthorizationCode(
            String clientId,
            Long userId,
            String redirectUri,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod) {

        AuthorizationCode authCode = new AuthorizationCode();
        authCode.setCode(generateRandomCode());
        authCode.setClientId(clientId);
        authCode.setUserId(userId);
        authCode.setRedirectUri(redirectUri);
        authCode.setScope(scope);
        authCode.setState(state);
        authCode.setCodeChallenge(codeChallenge);
        authCode.setCodeChallengeMethod(codeChallengeMethod);
        authCode.setExpiresAt(LocalDateTime.now().plusMinutes(10)); // 授权码 10 分钟有效
        authCode.setUsed(false);

        return authorizationCodeRepository.save(authCode);
    }

    /**
     * 验证授权码并生成 Token
     */
    public OAuthToken exchangeCodeForToken(
            String code,
            String clientId,
            String clientSecret,
            String redirectUri,
            String codeVerifier) {

        // 1. 验证客户端凭证
        validateClient(clientId, clientSecret);

        // 2. 查找授权码
        AuthorizationCode authCode = authorizationCodeRepository.findByCode(code)
                .orElseThrow(() -> new RuntimeException("Invalid authorization code"));

        // 3. 验证授权码是否过期
        if (authCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Authorization code has expired");
        }

        // 4. 验证授权码是否已使用
        if (authCode.getUsed()) {
            throw new RuntimeException("Authorization code has already been used");
        }

        // 5. 验证 clientId 和 redirectUri
        if (!authCode.getClientId().equals(clientId)) {
            throw new RuntimeException("Client ID mismatch");
        }
        if (!authCode.getRedirectUri().equals(redirectUri)) {
            throw new RuntimeException("Redirect URI mismatch");
        }

        // 6. 验证 PKCE（根据客户端类型强制或可选）
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("Client not found"));

        if (client.getClientType() == Client.ClientType.PUBLIC) {
            // 公开客户端必须使用 PKCE
            if (authCode.getCodeChallenge() == null) {
                throw new RuntimeException("PKCE is required for public clients");
            }
            validatePKCE(authCode.getCodeChallenge(), authCode.getCodeChallengeMethod(), codeVerifier);
        } else {
            // 机密客户端可选使用 PKCE
            if (authCode.getCodeChallenge() != null) {
                validatePKCE(authCode.getCodeChallenge(), authCode.getCodeChallengeMethod(), codeVerifier);
            }
        }

        // 7. 标记授权码为已使用
        authCode.setUsed(true);
        authorizationCodeRepository.save(authCode);

        // 8. 生成 Token
        return generateToken(authCode.getUserId(), clientId, authCode.getScope());
    }

    /**
     * 使用 Refresh Token 刷新 Access Token
     */
    public OAuthToken refreshAccessToken(String refreshToken, String clientId, String clientSecret) {
        // 1. 验证客户端凭证
        validateClient(clientId, clientSecret);

        // 2. 查找 Refresh Token
        OAuthToken oldToken = tokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 3. 验证 Refresh Token 是否过期
        if (oldToken.getRefreshTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token has expired");
        }

        // 4. 验证 Refresh Token 是否被撤销
        if (oldToken.getRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }

        // 5. 验证 clientId
        if (!oldToken.getClientId().equals(clientId)) {
            throw new RuntimeException("Client ID mismatch");
        }

        // 6. 撤销旧 Token
        oldToken.setRevoked(true);
        tokenRepository.save(oldToken);

        // 7. 生成新 Token
        return generateToken(oldToken.getUserId(), clientId, oldToken.getScope());
    }

    /**
     * 撤销 Token
     */
    public void revokeToken(String token) {
        // 尝试按 access_token 查找
        tokenRepository.findByAccessToken(token).ifPresent(oauthToken -> {
            oauthToken.setRevoked(true);
            tokenRepository.save(oauthToken);
        });

        // 尝试按 refresh_token 查找
        tokenRepository.findByRefreshToken(token).ifPresent(oauthToken -> {
            oauthToken.setRevoked(true);
            tokenRepository.save(oauthToken);
        });
    }

    /**
     * Token 自省（验证 Token 有效性）
     */
    public TokenIntrospectionResult introspectToken(String token) {
        OAuthToken oauthToken = tokenRepository.findByAccessToken(token).orElse(null);

        if (oauthToken == null) {
            return new TokenIntrospectionResult(false, null, null, null, null);
        }

        boolean active = !oauthToken.getRevoked()
                && oauthToken.getAccessTokenExpiresAt().isAfter(LocalDateTime.now());

        return new TokenIntrospectionResult(
                active,
                oauthToken.getClientId(),
                String.valueOf(oauthToken.getUserId()),
                oauthToken.getScope(),
                oauthToken.getAccessTokenExpiresAt()
        );
    }

    /**
     * 生成 Token（包括 Access Token 和 Refresh Token）
     */
    private OAuthToken generateToken(Long userId, String clientId, String scope) {
        // 生成 Access Token (JWT)
        String accessToken = jwtTokenService.generateAccessToken(userId, clientId, scope, 3600); // 1 小时

        // 生成 Refresh Token（随机字符串）
        String refreshToken = generateRandomToken();

        OAuthToken token = new OAuthToken();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setTokenType("Bearer");
        token.setClientId(clientId);
        token.setUserId(userId);
        token.setScope(scope);
        token.setAccessTokenExpiresAt(LocalDateTime.now().plusHours(1));
        token.setRefreshTokenExpiresAt(LocalDateTime.now().plusDays(30));
        token.setRevoked(false);

        return tokenRepository.save(token);
    }

    /**
     * 验证 PKCE
     */
    private void validatePKCE(String codeChallenge, String codeChallengeMethod, String codeVerifier) {
        if (codeVerifier == null) {
            throw new RuntimeException("code_verifier is required for PKCE");
        }

        String computedChallenge = switch (codeChallengeMethod) {
            case "S256" ->
                base64UrlEncode(sha256(codeVerifier));
            case "plain" ->
                codeVerifier;
            default ->
                throw new RuntimeException("Unsupported code_challenge_method");
        };

        if (!codeChallenge.equals(computedChallenge)) {
            throw new RuntimeException("code_verifier does not match code_challenge");
        }
    }

    /**
     * 生成随机授权码
     */
    private String generateRandomCode() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * 生成随机 Token
     */
    private String generateRandomToken() {
        return UUID.randomUUID().toString() + UUID.randomUUID().toString();
    }

    /**
     * SHA-256 哈希
     */
    private byte[] sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Base64 URL 编码
     */
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Token 自省结果
     */
    public record TokenIntrospectionResult(
            boolean active,
            String clientId,
            String userId,
            String scope,
            LocalDateTime expiresAt
            ) {

    }
}
