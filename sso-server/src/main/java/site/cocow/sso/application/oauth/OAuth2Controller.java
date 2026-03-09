package site.cocow.sso.application.oauth;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;
import site.cocow.sso.application.oauth.dto.AuthorizeGrantRequest;
import site.cocow.sso.application.oauth.dto.IntrospectionResponse;
import site.cocow.sso.application.oauth.dto.JwksResponse;
import site.cocow.sso.application.oauth.dto.OidcDiscoveryResponse;
import site.cocow.sso.application.oauth.dto.TokenResponse;
import site.cocow.sso.domain.client.Client;
import site.cocow.sso.domain.oauth.AuthorizationCode;
import site.cocow.sso.domain.oauth.OAuthToken;
import site.cocow.sso.infrastructure.config.ApiConstants;
import site.cocow.sso.infrastructure.jwt.JwtTokenService;

/**
 * OAuth2 端点控制器
 */
@RestController
@RequestMapping(ApiConstants.OAUTH_BASE)
public class OAuth2Controller {

    private final OAuth2Service oauth2Service;
    private final JwtTokenService jwtTokenService;

    @Value("${jwt.issuer:http://localhost:8848}")
    private String issuer;

    @Value("${server.port:8848}")
    private String serverPort;

    public OAuth2Controller(OAuth2Service oauth2Service, JwtTokenService jwtTokenService) {
        this.oauth2Service = oauth2Service;
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * 授权端点 POST /api/v1/oauth/authorize
     *
     * 整个授权流程由 SSO 前端完成： 1. 客户端将浏览器重定向到 SSO 前端 /oauth/authorize?... 2. 前端捕获参数 →
     * 引导用户登录 → 展示授权同意页 3. 用户点击「允许」后，前端将参数以 JSON Body POST 到此接口 4.
     * 后端验证、生成授权码，将完整回调 URI 以 JSON 返回给前端 5. 前端执行 window.location.href
     * 跳转，浏览器永不直接访问后端授权端点
     */
    @PostMapping("/authorize")
    public ResponseEntity<Map<String, String>> grantAuthorization(
            @RequestBody AuthorizeGrantRequest request,
            HttpSession session
    ) {
        // 1. 检查用户是否已登录
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            throw new OAuth2Service.NotAuthenticatedException("User is not authenticated");
        }

        // 2. 验证 response_type
        if (!"code".equals(request.responseType())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "unsupported_response_type",
                            "error_description", "Only response_type=code is supported"));
        }

        // 3. 验证客户端
        Client client = oauth2Service.validateClientById(request.clientId());

        // 4. 验证 redirect_uri
        oauth2Service.validateRedirectUri(client, request.redirectUri());

        // 5. 生成授权码
        AuthorizationCode authCode = oauth2Service.generateAuthorizationCode(
                request.clientId(), userId, request.redirectUri(),
                request.scope(), request.state(),
                request.codeChallenge(), request.codeChallengeMethod()
        );

        // 6. 拼接回调 URI 并以 JSON 返回 — 由前端负责最终跳转
        String redirectUrl = request.redirectUri() + "?code=" + authCode.getCode();
        if (request.state() != null && !request.state().isBlank()) {
            redirectUrl += "&state=" + request.state();
        }

        return ResponseEntity.ok(Map.of("redirectUri", redirectUrl));
    }

    /**
     * Token 端点 - 授权码换取 Token POST /oauth/token
     */
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> token(
            @RequestParam("grant_type") @NonNull String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "client_id") @NonNull String clientId,
            @RequestParam(value = "client_secret") @NonNull String clientSecret,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken
    ) {
        OAuthToken token = switch (grantType) {
            case "authorization_code" ->
                oauth2Service.exchangeCodeForToken(code, clientId, clientSecret, redirectUri, codeVerifier);
            case "refresh_token" ->
                oauth2Service.refreshAccessToken(refreshToken, clientId, clientSecret);
            default ->
                throw new IllegalArgumentException("Unsupported grant_type: " + grantType);
        };

        TokenResponse response = new TokenResponse(
                token.getAccessToken(),
                token.getRefreshToken(),
                token.getScope() != null ? token.getScope() : ""
        );
        return ResponseEntity.ok(response);
    }

    /**
     * Token 撤销端点 POST /oauth/revoke
     */
    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(@RequestParam("token") @NonNull String token) {
        oauth2Service.revokeToken(token);
        return ResponseEntity.ok().build();
    }

    /**
     * Token 自省端点 POST /oauth/introspect
     */
    @PostMapping("/introspect")
    public ResponseEntity<IntrospectionResponse> introspect(@RequestParam("token") @NonNull String token) {
        OAuth2Service.TokenIntrospectionResult result = oauth2Service.introspectToken(token);

        IntrospectionResponse response = result.active()
                ? IntrospectionResponse.active(result.clientId(), result.userId(), result.scope(), result.expiresAt())
                : IntrospectionResponse.inactive();

        return ResponseEntity.ok(response);
    }

    /**
     * OIDC UserInfo 端点 GET /oauth/userinfo 返回标准 OIDC claims，根据 access token 的
     * scope 返回不同字段
     */
    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(
            @RequestHeader(value = "Authorization", required = false) String authorization
    ) {
        Map<String, Object> userInfo = oauth2Service.getUserInfoFromAccessToken(authorization);
        return ResponseEntity.ok(userInfo);
    }

    /**
     * OIDC 发现端点 GET /.well-known/openid-configuration 返回 OIDC 提供者的元数据信息
     */
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<OidcDiscoveryResponse> oidcDiscovery() {
        String baseUrl = issuer.startsWith("http") ? issuer : "http://localhost:" + serverPort;

        OidcDiscoveryResponse response = new OidcDiscoveryResponse(
                baseUrl,
                baseUrl + ApiConstants.OAUTH_BASE + "/authorize",
                baseUrl + ApiConstants.OAUTH_BASE + "/token",
                baseUrl + ApiConstants.OAUTH_BASE + "/userinfo",
                baseUrl + ApiConstants.OAUTH_BASE + "/.well-known/jwks.json",
                List.of("code", "id_token", "token id_token"),
                List.of("public"),
                List.of("RS256"),
                List.of("openid", "profile", "email"),
                List.of("authorization_code", "refresh_token"),
                List.of("S256", "plain")
        );

        return ResponseEntity.ok(response);
    }

    /**
     * JWKS 端点 GET /.well-known/jwks.json 返回用于验证 JWT 签名的公钥集
     */
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<JwksResponse> jwks() {
        Map<String, Object> jwk = jwtTokenService.getJwksKey();
        JwksResponse response = new JwksResponse(List.of(jwk));
        return ResponseEntity.ok(response);
    }

    /**
     * 处理用户未登录异常（前端负责跳转到登录页）
     */
    @ExceptionHandler(OAuth2Service.NotAuthenticatedException.class)
    public ResponseEntity<Map<String, String>> handleNotAuthenticated(OAuth2Service.NotAuthenticatedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "login_required", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理无效客户端异常
     */
    @ExceptionHandler(OAuth2Service.InvalidClientException.class)
    public ResponseEntity<Map<String, String>> handleInvalidClient(OAuth2Service.InvalidClientException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_client", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理无效授权码异常
     */
    @ExceptionHandler(OAuth2Service.InvalidAuthorizationCodeException.class)
    public ResponseEntity<Map<String, String>> handleInvalidAuthorizationCode(OAuth2Service.InvalidAuthorizationCodeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_grant", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理无效令牌异常
     */
    @ExceptionHandler(OAuth2Service.InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidToken(OAuth2Service.InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_token", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理无效重定向URI异常
     */
    @ExceptionHandler(OAuth2Service.InvalidRedirectUriException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRedirectUri(OAuth2Service.InvalidRedirectUriException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_request", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理PKCE验证异常
     */
    @ExceptionHandler(OAuth2Service.PKCEValidationException.class)
    public ResponseEntity<Map<String, String>> handlePKCEValidation(OAuth2Service.PKCEValidationException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_grant", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理JWT令牌异常
     */
    @ExceptionHandler(JwtTokenService.InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleJwtInvalidToken(JwtTokenService.InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_token", "error_description", ex.getMessage(), "code", ex.getCode()));
    }

    /**
     * 处理非法参数异常
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_request", "error_description", ex.getMessage()));
    }
}
