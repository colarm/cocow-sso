package site.cocow.sso.application.oauth;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import site.cocow.sso.application.user.UserService;
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
    private final UserService userService;

    public OAuth2Controller(
            OAuth2Service oauth2Service,
            JwtTokenService jwtTokenService,
            UserService userService
    ) {
        this.oauth2Service = oauth2Service;
        this.jwtTokenService = jwtTokenService;
        this.userService = userService;
    }

    /**
     * Token 端点 - 授权码换取 Token POST /oauth/token
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam("grant_type") @NonNull String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "client_id", required = false) @NonNull String clientId,
            @RequestParam(value = "client_secret", required = false) @NonNull String clientSecret,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken
    ) {

        return switch (grantType) {
            case "authorization_code" -> {
                if (code == null || redirectUri == null) {
                    throw new IllegalArgumentException("code and redirect_uri are required for authorization_code grant");
                }
                OAuthToken token = oauth2Service.exchangeCodeForToken(
                        code, clientId, clientSecret, redirectUri, codeVerifier);
                yield ResponseEntity.ok(buildTokenResponse(token));
            }
            case "refresh_token" -> {
                if (refreshToken == null) {
                    throw new IllegalArgumentException("refresh_token is required for refresh_token grant");
                }
                OAuthToken token = oauth2Service.refreshAccessToken(refreshToken, clientId, clientSecret);
                yield ResponseEntity.ok(buildTokenResponse(token));
            }
            default ->
                throw new IllegalArgumentException("Unsupported grant_type: " + grantType);
        };
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
    public ResponseEntity<Map<String, Object>> introspect(@RequestParam("token") @NonNull String token) {
        OAuth2Service.TokenIntrospectionResult result = oauth2Service.introspectToken(token);

        return ResponseEntity.ok(Map.of(
                "active", result.active(),
                "client_id", result.clientId() != null ? result.clientId() : "",
                "sub", result.userId() != null ? result.userId() : "",
                "scope", result.scope() != null ? result.scope() : "",
                "exp", result.expiresAt() != null ? result.expiresAt().toString() : ""
        ));
    }

    /**
     * OIDC UserInfo 端点 GET /oauth/userinfo 返回标准 OIDC claims，根据 access token 的
     * scope 返回不同字段
     */
    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(
            @RequestHeader("Authorization") String authorization
    ) {
        // 验证 Bearer token
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid or missing Authorization header");
        }

        String accessToken = authorization.substring(7); // 去掉 "Bearer " 前缀

        // 验证 token 并解析
        Map<String, Object> claims = jwtTokenService.verifyAndParseToken(accessToken);
        String subClaim = (String) claims.get("sub");
        if (subClaim == null) {
            throw new IllegalArgumentException("Token missing 'sub' claim");
        }
        Long userId = Objects.requireNonNull(Long.valueOf(subClaim));
        String scope = (String) claims.get("scope");

        // 解析 scope
        Set<String> scopes = Objects.requireNonNull(
                scope != null ? Set.of(scope.split(" ")) : Set.of()
        );

        // 根据 scope 返回用户信息
        Map<String, Object> userInfo = userService.getUserInfoByClaims(userId, scopes);

        return ResponseEntity.ok(userInfo);
    }

    /**
     * 构建 Token 响应
     */
    private Map<String, Object> buildTokenResponse(OAuthToken token) {
        return Map.of(
                "access_token", token.getAccessToken(),
                "token_type", token.getTokenType(),
                "expires_in", 3600, // 1 小时
                "refresh_token", token.getRefreshToken(),
                "scope", token.getScope() != null ? token.getScope() : ""
        );
    }

    /**
     * 统一异常处理
     */
    @ExceptionHandler({RuntimeException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, String>> handleOAuthException(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", ex.getMessage()));
    }
}
