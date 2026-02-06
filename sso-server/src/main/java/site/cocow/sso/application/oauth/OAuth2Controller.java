package site.cocow.sso.application.oauth;

import java.util.Map;

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

import site.cocow.sso.application.oauth.dto.IntrospectionResponse;
import site.cocow.sso.application.oauth.dto.TokenResponse;
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

    public OAuth2Controller(OAuth2Service oauth2Service, JwtTokenService jwtTokenService) {
        this.oauth2Service = oauth2Service;
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
     * 处理无效客户端异常
     */
    @ExceptionHandler(OAuth2Service.InvalidClientException.class)
    public ResponseEntity<Map<String, String>> handleInvalidClient(OAuth2Service.InvalidClientException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_client", "error_description", ex.getMessage()));
    }

    /**
     * 处理无效授权码异常
     */
    @ExceptionHandler(OAuth2Service.InvalidAuthorizationCodeException.class)
    public ResponseEntity<Map<String, String>> handleInvalidAuthorizationCode(OAuth2Service.InvalidAuthorizationCodeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_grant", "error_description", ex.getMessage()));
    }

    /**
     * 处理无效令牌异常
     */
    @ExceptionHandler(OAuth2Service.InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidToken(OAuth2Service.InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_token", "error_description", ex.getMessage()));
    }

    /**
     * 处理无效重定向URI异常
     */
    @ExceptionHandler(OAuth2Service.InvalidRedirectUriException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRedirectUri(OAuth2Service.InvalidRedirectUriException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_request", "error_description", ex.getMessage()));
    }

    /**
     * 处理PKCE验证异常
     */
    @ExceptionHandler(OAuth2Service.PKCEValidationException.class)
    public ResponseEntity<Map<String, String>> handlePKCEValidation(OAuth2Service.PKCEValidationException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "invalid_grant", "error_description", ex.getMessage()));
    }

    /**
     * 处理JWT令牌异常
     */
    @ExceptionHandler(JwtTokenService.InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleJwtInvalidToken(JwtTokenService.InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_token", "error_description", ex.getMessage()));
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
