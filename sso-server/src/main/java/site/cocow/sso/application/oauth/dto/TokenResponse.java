package site.cocow.sso.application.oauth.dto;

/**
 * Token响应
 */
public record TokenResponse(
        String accessToken,
        String tokenType,
        Integer expiresIn,
        String refreshToken,
        String scope
        ) {

    public TokenResponse(String accessToken, String refreshToken, String scope) {
        this(accessToken, "Bearer", 3600, refreshToken, scope);
    }
}
