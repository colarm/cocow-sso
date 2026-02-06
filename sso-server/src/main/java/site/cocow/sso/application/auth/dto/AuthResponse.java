package site.cocow.sso.application.auth.dto;

/**
 * 认证响应
 */
public record AuthResponse(
        String accessToken,
        String tokenType,
        Long expiresIn,
        String username
        ) {

    public AuthResponse(String accessToken, Long expiresIn, String username) {
        this(accessToken, "Bearer", expiresIn, username);
    }
}
