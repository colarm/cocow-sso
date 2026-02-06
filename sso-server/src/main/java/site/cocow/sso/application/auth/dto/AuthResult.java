package site.cocow.sso.application.auth.dto;

/**
 * 认证结果（内部使用）
 */
public record AuthResult(
        Long userId,
        String username,
        String role
        ) {

}
