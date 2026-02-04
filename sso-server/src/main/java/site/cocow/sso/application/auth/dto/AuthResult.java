package site.cocow.sso.application.auth.dto;

/**
 * 认证结果（内部使用）
 */
public class AuthResult {

    private final String username;

    public AuthResult(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
