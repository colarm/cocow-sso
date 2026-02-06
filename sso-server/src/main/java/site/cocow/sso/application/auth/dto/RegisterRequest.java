package site.cocow.sso.application.auth.dto;

/**
 * 用户注册请求
 */
public record RegisterRequest(
        String username,
        String email,
        String password
        ) {

}
