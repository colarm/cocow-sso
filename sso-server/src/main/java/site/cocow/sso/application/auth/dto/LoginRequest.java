package site.cocow.sso.application.auth.dto;

/**
 * 用户登录请求
 */
public record LoginRequest(
        String username,
        String password
        ) {

}
