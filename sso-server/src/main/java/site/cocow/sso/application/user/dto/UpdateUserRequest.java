package site.cocow.sso.application.user.dto;

/**
 * 更新用户信息请求
 */
public record UpdateUserRequest(
        String username,
        String email
        ) {

}
