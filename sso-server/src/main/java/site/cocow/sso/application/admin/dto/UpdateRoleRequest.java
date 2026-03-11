package site.cocow.sso.application.admin.dto;

import site.cocow.sso.domain.user.User;

/**
 * 更新用户角色请求
 */
public record UpdateRoleRequest(User.UserRole role) {

}
