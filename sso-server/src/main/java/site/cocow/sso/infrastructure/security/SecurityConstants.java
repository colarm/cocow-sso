package site.cocow.sso.infrastructure.security;

import org.springframework.lang.NonNull;

import site.cocow.sso.infrastructure.config.ApiConstants;

/**
 * 安全配置常量
 */
public class SecurityConstants {

    /**
     * Request 属性键
     */
    public static final String REQUEST_USER_ID_KEY = "userId";
    public static final String REQUEST_USERNAME_KEY = "username";

    /**
     * Session 属性键
     */
    public static final String SESSION_USER_ID_KEY = "userId";
    public static final String SESSION_USERNAME_KEY = "username";

    /**
     * 公开接口路径（无需认证） 添加新的公开接口时，只需在此数组中添加路径模式
     */
    @NonNull
    public static final String[] PUBLIC_ENDPOINTS = {
        // 认证相关接口
        ApiConstants.AUTH_BASE + "/**",
        // 健康检查
        ApiConstants.HEALTH,
        // OAuth2 公开端点
        ApiConstants.OAUTH_BASE + "/token",
        ApiConstants.OAUTH_BASE + "/revoke",
        ApiConstants.OAUTH_BASE + "/introspect",};

    /**
     * 需要认证的接口路径 添加新的受保护接口时，只需在此数组中添加路径模式
     */
    @NonNull
    public static final String[] PROTECTED_ENDPOINTS = {
        // 用户相关接口
        ApiConstants.USER_BASE + "/**",
        // OAuth2 需要用户登录的端点
        ApiConstants.OAUTH_BASE + "/authorize",
        ApiConstants.OAUTH_BASE + "/userinfo",};

    /**
     * 可选认证的接口路径（尝试获取用户信息，但不强制要求登录） 适用于：首页、公开内容等场景
     */
    @NonNull
    public static final String[] OPTIONAL_AUTH_ENDPOINTS = { // 可选认证的接口
    };

    private SecurityConstants() {
        // 工具类，禁止实例化
    }
}
