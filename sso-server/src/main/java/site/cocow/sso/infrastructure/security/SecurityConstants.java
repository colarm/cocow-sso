package site.cocow.sso.infrastructure.security;

import org.springframework.lang.NonNull;

/**
 * 安全配置常量
 */
public class SecurityConstants {

    /**
     * 公开接口路径（无需认证） 添加新的公开接口时，只需在此数组中添加路径模式
     */
    @NonNull
    public static final String[] PUBLIC_ENDPOINTS = {
        // 认证相关接口
        "/api/v1/auth/**",
        // 健康检查
        "/api/v1/health",};

    /**
     * 需要认证的接口路径 添加新的受保护接口时，只需在此数组中添加路径模式
     */
    @NonNull
    public static final String[] PROTECTED_ENDPOINTS = {
        // 用户相关接口
        "/api/v1/user/**",
    };

    /**
     * 可选认证的接口路径（尝试获取用户信息，但不强制要求登录） 适用于：首页、公开内容等场景
     */
    @NonNull
    public static final String[] OPTIONAL_AUTH_ENDPOINTS = {
        // 可选认证的接口
    };

    private SecurityConstants() {
        // 工具类，禁止实例化
    }
}
