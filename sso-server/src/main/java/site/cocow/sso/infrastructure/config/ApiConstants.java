package site.cocow.sso.infrastructure.config;

/**
 * API 路径常量
 */
public class ApiConstants {

    /**
     * API 版本前缀
     */
    public static final String API_V1 = "/api/v1";

    /**
     * 认证相关端点
     */
    public static final String AUTH_BASE = API_V1 + "/auth";

    /**
     * 用户相关端点
     */
    public static final String USER_BASE = API_V1 + "/user";

    /**
     * 健康检查端点
     */
    public static final String HEALTH = API_V1 + "/health";

    /**
     * OAuth2 端点
     */
    public static final String OAUTH_BASE = "/oauth";

    private ApiConstants() {
        // 工具类，禁止实例化
    }
}
