package site.cocow.sso.infrastructure.security;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * 可选认证拦截器 尝试获取用户登录信息，但不强制要求登录 适用于：首页、公开内容等场景（登录用户看到个性化内容，未登录用户看到通用内容）
 */
@Component
public class OptionalAuthenticationInterceptor implements HandlerInterceptor {

    public static final String REQUEST_USER_ID_KEY = "userId";
    public static final String REQUEST_USERNAME_KEY = "username";

    private static final String SESSION_USER_ID_KEY = "userId";
    private static final String SESSION_USERNAME_KEY = "username";

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull Object handler) throws Exception {
        // 尝试获取 Session，但不强制要求
        HttpSession session = request.getSession(false);

        if (session != null && session.getAttribute(SESSION_USER_ID_KEY) != null) {
            // 如果用户已登录，将用户信息存入 Request 属性
            Long userId = (Long) session.getAttribute(SESSION_USER_ID_KEY);
            String username = (String) session.getAttribute(SESSION_USERNAME_KEY);

            request.setAttribute(REQUEST_USER_ID_KEY, userId);
            request.setAttribute(REQUEST_USERNAME_KEY, username);
        }
        // 无论是否登录，都放行请求
        return true;
    }
}
