package site.cocow.sso.infrastructure.security;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USERNAME_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ID_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ROLE_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.SESSION_USERNAME_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.SESSION_USER_ID_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.SESSION_USER_ROLE_KEY;

/**
 * 统一的Session认证拦截器
 * <p>
 * 根据构造函数参数 {@code required} 决定是否强制要求用户登录：
 * <ul>
 * <li>{@code required = true}：强制认证，未登录返回 401</li>
 * <li>{@code required = false}：可选认证，尝试获取用户信息但不强制要求登录</li>
 * </ul>
 */
public class SessionAuthenticationInterceptor implements HandlerInterceptor {

    private final boolean required;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 创建认证拦截器
     *
     * @param required 是否强制要求认证（true=必须登录，false=可选登录）
     */
    public SessionAuthenticationInterceptor(boolean required) {
        this.required = required;
    }

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull Object handler) throws Exception {
        // 1. 检查 Session
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(SESSION_USER_ID_KEY) == null) {
            // 未登录时的处理
            if (required) {
                // 强制认证：返回 401
                sendUnauthorizedResponse(response, "Not logged in");
                return false;
            } else {
                // 可选认证：放行请求（不设置用户信息）
                return true;
            }
        }

        // 2. 获取用户信息
        Long userId = (Long) session.getAttribute(SESSION_USER_ID_KEY);
        String username = (String) session.getAttribute(SESSION_USERNAME_KEY);
        String userRole = (String) session.getAttribute(SESSION_USER_ROLE_KEY);

        if (userId == null) {
            if (required) {
                sendUnauthorizedResponse(response, "Invalid session");
                return false;
            } else {
                return true;
            }
        }

        // 3. 存入 Request 属性，供 Controller 使用
        request.setAttribute(REQUEST_USER_ID_KEY, userId);
        request.setAttribute(REQUEST_USERNAME_KEY, username);
        request.setAttribute(REQUEST_USER_ROLE_KEY, userRole);

        return true;
    }

    /**
     * 发送 401 响应
     */
    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        String json = objectMapper.writeValueAsString(
                java.util.Map.of("error", message)
        );
        response.getWriter().write(json);
    }
}
