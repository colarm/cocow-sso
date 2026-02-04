package site.cocow.sso.infrastructure.security;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * 认证拦截器 验证用户登录状态，将用户信息存入 Request 属性
 */
@Component
public class AuthenticationInterceptor implements HandlerInterceptor {

    public static final String REQUEST_USER_ID_KEY = "userId";
    public static final String REQUEST_USERNAME_KEY = "username";

    private static final String SESSION_USER_ID_KEY = "userId";
    private static final String SESSION_USERNAME_KEY = "username";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull Object handler) throws Exception {
        // 1. 检查 Session
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(SESSION_USER_ID_KEY) == null) {
            sendUnauthorizedResponse(response, "Not logged in");
            return false;
        }

        // 2. 获取用户信息
        Long userId = (Long) session.getAttribute(SESSION_USER_ID_KEY);
        String username = (String) session.getAttribute(SESSION_USERNAME_KEY);

        if (userId == null) {
            sendUnauthorizedResponse(response, "Invalid session");
            return false;
        }

        // 3. 存入 Request 属性，供 Controller 使用
        request.setAttribute(REQUEST_USER_ID_KEY, userId);
        request.setAttribute(REQUEST_USERNAME_KEY, username);

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
