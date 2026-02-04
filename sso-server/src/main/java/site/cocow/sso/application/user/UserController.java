package site.cocow.sso.application.user;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import site.cocow.sso.domain.user.User;
import site.cocow.sso.domain.user.UserRepository;
import site.cocow.sso.infrastructure.security.AuthenticationInterceptor;

/**
 * 用户信息控制器 已通过 AuthenticationInterceptor 验证登录状态
 */
@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * 获取当前登录用户信息 已通过 AuthenticationInterceptor 验证登录状态
     */
    @GetMapping("/info")
    public ResponseEntity<?> getUserInfo(HttpServletRequest request) {
        // 1. 从 Request 属性获取用户 ID（由 Interceptor 注入）
        Long userId = Objects.requireNonNull(
                (Long) request.getAttribute(AuthenticationInterceptor.REQUEST_USER_ID_KEY),
                "User ID must be set by AuthenticationInterceptor"
        );

        // 2. 从数据库加载完整用户信息
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }

        // 3. 返回用户信息（不包含密码）
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("id", user.getId());
        userInfo.put("username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("enabled", user.getEnabled());
        userInfo.put("locked", user.getLocked());
        userInfo.put("createdAt", user.getCreatedAt());

        return ResponseEntity.ok(userInfo);
    }
}
