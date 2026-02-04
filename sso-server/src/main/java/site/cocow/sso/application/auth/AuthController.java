package site.cocow.sso.application.auth;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import site.cocow.sso.application.auth.dto.AuthResult;
import site.cocow.sso.application.auth.dto.LoginRequest;
import site.cocow.sso.application.auth.dto.RegisterRequest;
import site.cocow.sso.domain.user.User;
import site.cocow.sso.domain.user.UserRepository;

/**
 * 认证控制器
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    public AuthController(AuthService authService, UserRepository userRepository) {
        this.authService = authService;
        this.userRepository = userRepository;
    }

    /**
     * 用户注册
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request,
            @RequestParam(value = "rememberMe", defaultValue = "false") boolean rememberMe,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        try {
            AuthResult authResult = authService.register(request);
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // 创建 Session 并存储用户信息
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());

            // 根据 rememberMe 设置 Session 超时时间
            if (rememberMe) {
                session.setMaxInactiveInterval(30 * 24 * 60 * 60); // 30天
            } else {
                session.setMaxInactiveInterval(30 * 60); // 30分钟
            }

            // 返回响应
            Map<String, Object> result = new HashMap<>();
            result.put("username", authResult.getUsername());
            result.put("message", "Registration successful");
            if (rememberMe) {
                result.put("rememberMe", true);
            }
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    /**
     * 用户登录
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            @RequestParam(value = "rememberMe", defaultValue = "false") boolean rememberMe,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        try {
            AuthResult authResult = authService.login(request);
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // 创建 Session 并存储用户信息
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());

            // 根据 rememberMe 设置 Session 超时时间
            if (rememberMe) {
                session.setMaxInactiveInterval(30 * 24 * 60 * 60); // 30天
            } else {
                session.setMaxInactiveInterval(30 * 60); // 30分钟
            }

            // 返回响应
            Map<String, Object> result = new HashMap<>();
            result.put("username", authResult.getUsername());
            result.put("message", "Login successful");
            if (rememberMe) {
                result.put("rememberMe", true);
            }
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    /**
     * 用户登出
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // 销毁 Session
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }

            Map<String, String> result = new HashMap<>();
            result.put("message", "Logout successful");
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }
}
