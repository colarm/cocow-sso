package site.cocow.sso.application.auth;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
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
import site.cocow.sso.application.user.UserService;
import site.cocow.sso.infrastructure.config.ApiConstants;

/**
 * 认证控制器
 */
@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
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
        AuthResult authResult = authService.register(request);

        // 创建 Session 并存储用户信息
        HttpSession session = httpRequest.getSession(true);
        session.setAttribute("userId", authResult.userId());
        session.setAttribute("username", authResult.username());
        session.setAttribute("userRole", authResult.role());

        // 根据 rememberMe 设置 Session 超时时间
        if (rememberMe) {
            session.setMaxInactiveInterval(30 * 24 * 60 * 60); // 30天
        } else {
            session.setMaxInactiveInterval(30 * 60); // 30分钟
        }

        // 返回响应
        Map<String, Object> result = new HashMap<>();
        result.put("username", authResult.username());
        result.put("message", "Registration successful");
        if (rememberMe) {
            result.put("rememberMe", true);
        }
        return ResponseEntity.ok(result);
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
        AuthResult authResult = authService.login(request);

        // 创建 Session 并存储用户信息
        HttpSession session = httpRequest.getSession(true);
        session.setAttribute("userId", authResult.userId());
        session.setAttribute("username", authResult.username());
        session.setAttribute("userRole", authResult.role());

        // 根据 rememberMe 设置 Session 超时时间
        if (rememberMe) {
            session.setMaxInactiveInterval(30 * 24 * 60 * 60); // 30天
        } else {
            session.setMaxInactiveInterval(30 * 60); // 30分钟
        }

        // 返回响应
        Map<String, Object> result = new HashMap<>();
        result.put("username", authResult.username());
        result.put("message", "Login successful");
        if (rememberMe) {
            result.put("rememberMe", true);
        }
        return ResponseEntity.ok(result);
    }

    /**
     * 用户登出
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        // 销毁 Session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        Map<String, String> result = new HashMap<>();
        result.put("message", "Logout successful");
        return ResponseEntity.ok(result);
    }

    /**
     * 处理用户名已存在异常
     */
    @ExceptionHandler(AuthService.UsernameAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleUsernameAlreadyExists(AuthService.UsernameAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理邮箱已存在异常
     */
    @ExceptionHandler(AuthService.EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleEmailAlreadyExists(AuthService.EmailAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理凭据无效异常
     */
    @ExceptionHandler(AuthService.InvalidCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleInvalidCredentials(AuthService.InvalidCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理账户被锁定异常
     */
    @ExceptionHandler(AuthService.AccountLockedException.class)
    public ResponseEntity<Map<String, String>> handleAccountLocked(AuthService.AccountLockedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理账户被禁用异常
     */
    @ExceptionHandler(AuthService.AccountDisabledException.class)
    public ResponseEntity<Map<String, String>> handleAccountDisabled(AuthService.AccountDisabledException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理用户未找到异常
     */
    @ExceptionHandler(UserService.UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFound(UserService.UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", ex.getMessage()));
    }
}
