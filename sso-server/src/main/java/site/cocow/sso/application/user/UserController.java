package site.cocow.sso.application.user;

import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import site.cocow.sso.infrastructure.config.ApiConstants;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ID_KEY;

/**
 * 用户信息控制器 已通过 SessionAuthenticationInterceptor 验证登录状态
 */
@RestController
@RequestMapping(ApiConstants.USER_BASE)
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * 获取当前登录用户信息 已通过 SessionAuthenticationInterceptor 验证登录状态
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getUserInfo(HttpServletRequest request) {
        Long userId = Objects.requireNonNull(
                (Long) request.getAttribute(REQUEST_USER_ID_KEY),
                "User ID must be set by SessionAuthenticationInterceptor"
        );

        Map<String, Object> userInfo = userService.getUserInfo(userId);
        return ResponseEntity.ok(userInfo);
    }

    /**
     * 更新用户信息
     */
    @PutMapping("/info")
    public ResponseEntity<Map<String, Object>> updateUserInfo(
            HttpServletRequest request,
            @RequestBody UpdateUserRequest updateRequest
    ) {
        Long userId = Objects.requireNonNull(
                (Long) request.getAttribute(REQUEST_USER_ID_KEY),
                "User ID must be set by SessionAuthenticationInterceptor"
        );

        Map<String, Object> updatedUserInfo = userService.updateUserInfo(
                userId,
                updateRequest.username,
                updateRequest.email
        );
        return ResponseEntity.ok(updatedUserInfo);
    }

    /**
     * 修改密码
     */
    @PatchMapping("/password")
    public ResponseEntity<Map<String, String>> changePassword(
            HttpServletRequest request,
            @RequestBody ChangePasswordRequest changePasswordRequest
    ) {
        Long userId = Objects.requireNonNull(
                (Long) request.getAttribute(REQUEST_USER_ID_KEY),
                "User ID must be set by SessionAuthenticationInterceptor"
        );

        String oldPassword = Objects.requireNonNull(
                changePasswordRequest.oldPassword,
                "Old password is required"
        );
        String newPassword = Objects.requireNonNull(
                changePasswordRequest.newPassword,
                "New password is required"
        );

        userService.changePassword(userId, oldPassword, newPassword);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    /**
     * 注销账户
     */
    @DeleteMapping("/account")
    public ResponseEntity<Map<String, String>> deleteAccount(
            HttpServletRequest request,
            @RequestBody DeleteAccountRequest deleteRequest
    ) {
        Long userId = Objects.requireNonNull(
                (Long) request.getAttribute(REQUEST_USER_ID_KEY),
                "User ID must be set by SessionAuthenticationInterceptor"
        );

        String password = Objects.requireNonNull(
                deleteRequest.password,
                "Password is required to delete account"
        );

        userService.deleteAccount(userId, password);

        // 注销成功后清除 Session
        request.getSession().invalidate();

        return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
    }

    /**
     * 处理用户未找到异常
     */
    @ExceptionHandler(UserService.UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFound(UserService.UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理邮箱已存在异常
     */
    @ExceptionHandler(UserService.EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleEmailAlreadyExists(UserService.EmailAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理用户名已存在异常
     */
    @ExceptionHandler(UserService.UsernameAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleUsernameAlreadyExists(UserService.UsernameAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理密码错误异常
     */
    @ExceptionHandler(UserService.InvalidPasswordException.class)
    public ResponseEntity<Map<String, String>> handleInvalidPassword(UserService.InvalidPasswordException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理弱密码异常
     */
    @ExceptionHandler(UserService.WeakPasswordException.class)
    public ResponseEntity<Map<String, String>> handleWeakPassword(UserService.WeakPasswordException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", ex.getMessage()));
    }

    // Request DTOs
    public record UpdateUserRequest(String username, String email) {

    }

    public record ChangePasswordRequest(String oldPassword, String newPassword) {

    }

    public record DeleteAccountRequest(String password) {

    }
}
