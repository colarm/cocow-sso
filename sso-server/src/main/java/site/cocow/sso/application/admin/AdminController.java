package site.cocow.sso.application.admin;

import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import site.cocow.sso.application.admin.dto.AdminResetPasswordRequest;
import site.cocow.sso.application.admin.dto.UpdateEnabledRequest;
import site.cocow.sso.application.admin.dto.UpdateLockedRequest;
import site.cocow.sso.application.admin.dto.UpdateRoleRequest;
import site.cocow.sso.infrastructure.config.ApiConstants;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ID_KEY;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ROLE_KEY;

/**
 * 管理员控制器 - 所有接口仅限 ADMIN 角色
 * <p>
 * 已通过 SessionAuthenticationInterceptor 验证登录状态， 角色校验在各接口内通过
 * {@link #requireAdmin(HttpServletRequest)} 完成。
 */
@RestController
@RequestMapping(ApiConstants.ADMIN_BASE)
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    /**
     * 获取用户列表（分页） GET /api/v1/admin/users?page=0&size=20
     */
    @GetMapping("/users")
    public ResponseEntity<?> listUsers(
            HttpServletRequest request,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        requireAdmin(request);
        return ResponseEntity.ok(adminService.listUsers(page, size));
    }

    /**
     * 获取指定用户详情 GET /api/v1/admin/users/{id}
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUser(HttpServletRequest request, @PathVariable Long id) {
        requireAdmin(request);
        return ResponseEntity.ok(adminService.getUserById(Objects.requireNonNull(id, "User ID is required")));
    }

    /**
     * 修改用户角色 PATCH /api/v1/admin/users/{id}/role Body: { "role": "USER" |
     * "CLIENT_ADMIN" | "ADMIN" }
     */
    @PatchMapping("/users/{id}/role")
    public ResponseEntity<?> updateRole(
            HttpServletRequest request,
            @PathVariable Long id,
            @RequestBody UpdateRoleRequest body
    ) {
        Long adminId = requireAdmin(request);
        return ResponseEntity.ok(adminService.updateRole(Objects.requireNonNull(id, "User ID is required"), Objects.requireNonNull(body.role(), "Role is required"), adminId));
    }

    /**
     * 启用 / 禁用用户账户 PATCH /api/v1/admin/users/{id}/enabled Body: { "enabled":
     * true | false }
     */
    @PatchMapping("/users/{id}/enabled")
    public ResponseEntity<?> setEnabled(
            HttpServletRequest request,
            @PathVariable Long id,
            @RequestBody UpdateEnabledRequest body
    ) {
        Long adminId = requireAdmin(request);
        return ResponseEntity.ok(adminService.setEnabled(Objects.requireNonNull(id, "User ID is required"), Objects.requireNonNull(body.enabled(), "Enabled is required"), adminId));
    }

    /**
     * 锁定 / 解锁用户账户 PATCH /api/v1/admin/users/{id}/locked Body: { "locked": true
     * | false }
     */
    @PatchMapping("/users/{id}/locked")
    public ResponseEntity<?> setLocked(
            HttpServletRequest request,
            @PathVariable Long id,
            @RequestBody UpdateLockedRequest body
    ) {
        Long adminId = requireAdmin(request);
        return ResponseEntity.ok(adminService.setLocked(Objects.requireNonNull(id, "User ID is required"), Objects.requireNonNull(body.locked(), "Locked is required"), adminId));
    }

    /**
     * 管理员重置用户密码（无需旧密码） POST /api/v1/admin/users/{id}/reset-password Body: {
     * "newPassword": "..." }
     */
    @PostMapping("/users/{id}/reset-password")
    public ResponseEntity<?> resetPassword(
            HttpServletRequest request,
            @PathVariable Long id,
            @RequestBody AdminResetPasswordRequest body
    ) {
        requireAdmin(request);
        String newPassword = Objects.requireNonNull(body.newPassword(), "newPassword is required");
        Long userId = Objects.requireNonNull(id, "User ID is required");
        adminService.resetPassword(userId, newPassword);
        return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
    }

    /**
     * 删除用户（硬删除） DELETE /api/v1/admin/users/{id}
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable Long id) {
        Long adminId = requireAdmin(request);
        Objects.requireNonNull(id, "User ID is required");
        adminService.deleteUser(id, adminId);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    // ── Exception handlers ──────────────────────────────────────────────────
    @ExceptionHandler(AdminService.UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFound(AdminService.UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("code", ex.getCode(), "message", ex.getMessage()));
    }

    @ExceptionHandler(AdminService.AdminOperationException.class)
    public ResponseEntity<Map<String, String>> handleAdminOperation(AdminService.AdminOperationException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("code", ex.getCode(), "message", ex.getMessage()));
    }

    @ExceptionHandler(AdminService.WeakPasswordException.class)
    public ResponseEntity<Map<String, String>> handleWeakPassword(AdminService.WeakPasswordException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("code", ex.getCode(), "message", ex.getMessage()));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────
    /**
     * 校验当前登录用户是否为 ADMIN，非 ADMIN 则抛出 403。
     *
     * @return 当前管理员的 userId
     */
    @NonNull
    private Long requireAdmin(HttpServletRequest request) {
        String role = (String) request.getAttribute(REQUEST_USER_ROLE_KEY);
        if (!"ADMIN".equals(role)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access required");
        }
        Long userId = (Long) request.getAttribute(REQUEST_USER_ID_KEY);
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid session: missing user ID");
        }
        return userId;
    }
}
