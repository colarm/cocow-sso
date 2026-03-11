package site.cocow.sso.application.admin;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import site.cocow.sso.domain.user.User;
import site.cocow.sso.domain.user.UserRepository;
import site.cocow.sso.infrastructure.exception.BusinessException;
import site.cocow.sso.infrastructure.security.PasswordEncoder;

/**
 * 管理员服务 - 仅限 ADMIN 角色调用
 */
@Service
@Transactional
public class AdminService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 分页获取用户列表
     */
    public Map<String, Object> listUsers(int page, int size) {
        Page<User> userPage = userRepository.findAll(
                PageRequest.of(page, size, Sort.by("createdAt").descending())
        );

        List<Map<String, Object>> users = userPage.getContent().stream()
                .map(this::buildUserInfo)
                .collect(Collectors.toList());

        Map<String, Object> result = new HashMap<>();
        result.put("users", users);
        result.put("total", userPage.getTotalElements());
        result.put("page", page);
        result.put("size", size);
        result.put("total_pages", userPage.getTotalPages());
        return result;
    }

    /**
     * 根据 ID 获取用户信息
     */
    public Map<String, Object> getUserById(@NonNull Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        return buildUserInfo(user);
    }

    /**
     * 修改用户角色（不允许修改自身角色）
     */
    public Map<String, Object> updateRole(@NonNull Long id, @NonNull User.UserRole role, @NonNull Long adminId) {
        if (id.equals(adminId)) {
            throw new AdminOperationException("Cannot change your own role");
        }
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        user.setRole(role);
        userRepository.save(user);
        return buildUserInfo(user);
    }

    /**
     * 启用 / 禁用用户账户（不允许操作自身）
     */
    public Map<String, Object> setEnabled(@NonNull Long id, boolean enabled, @NonNull Long adminId) {
        if (id.equals(adminId)) {
            throw new AdminOperationException("Cannot change enabled status of your own account");
        }
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        user.setEnabled(enabled);
        userRepository.save(user);
        return buildUserInfo(user);
    }

    /**
     * 锁定 / 解锁用户账户（不允许操作自身）
     */
    public Map<String, Object> setLocked(@NonNull Long id, boolean locked, @NonNull Long adminId) {
        if (id.equals(adminId)) {
            throw new AdminOperationException("Cannot lock your own account");
        }
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        user.setLocked(locked);
        userRepository.save(user);
        return buildUserInfo(user);
    }

    /**
     * 管理员直接重置用户密码（无需旧密码）
     */
    public void resetPassword(@NonNull Long id, @NonNull String newPassword) {
        validatePasswordStrength(newPassword);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    /**
     * 删除用户（硬删除，不允许删除自身）
     */
    public void deleteUser(@NonNull Long id, @NonNull Long adminId) {
        if (id.equals(adminId)) {
            throw new AdminOperationException("Cannot delete your own account");
        }
        userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        userRepository.deleteById(id);
    }

    private Map<String, Object> buildUserInfo(User user) {
        Map<String, Object> info = new HashMap<>();
        info.put("id", user.getId());
        info.put("username", user.getUsername());
        info.put("email", user.getEmail());
        info.put("enabled", user.getEnabled());
        info.put("locked", user.getLocked());
        info.put("role", user.getRole());
        info.put("created_at", user.getCreatedAt());
        info.put("updated_at", user.getUpdatedAt());
        return info;
    }

    private void validatePasswordStrength(String password) {
        if (password.length() < 8) {
            throw new WeakPasswordException("Password must be at least 8 characters long");
        }
        if (password.contains(" ")) {
            throw new WeakPasswordException("Password must not contain spaces");
        }
        if (!password.matches(".*[A-Za-z].*")) {
            throw new WeakPasswordException("Password must contain at least one letter");
        }
        if (!password.matches(".*\\d.*")) {
            throw new WeakPasswordException("Password must contain at least one digit");
        }
    }

    /**
     * 用户未找到异常
     */
    public static class UserNotFoundException extends BusinessException {

        public UserNotFoundException(String message) {
            super("admin.user_not_found", message);
        }
    }

    /**
     * 管理操作不允许异常
     */
    public static class AdminOperationException extends BusinessException {

        public AdminOperationException(String message) {
            super("admin.operation_not_allowed", message);
        }
    }

    /**
     * 弱密码异常
     */
    public static class WeakPasswordException extends BusinessException {

        public WeakPasswordException(String message) {
            super("admin.weak_password", message);
        }
    }
}
