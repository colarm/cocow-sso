package site.cocow.sso.application.user;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import site.cocow.sso.domain.user.User;
import site.cocow.sso.domain.user.UserRepository;
import site.cocow.sso.infrastructure.exception.BusinessException;
import site.cocow.sso.infrastructure.security.PasswordEncoder;

/**
 * 用户服务
 */
@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 获取用户信息（不包含密码）
     */
    public Map<String, Object> getUserInfo(@NonNull Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("id", user.getId());
        userInfo.put("username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("enabled", user.getEnabled());
        userInfo.put("locked", user.getLocked());
        userInfo.put("role", user.getRole());
        userInfo.put("createdAt", user.getCreatedAt());
        userInfo.put("updatedAt", user.getUpdatedAt());

        return userInfo;
    }

    /**
     * 根据 OIDC scope 获取用户信息 根据 scopes 返回标准 OIDC claims
     *
     * @param userId 用户 ID
     * @param scopes OAuth2 scopes (openid, profile, email 等)
     * @return OIDC 标准 claims
     */
    public Map<String, Object> getUserInfoByClaims(@NonNull Long userId, @NonNull Set<String> scopes) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        Map<String, Object> claims = new HashMap<>();

        // sub (subject) 是必须的，标识用户的唯一 ID
        claims.put("sub", user.getId().toString());

        // profile scope - 基本用户信息
        if (scopes.contains("profile")) {
            claims.put("preferred_username", user.getUsername());
            claims.put("updated_at", user.getUpdatedAt() != null
                    ? user.getUpdatedAt().toString() : user.getCreatedAt().toString());
        }

        // email scope - 邮箱信息
        if (scopes.contains("email")) {
            claims.put("email", user.getEmail());
            claims.put("email_verified", user.getEnabled()); // 简化：enabled 表示邮箱已验证
        }

        return claims;
    }

    /**
     * 更新用户信息（允许更新 username 和 email）
     */
    public Map<String, Object> updateUserInfo(@NonNull Long userId, String username, String email) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        // 检查用户名是否已被其他用户使用
        if (username != null && !username.equals(user.getUsername())) {
            userRepository.findByUsername(username).ifPresent(existingUser -> {
                if (!existingUser.getId().equals(userId)) {
                    throw new UsernameAlreadyExistsException("Username already exists: " + username);
                }
            });
            user.setUsername(username);
        }

        // 检查邮箱是否已被其他用户使用
        if (email != null && !email.equals(user.getEmail())) {
            userRepository.findByEmail(email).ifPresent(existingUser -> {
                if (!existingUser.getId().equals(userId)) {
                    throw new EmailAlreadyExistsException("Email already exists: " + email);
                }
            });
            user.setEmail(email);
        }

        userRepository.save(Objects.requireNonNull(user));
        return getUserInfo(Objects.requireNonNull(user.getId()));
    }

    /**
     * 修改密码
     */
    public void changePassword(@NonNull Long userId, @NonNull String oldPassword, @NonNull String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        // 验证旧密码
        if (!passwordEncoder.matches(oldPassword, user.getPasswordHash())) {
            throw new InvalidPasswordException("Old password is incorrect");
        }

        // 验证新密码强度
        validatePasswordStrength(newPassword);

        // 更新密码
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(Objects.requireNonNull(user));
    }

    /**
     * 注销账户（软删除：禁用 + 锁定）
     */
    public void deleteAccount(@NonNull Long userId, @NonNull String password) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        // 验证密码确认身份
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new InvalidPasswordException("Password is incorrect");
        }

        // 软删除：禁用并锁定账户
        user.setEnabled(false);
        user.setLocked(true);
        userRepository.save(Objects.requireNonNull(user));
    }

    /**
     * 验证密码强度
     */
    private void validatePasswordStrength(String password) {
        if (password.length() < 8) {
            throw new WeakPasswordException("Password must be at least 8 characters long");
        }
        // 可以添加更多规则：大小写、数字、特殊字符等
    }

    /**
     * 用户未找到异常
     */
    public static class UserNotFoundException extends BusinessException {

        public UserNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * 邮箱已存在异常
     */
    public static class EmailAlreadyExistsException extends BusinessException {

        public EmailAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * 用户名已存在异常
     */
    public static class UsernameAlreadyExistsException extends BusinessException {

        public UsernameAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * 密码错误异常
     */
    public static class InvalidPasswordException extends BusinessException {

        public InvalidPasswordException(String message) {
            super(message);
        }
    }

    /**
     * 弱密码异常
     */
    public static class WeakPasswordException extends BusinessException {

        public WeakPasswordException(String message) {
            super(message);
        }
    }
}
