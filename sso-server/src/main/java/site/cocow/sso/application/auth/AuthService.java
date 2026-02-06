package site.cocow.sso.application.auth;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import site.cocow.sso.application.auth.dto.AuthResult;
import site.cocow.sso.application.auth.dto.LoginRequest;
import site.cocow.sso.application.auth.dto.RegisterRequest;
import site.cocow.sso.domain.user.User;
import site.cocow.sso.domain.user.UserRepository;
import site.cocow.sso.infrastructure.exception.BusinessException;
import site.cocow.sso.infrastructure.security.PasswordEncoder;

/**
 * 认证应用服务
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 用户注册
     */
    public AuthResult register(RegisterRequest request) {
        // 检查用户名是否已存在
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException("Username already exists");
        }

        // 检查邮箱是否已存在
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException("Email already registered");
        }

        // 创建用户
        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.setLocked(false);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        user = userRepository.save(user);

        return new AuthResult(user.getUsername());
    }

    /**
     * 用户登录
     */
    public AuthResult login(LoginRequest request) {
        // 查找用户
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        // 检查账户状态
        if (user.getLocked()) {
            throw new AccountLockedException("Account is locked");
        }

        if (!user.getEnabled()) {
            throw new AccountDisabledException("Account is disabled");
        }

        // 验证密码
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        return new AuthResult(user.getUsername());
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
     * 邮箱已注册异常
     */
    public static class EmailAlreadyExistsException extends BusinessException {

        public EmailAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * 无效凭据异常
     */
    public static class InvalidCredentialsException extends BusinessException {

        public InvalidCredentialsException(String message) {
            super(message);
        }
    }

    /**
     * 账户被锁定异常
     */
    public static class AccountLockedException extends BusinessException {

        public AccountLockedException(String message) {
            super(message);
        }
    }

    /**
     * 账户被禁用异常
     */
    public static class AccountDisabledException extends BusinessException {

        public AccountDisabledException(String message) {
            super(message);
        }
    }
}
