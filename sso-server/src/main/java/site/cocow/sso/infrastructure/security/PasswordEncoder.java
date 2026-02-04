package site.cocow.sso.infrastructure.security;

import org.springframework.stereotype.Component;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

/**
 * Argon2 密码编码器
 */
@Component
public class PasswordEncoder {

    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    // Argon2 参数配置
    private static final int ITERATIONS = 3;
    private static final int MEMORY = 65536; // 64 MB
    private static final int PARALLELISM = 1;

    /**
     * 加密密码
     */
    public String encode(String rawPassword) {
        try {
            return argon2.hash(ITERATIONS, MEMORY, PARALLELISM, rawPassword.toCharArray());
        } finally {
            argon2.wipeArray(rawPassword.toCharArray());
        }
    }

    /**
     * 验证密码
     */
    public boolean matches(String rawPassword, String encodedPassword) {
        try {
            return argon2.verify(encodedPassword, rawPassword.toCharArray());
        } finally {
            argon2.wipeArray(rawPassword.toCharArray());
        }
    }
}
