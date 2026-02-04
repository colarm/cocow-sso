package site.cocow.sso.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 配置
 *
 * 说明： - Spring Security 允许所有请求通过（anyRequest().permitAll()） - 实际的认证和授权由拦截器控制： 1.
 * AuthenticationInterceptor - 强制认证（PROTECTED_ENDPOINTS） 2.
 * OptionalAuthenticationInterceptor - 可选认证（OPTIONAL_AUTH_ENDPOINTS） - CSRF
 * 已禁用（适用于 API 服务） - Session 策略：IF_REQUIRED（按需创建）
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                // 所有接口都允许通过 Spring Security
                // 实际的认证由 AuthenticationInterceptor 和 OptionalAuthenticationInterceptor 处理
                .anyRequest().permitAll()
                )
                .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 允许创建 Session
                );

        return http.build();
    }

}
