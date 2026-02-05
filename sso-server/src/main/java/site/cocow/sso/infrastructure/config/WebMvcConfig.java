package site.cocow.sso.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static site.cocow.sso.infrastructure.security.SecurityConstants.OPTIONAL_AUTH_ENDPOINTS;
import static site.cocow.sso.infrastructure.security.SecurityConstants.PROTECTED_ENDPOINTS;
import site.cocow.sso.infrastructure.security.SessionAuthenticationInterceptor;

/**
 * Web MVC 配置
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * 必须认证的拦截器
     */
    @Bean
    @NonNull
    public SessionAuthenticationInterceptor requiredAuthenticationInterceptor() {
        return new SessionAuthenticationInterceptor(true);
    }

    /**
     * 可选认证的拦截器
     */
    @Bean
    @NonNull
    public SessionAuthenticationInterceptor optionalAuthenticationInterceptor() {
        return new SessionAuthenticationInterceptor(false);
    }

    @Override
    public void addInterceptors(@NonNull InterceptorRegistry registry) {
        // 必须认证的接口
        registry.addInterceptor(requiredAuthenticationInterceptor())
                .addPathPatterns(PROTECTED_ENDPOINTS);

        // 可选认证的接口
        registry.addInterceptor(optionalAuthenticationInterceptor())
                .addPathPatterns(OPTIONAL_AUTH_ENDPOINTS);
    }
}
