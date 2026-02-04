package site.cocow.sso.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import site.cocow.sso.infrastructure.security.AuthenticationInterceptor;
import site.cocow.sso.infrastructure.security.OptionalAuthenticationInterceptor;
import static site.cocow.sso.infrastructure.security.SecurityConstants.OPTIONAL_AUTH_ENDPOINTS;
import static site.cocow.sso.infrastructure.security.SecurityConstants.PROTECTED_ENDPOINTS;

/**
 * Web MVC 配置
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @NonNull
    private final AuthenticationInterceptor authenticationInterceptor;

    @NonNull
    private final OptionalAuthenticationInterceptor optionalAuthenticationInterceptor;

    public WebMvcConfig(
            @NonNull AuthenticationInterceptor authenticationInterceptor,
            @NonNull OptionalAuthenticationInterceptor optionalAuthenticationInterceptor) {
        this.authenticationInterceptor = authenticationInterceptor;
        this.optionalAuthenticationInterceptor = optionalAuthenticationInterceptor;
    }

    @Override
    public void addInterceptors(@NonNull InterceptorRegistry registry) {
        // 必须认证的接口
        registry.addInterceptor(authenticationInterceptor)
                .addPathPatterns(PROTECTED_ENDPOINTS);

        // 可选认证的接口
        registry.addInterceptor(optionalAuthenticationInterceptor)
                .addPathPatterns(OPTIONAL_AUTH_ENDPOINTS);
    }
}
