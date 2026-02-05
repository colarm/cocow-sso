package site.cocow.sso.application;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import site.cocow.sso.infrastructure.config.ApiConstants;

/**
 * 健康检查控制器
 */
@RestController
@RequestMapping(ApiConstants.HEALTH)
public class HealthController {

    @GetMapping
    public String health() {
        return "SSO Server is running";
    }
}
