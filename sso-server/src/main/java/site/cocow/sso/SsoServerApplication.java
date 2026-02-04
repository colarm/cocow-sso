package site.cocow.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

/**
 * SSO Server 主应用 统一身份认证中心
 *
 * @author cocow
 */
@SpringBootApplication
public class SsoServerApplication {

    private final Environment environment;

    public SsoServerApplication(Environment environment) {
        this.environment = environment;
    }

    public static void main(String[] args) {
        SpringApplication.run(SsoServerApplication.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        String port = environment.getProperty("server.port", "8080");
        String contextPath = environment.getProperty("server.servlet.context-path", "/");

        System.out.println("\n========================================");
        System.out.println("   SSO Server Started Successfully!");
        System.out.println("========================================");
        System.out.println("   Service URL: http://localhost:" + port + contextPath);
        System.out.println("   Health Check: http://localhost:" + port + contextPath + "api/v1/health");
        System.out.println("========================================\n");
    }

}
