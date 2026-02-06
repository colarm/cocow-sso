package site.cocow.sso.application.client;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import site.cocow.sso.application.client.dto.RegisterClientRequest;
import site.cocow.sso.application.client.dto.UpdateClientRequest;
import site.cocow.sso.infrastructure.config.ApiConstants;
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ID_KEY;

/**
 * OAuth2 客户端管理控制器 需要登录才能访问（通过 SessionAuthenticationInterceptor 验证）
 */
@RestController
@RequestMapping(ApiConstants.CLIENT_BASE)
public class ClientController {

    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    /**
     * 注册新客户端
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> registerClient(
            HttpServletRequest request,
            @RequestBody RegisterClientRequest registerRequest
    ) {
        // 验证用户已登录
        Objects.requireNonNull(
                request.getAttribute(REQUEST_USER_ID_KEY),
                "User must be authenticated"
        );

        Map<String, Object> client = clientService.registerClient(
                Objects.requireNonNull(registerRequest.clientName(), "clientName is required"),
                Objects.requireNonNull(registerRequest.clientType(), "clientType is required"),
                Objects.requireNonNull(registerRequest.redirectUris(), "redirectUris is required"),
                Objects.requireNonNull(registerRequest.scopes(), "scopes is required")
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(client);
    }

    /**
     * 获取客户端信息
     */
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getClient(
            HttpServletRequest request,
            @PathVariable Long id
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        Map<String, Object> client = clientService.getClient(Objects.requireNonNull(id, "Client ID is required"));
        return ResponseEntity.ok(client);
    }

    /**
     * 列出所有客户端
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listClients(HttpServletRequest request) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        List<Map<String, Object>> clients = clientService.listClients();
        return ResponseEntity.ok(clients);
    }

    /**
     * 更新客户端信息
     */
    @PutMapping("/{id}")
    public ResponseEntity<Map<String, Object>> updateClient(
            HttpServletRequest request,
            @PathVariable Long id,
            @RequestBody UpdateClientRequest updateRequest
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");

        Map<String, Object> client = clientService.updateClient(
                Objects.requireNonNull(id, "Client ID is required"),
                updateRequest.clientName(),
                updateRequest.redirectUris(),
                updateRequest.scopes()
        );

        return ResponseEntity.ok(client);
    }

    /**
     * 重新生成 client_secret
     */
    @PostMapping("/{id}/regenerate-secret")
    public ResponseEntity<Map<String, Object>> regenerateSecret(
            HttpServletRequest request,
            @PathVariable Long id
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        Map<String, Object> client = clientService.regenerateSecret(Objects.requireNonNull(id, "Client ID is required"));
        return ResponseEntity.ok(client);
    }

    /**
     * 启用客户端
     */
    @PatchMapping("/{id}/enable")
    public ResponseEntity<Map<String, Object>> enableClient(
            HttpServletRequest request,
            @PathVariable Long id
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        Map<String, Object> client = clientService.toggleClientStatus(Objects.requireNonNull(id, "Client ID is required"), true);
        return ResponseEntity.ok(client);
    }

    /**
     * 禁用客户端
     */
    @PatchMapping("/{id}/disable")
    public ResponseEntity<Map<String, Object>> disableClient(
            HttpServletRequest request,
            @PathVariable Long id
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        Map<String, Object> client = clientService.toggleClientStatus(Objects.requireNonNull(id, "Client ID is required"), false);
        return ResponseEntity.ok(client);
    }

    /**
     * 删除客户端
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteClient(
            HttpServletRequest request,
            @PathVariable Long id
    ) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        clientService.deleteClient(Objects.requireNonNull(id, "Client ID is required"));
        return ResponseEntity.ok(Map.of("message", "Client deleted successfully"));
    }

    /**
     * 处理客户端未找到异常
     */
    @ExceptionHandler(ClientService.ClientNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleClientNotFound(ClientService.ClientNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理客户端已存在异常
     */
    @ExceptionHandler(ClientService.ClientAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleClientAlreadyExists(ClientService.ClientAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }
}
