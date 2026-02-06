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
import static site.cocow.sso.infrastructure.security.SecurityConstants.REQUEST_USER_ROLE_KEY;

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
     * 验证用户有客户端管理权限（ADMIN 或 CLIENT_ADMIN）
     */
    private void requireClientManagement(HttpServletRequest request) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        String userRole = (String) request.getAttribute(REQUEST_USER_ROLE_KEY);
        if (!"ADMIN".equals(userRole) && !"CLIENT_ADMIN".equals(userRole)) {
            throw new ClientManagementAccessRequiredException("Client management access required");
        }
    }

    /**
     * 验证用户对指定客户端有访问权限
     */
    private void requireClientAccess(HttpServletRequest request, Long clientId) {
        Long userId = (Long) Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        String userRole = (String) request.getAttribute(REQUEST_USER_ROLE_KEY);

        if (!clientService.hasAccessToClient(clientId, userId, userRole)) {
            throw new ClientAccessDeniedException("Access denied to this client");
        }
    }

    /**
     * 验证用户是系统管理员
     */
    private void requireAdmin(HttpServletRequest request) {
        Objects.requireNonNull(request.getAttribute(REQUEST_USER_ID_KEY), "User must be authenticated");
        String userRole = (String) request.getAttribute(REQUEST_USER_ROLE_KEY);
        if (!"ADMIN".equals(userRole)) {
            throw new AdminAccessRequiredException("System admin access required");
        }
    }

    /**
     * 注册新客户端
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> registerClient(
            HttpServletRequest request,
            @RequestBody RegisterClientRequest registerRequest
    ) {
        requireClientManagement(request);
        Long userId = (Long) request.getAttribute(REQUEST_USER_ID_KEY);

        Map<String, Object> client = clientService.registerClient(
                Objects.requireNonNull(registerRequest.clientName(), "clientName is required"),
                Objects.requireNonNull(registerRequest.clientType(), "clientType is required"),
                Objects.requireNonNull(registerRequest.redirectUris(), "redirectUris is required"),
                Objects.requireNonNull(registerRequest.scopes(), "scopes is required"),
                userId
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
        requireClientAccess(request, id);
        Map<String, Object> client = clientService.getClient(Objects.requireNonNull(id, "Client ID is required"));
        return ResponseEntity.ok(client);
    }

    /**
     * 列出所有客户端
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listClients(HttpServletRequest request) {
        requireAdmin(request);
        List<Map<String, Object>> clients = clientService.listClients();
        return ResponseEntity.ok(clients);
    }

    /**
     * 获取允许的 scopes 列表
     */
    @GetMapping("/allowed-scopes")
    public ResponseEntity<Map<String, Object>> getAllowedScopes() {
        return ResponseEntity.ok(Map.of(
                "scopes", clientService.getAllowedScopes(),
                "description", Map.of(
                        "openid", "OpenID Connect scope",
                        "offline_access", "Request refresh token",
                        "read:profile", "Read user profile information",
                        "read:email", "Read email address"
                // "write:profile", "Modify user profile information",
                // "write:email", "Modify email address"
                )
        ));
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
        requireClientAccess(request, id);

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
        requireClientAccess(request, id);
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
        requireClientAccess(request, id);
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
        requireClientAccess(request, id);
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
        requireClientAccess(request, id);
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

    /**
     * 处理无效Scope异常
     */
    @ExceptionHandler(ClientService.InvalidScopeException.class)
    public ResponseEntity<Map<String, String>> handleInvalidScope(ClientService.InvalidScopeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理管理员权限不足异常
     */
    @ExceptionHandler(AdminAccessRequiredException.class)
    public ResponseEntity<Map<String, String>> handleAdminAccessRequired(AdminAccessRequiredException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理客户端管理权限不足异常
     */
    @ExceptionHandler(ClientManagementAccessRequiredException.class)
    public ResponseEntity<Map<String, String>> handleClientManagementAccessRequired(ClientManagementAccessRequiredException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 处理客户端访问被拒绝异常
     */
    @ExceptionHandler(ClientAccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleClientAccessDenied(ClientAccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * 管理员权限不足异常
     */
    public static class AdminAccessRequiredException extends RuntimeException {

        public AdminAccessRequiredException(String message) {
            super(message);
        }
    }

    /**
     * 客户端管理权限不足异常
     */
    public static class ClientManagementAccessRequiredException extends RuntimeException {

        public ClientManagementAccessRequiredException(String message) {
            super(message);
        }
    }

    /**
     * 客户端访问被拒绝异常
     */
    public static class ClientAccessDeniedException extends RuntimeException {

        public ClientAccessDeniedException(String message) {
            super(message);
        }
    }
}
