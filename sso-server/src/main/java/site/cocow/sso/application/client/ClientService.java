package site.cocow.sso.application.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import site.cocow.sso.domain.client.Client;
import site.cocow.sso.domain.client.ClientRepository;
import site.cocow.sso.infrastructure.exception.BusinessException;

/**
 * OAuth2 客户端管理服务
 */
@Service
@Transactional
public class ClientService {

    private final ClientRepository clientRepository;
    private final Argon2 argon2 = Argon2Factory.create();

    public ClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    /**
     * 注册新客户端
     */
    public Map<String, Object> registerClient(
            @NonNull String clientName,
            @NonNull Client.ClientType clientType,
            @NonNull Set<String> redirectUris,
            @NonNull Set<String> scopes
    ) {
        // 生成 client_id 和 client_secret
        String clientId = generateClientId();
        String clientSecret = generateClientSecret();
        String hashedSecret = argon2.hash(10, 65536, 1, clientSecret.toCharArray());

        Client client = new Client();
        client.setClientId(clientId);
        client.setClientSecret(hashedSecret);
        client.setClientName(clientName);
        client.setClientType(clientType);
        client.setRedirectUris(redirectUris);
        client.setScopes(scopes);
        client.setGrantTypes(Set.of("authorization_code", "refresh_token"));
        client.setEnabled(true);

        Client savedClient = Objects.requireNonNull(clientRepository.save(client));

        // 返回客户端信息（包含明文 client_secret，仅此一次）
        Map<String, Object> response = buildClientInfo(savedClient);
        response.put("client_secret", clientSecret); // 明文密钥仅在创建时返回
        return response;
    }

    /**
     * 获取客户端信息
     */
    public Map<String, Object> getClient(@NonNull Long clientId) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with id: " + clientId));
        return buildClientInfo(client);
    }

    /**
     * 根据 clientId 获取客户端信息
     */
    public Map<String, Object> getClientByClientId(@NonNull String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with clientId: " + clientId));
        return buildClientInfo(client);
    }

    /**
     * 列出所有客户端
     */
    public List<Map<String, Object>> listClients() {
        return clientRepository.findAll().stream()
                .map(this::buildClientInfo)
                .collect(Collectors.toList());
    }

    /**
     * 更新客户端信息
     */
    public Map<String, Object> updateClient(
            @NonNull Long clientId,
            String clientName,
            Set<String> redirectUris,
            Set<String> scopes
    ) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with id: " + clientId));

        if (clientName != null) {
            client.setClientName(clientName);
        }
        if (redirectUris != null && !redirectUris.isEmpty()) {
            client.setRedirectUris(redirectUris);
        }
        if (scopes != null && !scopes.isEmpty()) {
            client.setScopes(scopes);
        }

        Client savedClient = clientRepository.save(Objects.requireNonNull(client));
        return buildClientInfo(savedClient);
    }

    /**
     * 重新生成 client_secret
     */
    public Map<String, Object> regenerateSecret(@NonNull Long clientId) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with id: " + clientId));

        String newSecret = generateClientSecret();
        String hashedSecret = argon2.hash(10, 65536, 1, newSecret.toCharArray());
        client.setClientSecret(hashedSecret);

        Client savedClient = clientRepository.save(Objects.requireNonNull(client));

        Map<String, Object> response = buildClientInfo(savedClient);
        response.put("client_secret", newSecret); // 明文密钥仅在重新生成时返回
        return response;
    }

    /**
     * 启用/禁用客户端
     */
    public Map<String, Object> toggleClientStatus(@NonNull Long clientId, boolean enabled) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with id: " + clientId));

        client.setEnabled(enabled);
        Client savedClient = clientRepository.save(Objects.requireNonNull(client));
        return buildClientInfo(savedClient);
    }

    /**
     * 删除客户端
     */
    public void deleteClient(@NonNull Long clientId) {
        if (!clientRepository.existsById(clientId)) {
            throw new ClientNotFoundException("Client not found with id: " + clientId);
        }
        clientRepository.deleteById(clientId);
    }

    /**
     * 构建客户端信息（不包含 secret）
     */
    private Map<String, Object> buildClientInfo(Client client) {
        Map<String, Object> info = new HashMap<>();
        info.put("id", client.getId());
        info.put("client_id", client.getClientId());
        info.put("client_name", client.getClientName());
        info.put("client_type", client.getClientType().name());
        info.put("redirect_uris", client.getRedirectUris());
        info.put("scopes", client.getScopes());
        info.put("grant_types", client.getGrantTypes());
        info.put("enabled", client.getEnabled());
        info.put("created_at", client.getCreatedAt());
        return info;
    }

    /**
     * 生成 client_id
     */
    private String generateClientId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 生成 client_secret
     */
    private String generateClientSecret() {
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 客户端未找到异常
     */
    public static class ClientNotFoundException extends BusinessException {

        public ClientNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * 客户端已存在异常
     */
    public static class ClientAlreadyExistsException extends BusinessException {

        public ClientAlreadyExistsException(String message) {
            super(message);
        }
    }
}
