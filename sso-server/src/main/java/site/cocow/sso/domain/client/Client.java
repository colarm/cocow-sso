package site.cocow.sso.domain.client;

import java.time.LocalDateTime;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

/**
 * OAuth2 客户端实体
 */
@Entity
@Table(name = "oauth_clients")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", unique = true, nullable = false, length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false, length = 255)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 100)
    private String clientName;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 20)
    private ClientType clientType = ClientType.CONFIDENTIAL;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_redirect_uris", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri", length = 500)
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_grant_types", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type", length = 50)
    private Set<String> grantTypes;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope", length = 50)
    private Set<String> scopes;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled = true;

    @Column(name = "owner_id")
    private Long ownerId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Constructors
    public Client() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public Set<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(Set<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public ClientType getClientType() {
        return clientType;
    }

    public void setClientType(ClientType clientType) {
        this.clientType = clientType;
    }

    /**
     * 客户端类型枚举
     */
    public enum ClientType {
        /**
         * 公开客户端 - 无法安全存储 client_secret（如移动应用、SPA） 必须使用 PKCE
         */
        PUBLIC,
        /**
         * 机密客户端 - 可以安全存储 client_secret（如服务端应用） PKCE 可选但推荐
         */
        CONFIDENTIAL
    }
}
